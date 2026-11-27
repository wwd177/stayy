from __future__ import annotations

import asyncio
import json
import logging
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import websockets

from stayy.agy_session import AgySession, SessionManager
from stayy.approvals import ApprovalReadonlyTracker, deny_auto_invoke
from stayy.auth import AuthManager, load_or_create_host_id
from stayy.beacon import (
    build_static_pwa_bundle,
    publish_ios_pwa_and_beacon,
    resolve_explicit_beacon_target,
    verify_published_beacon,
)
from stayy.config import BridgeConfig
from stayy.notifier import (
    SAFE_NOTIFY_BODY,
    SAFE_NOTIFY_TITLE,
    BarkNotifier,
    _NoRedirectHandler,
    _PinnedHTTPSConnection,
    post_sanitized_bark_push,
    redact_url,
    validate_bark_url,
)
from stayy.setup_wizard import (
    create_windows_desktop_shortcut,
    detect_local_backends,
    main as wizard_main,
    run_doctor,
)
from stayy.web_pwa import WebPwaServer

MOCK_AGY = Path(__file__).parent / "mock_agy.py"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _make_cfg(tmp_path: Path, **overrides) -> BridgeConfig:
    base = dict(
        agy_executable=sys.executable,
        agy_workspace=tmp_path,
        agy_model="balanced-test",
        agy_effort="",
        agy_dangerously_skip_permissions=True,
        agy_timeout_seconds=30,
        progress_notice_delay_seconds=0,
        log_level="DEBUG",
        web_pwa_enabled=True,
        web_pwa_host="127.0.0.1",
        web_pwa_port=_free_port(),
        web_access_token="initial-master-token-sec-001",
    )
    base.update(overrides)
    return BridgeConfig(**base)


@pytest.mark.asyncio
async def test_m1_revocation_race_barrier_atomic_env_failure_and_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify atomic token rotation, pre-register epoch barrier, <=1s 4001 disconnect, and rollback on .env error."""
    env_file = tmp_path / ".env"
    init_tok = "init-master-tok-000001-stayy"
    env_file.write_text(f"WEB_ACCESS_TOKEN={init_tok}\nWEB_PWA_PORT=8766\n", encoding="utf-8")
    rt_dir = tmp_path / ".runtime"

    # 1. Verify .env atomic write failure aborts rotation and preserves epoch & token
    mgr = AuthManager(init_tok, runtime_dir=rt_dir, env_path=env_file)

    def _boom_write(_path: Path, _new: str) -> None:
        raise OSError("simulated disk full")

    monkeypatch.setattr("stayy.auth.atomic_write_env_token", _boom_write)
    ok_fail, _, ep_fail = mgr.revoke_and_rotate()
    assert ok_fail is False
    assert ep_fail == 1
    assert mgr.current_epoch() == 1
    assert mgr.verify_credential(init_tok, "127.0.0.1")[0] is True
    monkeypatch.undo()

    # 2. Spin up server with deterministic `on_ws_pre_register` barrier
    arm_barrier = False
    barrier_reached = asyncio.Event()
    allow_register = asyncio.Event()
    desk_calls: list[str] = []

    async def _pre_reg_barrier(_ws) -> None:
        if not arm_barrier:
            return
        barrier_reached.set()
        await asyncio.wait_for(allow_register.wait(), timeout=5.0)

    cfg = _make_cfg(tmp_path, web_access_token=init_tok)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=init_tok,
        env_path=env_file,
        runtime_dir=rt_dir,
        ide_store_dir=tmp_path / "ide_rev",
        cli_store_dir=tmp_path / "cli_rev",
        codex_store_dir=tmp_path / "cdx_rev",
        desktop_input_handler=lambda act, *_a: (desk_calls.append(act) or True, "ok"),
        on_ws_pre_register=_pre_reg_barrier,
    )
    stop_event = asyncio.Event()
    task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        for _ in range(50):
            if pwa.admin_port > 0:
                break
            await asyncio.sleep(0.05)
        assert pwa.admin_port > 0

        # Connect healthy client in epoch 1
        async with websockets.connect(f"ws://127.0.0.1:{cfg.web_pwa_port}/ws?token={init_tok}") as ws_healthy:
            hello1 = json.loads(await asyncio.wait_for(ws_healthy.recv(), timeout=4.0))
            assert hello1["auth_epoch"] == 1
            old_sess_tok = pwa.auth.issue_session_token()

            # Arm barrier so ws_escaping authenticates in epoch 1, then pauses BEFORE registering in _clients!
            arm_barrier = True
            escaping_result: dict[str, object] = {}

            async def _escaping_worker() -> None:
                async with websockets.connect(
                    f"ws://127.0.0.1:{cfg.web_pwa_port}/ws?token={init_tok}"
                ) as ws_esc:
                    try:
                        await asyncio.wait_for(ws_esc.recv(), timeout=3.0)
                        escaping_result["got_frame"] = True
                    except websockets.exceptions.ConnectionClosed as exc:
                        escaping_result["close_code"] = exc.rcvd.code if exc.rcvd else None

            esc_task = asyncio.create_task(_escaping_worker())
            await asyncio.wait_for(barrier_reached.wait(), timeout=3.0)

            # Trigger loopback admin /admin/revoke BEFORE releasing the barrier
            def _post_revoke() -> dict:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{pwa.admin_port}/admin/revoke",
                    data=b"{}",
                    method="POST",
                    headers={"X-Admin-Token": pwa.admin_secret},
                )
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    return json.loads(resp.read().decode("utf-8"))

            rev_res = await asyncio.to_thread(_post_revoke)
            assert rev_res["ok"] is True
            assert rev_res["auth_epoch"] == 2
            assert rev_res["closed_clients"] == 1

            # Existing healthy WS MUST close with 4001 within 1s
            with pytest.raises(websockets.exceptions.ConnectionClosed) as hc_exc:
                await asyncio.wait_for(ws_healthy.recv(), timeout=1.0)
            assert hc_exc.value.rcvd is not None and hc_exc.value.rcvd.code == 4001

            # Release barrier -> escaping WS MUST be rejected inside _clients_lock with 4001 and 0 frames!
            allow_register.set()
            await asyncio.wait_for(esc_task, timeout=3.0)
            assert escaping_result.get("close_code") == 4001
            assert "got_frame" not in escaping_result
            assert desk_calls == []

            # Verify .env on disk was atomically rotated & old token + old session fail
            new_cfg = BridgeConfig.from_env(env_file)
            assert new_cfg.web_access_token and new_cfg.web_access_token != init_tok
            restarted_auth = AuthManager(new_cfg.web_access_token, runtime_dir=rt_dir, env_path=env_file)
            assert restarted_auth.verify_credential(init_tok, "127.0.0.1")[0] is False
            assert restarted_auth.verify_credential(old_sess_tok, "127.0.0.1")[0] is False
            assert restarted_auth.verify_credential(new_cfg.web_access_token, "127.0.0.1")[0] is True
    finally:
        stop_event.set()
        await asyncio.wait_for(task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_m1_closed_auth_loopback_admin_and_acl(tmp_path: Path) -> None:
    """Verify /dl/ 0-byte 401 without Origin, CSWSH/CORS closedness, /admin 404 on main port, and admin.json ACL."""
    tok = "closed-auth-master-tok-888"
    rt_dir = tmp_path / ".runtime"
    cfg = _make_cfg(tmp_path, web_access_token=tok)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    desk_calls: list[str] = []
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        runtime_dir=rt_dir,
        ide_store_dir=tmp_path / "ide_ca",
        cli_store_dir=tmp_path / "cli_ca",
        codex_store_dir=tmp_path / "cdx_ca",
        desktop_input_handler=lambda act, *_a: (desk_calls.append(act) or True, "ok"),
    )
    img_path = tmp_path / "demo_shot.png"
    img_bytes = b"\x89PNG\r\n\x1a\n" + b"PNGDATA" * 10
    img_path.write_bytes(img_bytes)
    mid = pwa.register_media(img_path)
    ticket = pwa.auth.issue_media_ticket(mid)
    wrong_ticket = pwa.auth.issue_media_ticket("other-media-id")

    stop_event = asyncio.Event()
    task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        for _ in range(50):
            if pwa.admin_port > 0:
                break
            await asyncio.sleep(0.05)

        def _http_call(url: str, headers: dict[str, str] | None = None, method: str = "GET") -> tuple[int, bytes, dict[str, str]]:
            req = urllib.request.Request(url, method=method, headers=headers or {})
            try:
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    return resp.status, resp.read(), {k.lower(): v for k, v in resp.headers.items()}
            except urllib.error.HTTPError as err:
                return err.code, err.read(), {k.lower(): v for k, v in err.headers.items()}

        # 1. /dl/<id> without Origin and without cred/ticket -> 401 with STRICT 0-byte body!
        st, body, hdrs = await asyncio.to_thread(_http_call, f"http://127.0.0.1:{cfg.web_pwa_port}/dl/{mid}")
        assert st == 401
        assert body == b""
        assert "access-control-allow-origin" not in hdrs

        # 2. Evil Origin on /dl/<id> NEVER gets Access-Control-Allow-Origin
        st2, body2, hdrs2 = await asyncio.to_thread(
            _http_call,
            f"http://127.0.0.1:{cfg.web_pwa_port}/dl/{mid}?ticket={ticket}",
            {"Origin": "https://evil.example"},
        )
        assert st2 == 200 and body2 == img_bytes
        assert "access-control-allow-origin" not in hdrs2

        # 3. Wrong-subject media ticket rejected 401 + 0 bytes
        st3, body3, _ = await asyncio.to_thread(
            _http_call, f"http://127.0.0.1:{cfg.web_pwa_port}/dl/{mid}?ticket={wrong_ticket}"
        )
        assert st3 == 401 and body3 == b""

        # 4. Unauth WS closes 4001 with 0 frames & 0 desktop calls
        async with websockets.connect(f"ws://127.0.0.1:{cfg.web_pwa_port}/ws?token=wrong-token") as ws_bad:
            with pytest.raises(websockets.exceptions.ConnectionClosed) as exc_bad:
                await asyncio.wait_for(ws_bad.recv(), timeout=3.0)
            assert exc_bad.value.rcvd is not None and exc_bad.value.rcvd.code == 4001
        assert desk_calls == []

        # 5. Business port /admin/revoke returns 404; loopback admin without X-Admin-Token returns 403
        st_adm_pub, _, _ = await asyncio.to_thread(
            _http_call, f"http://127.0.0.1:{cfg.web_pwa_port}/admin/revoke", method="POST"
        )
        assert st_adm_pub == 404
        st_adm_403, _, _ = await asyncio.to_thread(
            _http_call, f"http://127.0.0.1:{pwa.admin_port}/admin/revoke", method="POST"
        )
        assert st_adm_403 == 403

        # 6. admin.json exists and ACL restricted on Windows
        admin_json = rt_dir / "admin.json"
        assert admin_json.is_file()
        meta = json.loads(admin_json.read_text(encoding="utf-8"))
        assert meta["port"] == pwa.admin_port
        assert meta["admin_token"] == pwa.admin_secret
        if sys.platform == "win32":
            ic = subprocess.run(
                ["icacls", str(admin_json)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            out_l = ic.stdout.lower()
            assert "everyone" not in out_l and "builtin\\users" not in out_l
    finally:
        stop_event.set()
        await asyncio.wait_for(task, timeout=5.0)
        await sessions.shutdown_all()
        assert not (rt_dir / "admin.json").exists()


def test_m1_multi_host_isolation_and_explicit_beacon(tmp_path: Path) -> None:
    """Verify BEACON_ENABLED defaults False, refuses upstream repo, binds host_id, and verifies Pages read-back."""
    assert BridgeConfig(agy_executable="agy", agy_workspace=tmp_path).beacon_enabled is False

    # Build synthetic git repo pointing to protected upstream repo
    proj = tmp_path / "repo_a"
    (proj / "src" / "stayy" / "static").mkdir(parents=True)
    real_static = Path(__file__).resolve().parents[1] / "src" / "stayy" / "static" / "index.html"
    (proj / "src" / "stayy" / "static" / "index.html").write_text(
        real_static.read_text(encoding="utf-8"), encoding="utf-8"
    )
    subprocess.run(["git", "init", "-b", "main"], cwd=str(proj), check=True, capture_output=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/wwd177/antigravity-remote-assistant.git"],
        cwd=str(proj),
        check=True,
        capture_output=True,
    )

    ok_dis, code_dis, _ = publish_ios_pwa_and_beacon(
        proj,
        access_token="tok-host-a-123456",
        tunnel_url="https://a.trycloudflare.com",
        lan_url="",
        host_id="host-a",
        beacon_enabled=False,
        explicit_remote="origin",
    )
    assert ok_dis is False and code_dis == "disabled"

    # Protected upstream MUST be refused even when beacon_enabled=True!
    assert (
        resolve_explicit_beacon_target(proj, beacon_enabled=True, explicit_remote="origin")
        is None
    )

    # Custom user repo succeeds
    target = resolve_explicit_beacon_target(
        proj, beacon_enabled=True, explicit_remote="https://github.com/alice/my-stayy-pages.git"
    )
    assert target is not None and target[3] == "https://alice.github.io/my-stayy-pages/"

    # Independent host_ids across two runtime dirs
    h_a = load_or_create_host_id(tmp_path / "rt_a")
    h_b = load_or_create_host_id(tmp_path / "rt_b")
    assert h_a != h_b

    # Serve beacon.json on local HTTP server to verify 404/conflict/verified states
    stage = tmp_path / "stage_readback"
    tok_a = "host-a-secret-token-2026"
    _, nonce_a = build_static_pwa_bundle(
        Path(__file__).resolve().parents[1],
        stage,
        owner="alice",
        repo="my-stayy-pages",
        access_token=tok_a,
        tunnel_url="https://a.trycloudflare.com",
        lan_url="",
        host_id=h_a,
        nonce="nonce-a-001",
    )
    state_box: dict[str, bytes | None] = {"payload": None}

    class _PagesHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            p = state_box["payload"]
            if p is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(p)

        def log_message(self, *args) -> None:
            pass

    httpd = HTTPServer(("127.0.0.1", 0), _PagesHandler)
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        base_url = f"http://127.0.0.1:{httpd.server_address[1]}"
        ok_404, code_404, _ = verify_published_beacon(base_url, tok_a, h_a, nonce_a)
        assert ok_404 is False and code_404 == "pages_not_ready"

        state_box["payload"] = (stage / "beacon.json").read_bytes()
        # Host B checking Host A's beacon sees host_conflict!
        ok_conf, code_conf, _ = verify_published_beacon(base_url, tok_a, h_b, nonce_a)
        assert ok_conf is False and code_conf == "host_conflict"

        # Matching host_a + nonce_a succeeds
        ok_ver, code_ver, _ = verify_published_beacon(base_url, tok_a, h_a, nonce_a)
        assert ok_ver is True and code_ver == "verified"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_m1_safe_defaults_wizard_backends_shortcuts_and_no_secret_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify safe CLI defaults, single-backend detection, non-destructive shortcuts, and zero secret leaks."""
    env_empty = tmp_path / "empty.env"
    env_empty.write_text("", encoding="utf-8")
    cfg_default = BridgeConfig.from_env(env_empty)
    assert cfg_default.agy_dangerously_skip_permissions is False
    assert cfg_default.agy_prewarm is False

    # CLI args check across unconfigured / false / true
    sess_def = AgySession("u1", cfg_default, tmp_path)
    assert "--dangerously-skip-permissions" not in sess_def._build_command()

    cfg_true = _make_cfg(tmp_path, agy_dangerously_skip_permissions=True)
    sess_true = AgySession("u2", cfg_true, tmp_path)
    assert "--dangerously-skip-permissions" in sess_true._build_command()

    # Single-backend detection: IDE-only, Codex-only, CLI-only each report at least one backend
    missing_path = tmp_path / "no_such_dir"
    ide_only = tmp_path / "ide_only"
    (ide_only / "brain").mkdir(parents=True)
    b_ide = detect_local_backends(
        "__nonexistent_agy_bin__",
        ide_store_dir=ide_only,
        codex_store_dir=missing_path,
        ide_exe_override=missing_path / "Missing.exe",
    )
    assert b_ide["antigravity_ide"]["available"] is True

    cdx_only = tmp_path / "cdx_only"
    (cdx_only / "sessions").mkdir(parents=True)
    b_cdx = detect_local_backends(
        "__nonexistent_agy_bin__",
        ide_store_dir=missing_path,
        codex_store_dir=cdx_only,
        ide_exe_override=missing_path / "Missing.exe",
    )
    assert b_cdx["codex_desktop"]["available"] is True

    fake_cli = tmp_path / ("agy.exe" if sys.platform == "win32" else "agy")
    fake_cli.write_bytes(b"echo")
    b_cli = detect_local_backends(
        str(fake_cli),
        ide_store_dir=missing_path,
        codex_store_dir=missing_path,
        ide_exe_override=missing_path / "Missing.exe",
    )
    assert b_cli["antigravity_cli"]["available"] is True

    # Non-destructive Windows Desktop shortcuts test in isolated tmp_path
    if sys.platform == "win32":
        desk = tmp_path / "Desktop"
        desk.mkdir()
        (desk / "Antigravity.lnk").write_bytes(b"SENTINEL_IDE_LNK")
        (desk / "反重力助手.lnk").write_bytes(b"SENTINEL_OLD_LNK")
        (desk / "Stayy.lnk").write_bytes(b"FOREIGN_STAYY_LNK")

        ok_sc, created_path = create_windows_desktop_shortcut(
            Path(__file__).resolve().parents[1], "Stayy.lnk", desktop_dir=desk
        )
        assert ok_sc is True
        # Existing foreign Stayy.lnk, Antigravity.lnk, and 反重力助手.lnk MUST be untouched!
        assert (desk / "Antigravity.lnk").read_bytes() == b"SENTINEL_IDE_LNK"
        assert (desk / "反重力助手.lnk").read_bytes() == b"SENTINEL_OLD_LNK"
        assert (desk / "Stayy.lnk").read_bytes() == b"FOREIGN_STAYY_LNK"
        assert Path(created_path).name == "Stayy Remote Hub.lnk" and Path(created_path).is_file()

    # Doctor & wizard CLI zero secret leak on both success and failure paths
    proj_doc = tmp_path / "proj_doc"
    proj_doc.mkdir()
    sent_tok = "SENTINEL_WEB_ACCESS_TOKEN_SECRET_777"
    sent_bark = "https://api.day.app/SENTINEL_BARK_SECRET_KEY_999/Stayy"
    (proj_doc / ".env").write_text(
        f"WEB_ACCESS_TOKEN={sent_tok}\nBARK_PUSH_URL={sent_bark}\nWEB_PWA_ENABLED=true\nWEB_PWA_PORT=8766\n",
        encoding="utf-8",
    )
    rep = run_doctor(
        proj_doc,
        ide_store_dir=ide_only,
        codex_store_dir=missing_path,
        ide_exe_override=missing_path / "Missing.exe",
    )
    dumped = json.dumps(rep, ensure_ascii=False)
    assert sent_tok not in dumped
    assert "SENTINEL_BARK_SECRET_KEY_999" not in dumped
    assert rep["bark_configured"] is True

    monkeypatch.setattr("stayy.setup_wizard.PROJECT_ROOT", proj_doc)
    rc_ok = wizard_main(["--doctor", "--json"])
    out_ok = capsys.readouterr().out
    assert rc_ok in (0, 1)
    assert sent_tok not in out_ok
    assert "SENTINEL_BARK_SECRET_KEY_999" not in out_ok

    # Failure path: misconfigured/disabled .env -> exit code 1, still zero secret leaks
    (proj_doc / ".env").write_text(
        f"WEB_ACCESS_TOKEN={sent_tok}\nBARK_PUSH_URL={sent_bark}\nWEB_PWA_ENABLED=false\nWEB_PWA_PORT=8766\n",
        encoding="utf-8",
    )
    rc_bad = wizard_main(["--doctor", "--json"])
    out_bad = capsys.readouterr().out
    assert rc_bad == 1
    assert sent_tok not in out_bad
    assert "SENTINEL_BARK_SECRET_KEY_999" not in out_bad


@pytest.mark.asyncio
async def test_m2_branch_b_approval_tracker_watch_race_and_shared_screen_hub(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify Branch B fail-closed tracking, distinct repeated event_keys, watch nav_seq barrier, and ScreenHub."""
    # 1. ApprovalReadonlyTracker fail-closed verification & distinct event_key on disappear->reappear
    tracker = ApprovalReadonlyTracker()
    bad = tracker.normalize_snapshot(
        [
            {"hwnd": 100, "conversation_id": "", "label": "Run", "context_summary": "ls"},
            {"hwnd": 100, "conversation_id": "cid1", "label": "Run", "context_summary": ""},
            {"hwnd": 100, "conversation_id": "cid1", "label": "Run", "context_summary": "echo hi", "verified": False, "reason": "context_truncated"},
        ]
    )
    assert bad[0]["verified"] is False and bad[0]["reason"] == "unverified_window"
    assert bad[1]["verified"] is False and bad[1]["reason"] == "missing_context"
    assert bad[2]["verified"] is False and bad[2]["reason"] == "context_truncated"

    ev1 = tracker.normalize_snapshot(
        [{"hwnd": 200, "conversation_id": "cid-same", "label": "Run command", "context_summary": "echo step1"}]
    )
    assert len(ev1) == 1 and ev1[0]["verified"] is True
    # Disappears on next snapshot
    assert tracker.normalize_snapshot([]) == []
    # Reappears with identical text -> MUST get a distinct event_key!
    ev2 = tracker.normalize_snapshot(
        [{"hwnd": 200, "conversation_id": "cid-same", "label": "Run command", "context_summary": "echo step1"}]
    )
    assert ev2[0]["event_key"] != ev1[0]["event_key"]

    ok_deny, code_deny, _ = deny_auto_invoke()
    assert ok_deny is False and code_deny == "manual_screen_required"

    # 2. Server test: watch race barrier, Shared ScreenHub + slow subscriber drop + clean stop, capability reject
    ide_store = tmp_path / "ide_m2"
    old_cid = "cid-old-watch"
    new_cid = "cid-new-watch"
    for cid, body in ((old_cid, "旧对话内容"), (new_cid, "新对话内容")):
        tf = ide_store / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"
        tf.parent.mkdir(parents=True, exist_ok=True)
        tf.write_text(
            json.dumps({"step_index": 0, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": body}, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    tok = "m2-gates-token-123456"
    cfg = _make_cfg(tmp_path, web_access_token=tok, remote_desktop_enabled=True)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    desk_calls: list[str] = []
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=ide_store,
        cli_store_dir=tmp_path / "cli_m2",
        codex_store_dir=tmp_path / "cdx_m2",
        desktop_input_handler=lambda act, *_a: (desk_calls.append(act) or True, "ok"),
    )

    shot_file = tmp_path / "frame_demo.jpg"
    shot_file.write_bytes(b"\xff\xd8\xff\xe0" + b"JFIF" * 20)
    cap_count = {"n": 0}

    def _mock_capturer(_dir_p: Path, _w: int = 1440, _q: int = 76) -> Path:
        cap_count["n"] += 1
        return shot_file

    pwa._screen_capturer = _mock_capturer
    pwa._cursor_reader = lambda: {"x_ratio": 0.5, "y_ratio": 0.5}
    pwa.ide_watch_interval = 3600.0  # driven deterministically via _poll_ide_watch_once()

    stop_event = asyncio.Event()
    task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        await asyncio.sleep(0.15)
        async with websockets.connect(f"ws://127.0.0.1:{cfg.web_pwa_port}/ws?token={tok}") as ws1:
            await asyncio.wait_for(ws1.recv(), timeout=4.0)

            # Select old_cid
            await ws1.send(json.dumps({"type": "select_conversation", "conversation_id": old_cid, "store": "ide"}))
            loaded1 = json.loads(await asyncio.wait_for(ws1.recv(), timeout=4.0))
            assert loaded1["conversation_id"] == old_cid

            # Modify old transcript on disk so watcher triggers read
            old_tf = ide_store / "brain" / old_cid / ".system_generated" / "logs" / "transcript.jsonl"
            with old_tf.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "source": "MODEL", "content": "旧对话新回复"}, ensure_ascii=False) + "\n")

            # Pause _poll_ide_watch_once deterministically during slow disk read
            poll_entered = threading.Event()
            poll_release = threading.Event()
            from stayy import web_pwa as web_pwa_mod

            orig_loader = web_pwa_mod.load_conversation_detail

            def _barrier_loader(cid: str, *args, **kwargs):  # type: ignore[no-untyped-def]
                if cid == old_cid and not poll_entered.is_set():
                    poll_entered.set()
                    poll_release.wait(timeout=5.0)
                return orig_loader(cid, *args, **kwargs)

            monkeypatch.setattr(web_pwa_mod, "load_conversation_detail", _barrier_loader)
            poll_task = asyncio.create_task(pwa._poll_ide_watch_once())
            await asyncio.to_thread(poll_entered.wait, 3.0)

            # Switch to new_cid BEFORE poll finishes!
            await ws1.send(json.dumps({"type": "select_conversation", "conversation_id": new_cid, "store": "ide"}))
            loaded_new = json.loads(await asyncio.wait_for(ws1.recv(), timeout=4.0))
            assert loaded_new["conversation_id"] == new_cid

            poll_release.set()
            await asyncio.wait_for(poll_task, timeout=3.0)
            monkeypatch.undo()

            # Stale watcher MUST NOT overwrite active new_cid history!
            assert pwa._slot_history[pwa._active_slot][0]["text"] == "新对话内容"

            # Shared _LiveScreenHub with 1 blocked slow subscriber + 1 healthy subscriber
            async with websockets.connect(f"ws://127.0.0.1:{cfg.web_pwa_port}/ws?token={tok}") as ws_slow:
                await asyncio.wait_for(ws_slow.recv(), timeout=4.0)
                await ws1.send(json.dumps({"type": "live_screen", "enable": True, "interval_ms": 600}))
                await ws_slow.send(json.dumps({"type": "live_screen", "enable": True, "interval_ms": 600}))
                for _ in range(40):
                    if len(pwa._screen_subs) == 2:
                        break
                    await asyncio.sleep(0.02)
                assert len(pwa._screen_subs) == 2

                # Match exact ServerConnection for ws_slow by client peer port and block its send()!
                slow_local_addr = ws_slow.transport.get_extra_info("sockname")
                server_ws_slow = next(
                    c for c in pwa._screen_subs if c.remote_address == slow_local_addr
                )
                release_slow_send = asyncio.Event()
                slow_entered = asyncio.Event()
                orig_slow_send = server_ws_slow.send

                async def _blocked_send(msg):
                    slow_entered.set()
                    await release_slow_send.wait()
                    return await orig_slow_send(msg)

                monkeypatch.setattr(server_ws_slow, "send", _blocked_send)
                await asyncio.wait_for(slow_entered.wait(), timeout=3.0)

                # Drain any frame queued BEFORE ws_slow stalled, then collect 2 brand-new shared frames
                cap_before = cap_count["n"]
                while True:
                    try:
                        await asyncio.wait_for(ws1.recv(), timeout=0.05)
                    except asyncio.TimeoutError:
                        break

                healthy_frames = 0
                for _ in range(12):
                    ev = json.loads(await asyncio.wait_for(ws1.recv(), timeout=2.5))
                    if ev.get("type") == "desktop_frame":
                        healthy_frames += 1
                        if healthy_frames >= 2:
                            break
                assert healthy_frames >= 2
                assert cap_count["n"] >= cap_before + 1
                assert pwa._screen_subs[server_ws_slow].maxsize == 1
                assert pwa._screen_subs[server_ws_slow].qsize() <= 1

                # Unblock slow subscriber cleanly before teardown
                release_slow_send.set()
                monkeypatch.undo()

                # Unsubscribe both -> producer MUST cleanly stop
                await ws1.send(json.dumps({"type": "live_screen", "enable": False}))
                await ws_slow.send(json.dumps({"type": "live_screen", "enable": False}))
                for _ in range(40):
                    if not pwa._screen_subs and (
                        pwa._screen_producer_task is None or pwa._screen_producer_task.done()
                    ):
                        break
                    await asyncio.sleep(0.05)
                assert len(pwa._screen_subs) == 0
                assert pwa._screen_producer_task is None or pwa._screen_producer_task.done()

                # Rapid unsubscribe + immediate resubscribe churn -> exactly ONE active producer & fresh frame delivered
                await ws1.send(json.dumps({"type": "live_screen", "enable": True, "interval_ms": 600}))
                await ws1.send(json.dumps({"type": "live_screen", "enable": False}))
                await ws1.send(json.dumps({"type": "live_screen", "enable": True, "interval_ms": 600}))
                churn_frame = False
                for _ in range(12):
                    ev = json.loads(await asyncio.wait_for(ws1.recv(), timeout=2.5))
                    if ev.get("type") == "desktop_frame":
                        churn_frame = True
                        break
                assert churn_frame is True
                assert len(pwa._screen_subs) == 1
                assert pwa._screen_producer_task is not None and not pwa._screen_producer_task.done()
                await ws1.send(json.dumps({"type": "live_screen", "enable": False}))
                for _ in range(30):
                    if pwa._screen_producer_task is None or pwa._screen_producer_task.done():
                        break
                    await asyncio.sleep(0.05)

            # Server-side capability rejection for disabled remote_desktop
            orig_caps = pwa._build_capabilities
            monkeypatch.setattr(
                pwa,
                "_build_capabilities",
                lambda: {**orig_caps(), "remote_desktop": {"enabled": False, "loupe": False, "trackpad": False}},
            )
            before_cnt = len(desk_calls)
            await ws1.send(json.dumps({"type": "desktop_input", "action": "click", "x_ratio": 0.5, "y_ratio": 0.5}))
            cap_toast = None
            for _ in range(6):
                ev = json.loads(await asyncio.wait_for(ws1.recv(), timeout=3.0))
                if ev.get("type") == "toast" and ev.get("code") == "capabilities_denied":
                    cap_toast = ev
                    break
            assert cap_toast is not None
            assert len(desk_calls) == before_cnt
    finally:
        stop_event.set()
        await asyncio.wait_for(task, timeout=5.0)
        await sessions.shutdown_all()


def test_m3_bark_notifier_ssrf_sanitization_and_coalescing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Verify Bark SSRF rules, redirect denial, fixed generic body (zero secret leak), and cooldown coalescing."""
    # 1. Strict HTTPS + SSRF rejection
    assert validate_bark_url("http://api.day.app/mykey/msg")[0] is False
    assert validate_bark_url("https://127.0.0.1/mykey")[0] is False
    assert validate_bark_url("https://10.0.0.5/mykey")[0] is False
    assert validate_bark_url("https://192.168.1.25/mykey")[0] is False
    assert validate_bark_url("https://169.254.169.254/latest/meta-data")[0] is False
    assert validate_bark_url("https://localhost/mykey")[0] is False

    # 2. Valid public host (mocked DNS) + sanitized POST body + no-redirect check
    sent_bark_url = "https://api.day.app/SENTINEL_BARK_TOKEN_123456/Stayy"
    monkeypatch.setattr(
        "stayy.notifier.socket.getaddrinfo",
        lambda host, port, type=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )

    captured_requests: list[tuple[str, bytes]] = []

    class _FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class _FakeOpener:
        def open(self, req, timeout=6.0):  # noqa: ARG002
            captured_requests.append((req.full_url, req.data))
            return _FakeResp()

    with caplog.at_level(logging.DEBUG):
        ok_send, msg_send = post_sanitized_bark_push(sent_bark_url, opener_factory=_FakeOpener)

    assert ok_send is True
    assert "SENTINEL_BARK_TOKEN_123456" not in msg_send
    assert len(captured_requests) == 1
    body_text = captured_requests[0][1].decode("utf-8")
    parsed_body = json.loads(body_text)
    assert parsed_body["title"] == SAFE_NOTIFY_TITLE
    assert parsed_body["body"] == SAFE_NOTIFY_BODY
    assert "SENTINEL_BARK_TOKEN_123456" not in body_text
    assert str(tmp_path) not in body_text
    for rec in caplog.records:
        assert "SENTINEL_BARK_TOKEN_123456" not in rec.getMessage()

    # 3. HTTP redirect handler refuses 302 and exception scrubber masks original URL
    with pytest.raises(urllib.error.HTTPError, match="redirects are disabled"):
        _NoRedirectHandler().redirect_request(
            urllib.request.Request(sent_bark_url), None, 302, "Found", {}, "https://127.0.0.1/evil"
        )

    def _boom_opener():
        class _Boom:
            def open(self, req, timeout=6.0):
                raise RuntimeError(f"dial failed for {sent_bark_url}")

        return _Boom()

    ok_err, msg_err = post_sanitized_bark_push(sent_bark_url, opener_factory=_boom_opener)
    assert ok_err is False
    assert "SENTINEL_BARK_TOKEN_123456" not in msg_err
    assert redact_url(sent_bark_url) in msg_err

    # 3b. Verify _PinnedHTTPSConnection connects strictly to pinned IP (immune to post-validation DNS rebinding)
    dialed_addrs: list[tuple[str, int]] = []
    sni_hosts: list[str | None] = []

    class _DummySock:
        def close(self) -> None:
            pass

    class _DummySSL:
        def wrap_socket(self, sock, server_hostname=None):  # noqa: ARG002
            sni_hosts.append(server_hostname)
            return sock

    monkeypatch.setattr(
        "stayy.notifier.socket.create_connection",
        lambda addr, *_a, **_kw: dialed_addrs.append(addr) or _DummySock(),
    )
    conn = _PinnedHTTPSConnection("api.day.app:8443", pinned_ips=["93.184.216.34"])
    conn._context = _DummySSL()  # type: ignore[assignment]
    conn.connect()
    assert dialed_addrs == [("93.184.216.34", 8443)]
    assert sni_hosts == ["api.day.app"]

    # 4. Bounded cooldown coalescing & repeated prompt event_key re-notification
    send_times: list[float] = []

    def _stub_sender(url: str, *, allow_private_host: bool = False) -> tuple[bool, str]:  # noqa: ARG001
        send_times.append(1.0)
        return True, "ok"

    bn = BarkNotifier(sent_bark_url, cooldown_seconds=30.0, sender_fn=_stub_sender)
    assert bn.notify_for_events(["100:cid1:Run:1"], now_mono=100.0)[0] is True
    assert len(send_times) == 1

    # New events inside 30s cooldown get coalesced without firing immediately
    ok_cd, st_cd = bn.notify_for_events(["100:cid1:Run:2"], now_mono=110.0)
    assert ok_cd is False and st_cd == "coalesced_in_cooldown"
    assert len(send_times) == 1

    # After cooldown expires, pending coalesced notification flushes reliably
    ok_flush, _ = bn.notify_for_events(["100:cid1:Run:2"], now_mono=135.0)
    assert ok_flush is True
    assert len(send_times) == 2

    # Same wording disappearing & reappearing gets new event_key -> notifies again after cooldown
    assert bn.notify_for_events(["100:cid1:Run:3"], now_mono=170.0)[0] is True
    assert len(send_times) == 3
