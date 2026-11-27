from __future__ import annotations

import asyncio
import ctypes
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from ctypes import wintypes
from pathlib import Path
from types import SimpleNamespace

import pytest
import websockets

import stayy.agents.desktop_apps as desktop_apps_mod
import stayy.auth as auth_mod
import stayy.launcher as launcher_mod
import stayy.web_pwa as web_pwa_mod
from stayy.agy_session import SessionManager, TurnResult
from stayy.beacon import build_static_pwa_bundle
from stayy.config import BridgeConfig
from stayy.web_pwa import WebPwaServer

MOCK_AGY = Path(__file__).parent / "mock_agy.py"
GITHUB_PAGES_ORIGIN = "https://wwd177.github.io"


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
        web_access_token="stayy-reg-suite-master-token-2026",
    )
    base.update(overrides)
    return BridgeConfig(**base)


def _http_call(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, method=method, data=data, headers=headers or {})
    try:
        with opener.open(req, timeout=5.0) as resp:
            return int(resp.status), resp.read(), dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        body = exc.read()
        hdrs = dict(exc.headers.items()) if exc.headers else {}
        return int(exc.code), body, hdrs


def _is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x100000 | 0x1000, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD(0)
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return int(code.value) == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def test_desktop_focus_win32_uses_module_time_without_nameerror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify `_focus_window_by_process_win32` executes its `time.sleep` path cleanly with 0 Popen calls."""
    assert hasattr(desktop_apps_mod, "time") and desktop_apps_mod.time is time

    app_exe = tmp_path / "FakeFocusApp.exe"
    app_exe.write_bytes(b"MZ" + b"\x00" * 64)
    discovered = desktop_apps_mod.discover_desktop_ai_apps(
        custom_apps=[{"id": "fake_focus", "name": "Fake Focus", "exe_path": str(app_exe)}]
    )
    entry = discovered["fake_focus"]

    popen_calls: list[object] = []
    monkeypatch.setattr(desktop_apps_mod, "is_process_elevated", lambda: False)
    monkeypatch.setattr(
        desktop_apps_mod.subprocess,
        "Popen",
        lambda *a, **kw: popen_calls.append((a, kw)),
    )

    if sys.platform == "win32":
        sleep_calls: list[float] = []
        orig_sleep = time.sleep

        def _track_sleep(sec: float) -> None:
            sleep_calls.append(sec)
            orig_sleep(min(sec, 0.01))

        monkeypatch.setattr(desktop_apps_mod.time, "sleep", _track_sleep)

        target_hwnd = 987654

        class _FakeUser32:
            @staticmethod
            def IsWindowVisible(hwnd: int) -> int:
                return 1 if hwnd == target_hwnd else 0

            @staticmethod
            def GetWindowTextLengthW(hwnd: int) -> int:
                return 12 if hwnd == target_hwnd else 0

            @staticmethod
            def GetWindowThreadProcessId(hwnd: int, pid_ptr: object) -> int:
                ctypes.memmove(
                    pid_ptr,
                    ctypes.byref(wintypes.DWORD(4242 if hwnd == target_hwnd else 0)),
                    ctypes.sizeof(wintypes.DWORD),
                )
                return 1

            @staticmethod
            def IsIconic(_hwnd: int) -> int:
                return 0

            @staticmethod
            def ShowWindow(_hwnd: int, _cmd: int) -> int:
                return 1

            @staticmethod
            def keybd_event(*_args: int) -> None:
                return None

            @staticmethod
            def BringWindowToTop(_hwnd: int) -> int:
                return 1

            @staticmethod
            def SetForegroundWindow(_hwnd: int) -> int:
                return 1

            @staticmethod
            def GetForegroundWindow() -> int:
                return target_hwnd

            @staticmethod
            def EnumWindows(cb: object, lparam: int) -> int:
                cb(target_hwnd, lparam)  # type: ignore[operator]
                return 1

        class _FakeKernel32:
            @staticmethod
            def OpenProcess(_access: int, _inherit: int, pid_val: int) -> int:
                return 555 if pid_val == 4242 else 0

            @staticmethod
            def QueryFullProcessImageNameW(
                _hproc: int, _flags: int, buf: object, _sz_ptr: object
            ) -> int:
                buf.value = str(app_exe.resolve())  # type: ignore[attr-defined]
                return 1

            @staticmethod
            def CloseHandle(_handle: int) -> int:
                return 1

        monkeypatch.setattr(ctypes.windll, "user32", _FakeUser32())
        monkeypatch.setattr(ctypes.windll, "kernel32", _FakeKernel32())
        monkeypatch.setattr(desktop_apps_mod, "_running_process_names_win32", lambda: {"fakefocusapp.exe"})

        assert desktop_apps_mod._focus_window_by_process_win32("FakeFocusApp") is True
        ok, focused, msg = desktop_apps_mod.launch_desktop_ai_app("fake_focus", entry)
        assert ok is True
        assert focused is True
        assert "Fake Focus" in msg and "置前" in msg
        assert sleep_calls == [0.06, 0.06]
        assert popen_calls == []
    else:
        assert desktop_apps_mod._focus_window_by_process_win32("FakeFocusApp") is False


@pytest.mark.asyncio
async def test_cross_origin_dl_revoke_anti_lockout_and_history_immutability(
    tmp_path: Path,
) -> None:
    """Verify Astra counterexample: 12 post-revoke /dl/ 401s never lock IP, expired ticket has 0 penalty, 429 isolates & resets on pair, and _refresh_history_media_tickets never mutates input."""
    env_file = tmp_path / ".env"
    init_tok = "stayy-anti-lockout-init-tok-2026"
    env_file.write_text(f"WEB_ACCESS_TOKEN={init_tok}\n", encoding="utf-8")

    img_file = tmp_path / "screen_a.png"
    img_bytes = b"\x89PNG\r\n\x1a\n" + (b"X" * 32)
    img_file.write_bytes(img_bytes)

    cfg = _make_cfg(tmp_path, web_access_token=init_tok, allowed_origins=(GITHUB_PAGES_ORIGIN,))
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=init_tok,
        env_path=env_file,
        runtime_dir=tmp_path / "rt",
        ide_store_dir=tmp_path / "ide_dl",
        cli_store_dir=tmp_path / "cli_dl",
        codex_store_dir=tmp_path / "cdx_dl",
    )
    stop_event = asyncio.Event()
    task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        for _ in range(50):
            if pwa.admin_port > 0:
                break
            await asyncio.sleep(0.05)
        assert pwa.admin_port > 0

        mid = pwa.register_media(img_file)
        old_ticket = pwa.auth.issue_media_ticket(mid)

        # 0. Verify _refresh_history_media_tickets refreshes valid tickets and marks evicted ones without mutating input
        orig_history = [
            {
                "role": "assistant",
                "text": "see ![shot](/dl/" + mid + ")",
                "images": [{"media_id": mid, "media_ticket": "stale-old-ticket", "name": "screen_a.png"}],
                "files": [{"media_id": "missing-id-999", "media_ticket": "gone-t", "name": "gone.bin"}],
                "attachments": [{"media_id": mid, "name": "screen_a.png"}],
            }
        ]
        refreshed = pwa._refresh_history_media_tickets(orig_history)
        assert orig_history[0]["images"][0]["media_ticket"] == "stale-old-ticket"
        assert "media_ticket" not in orig_history[0]["attachments"][0]
        assert "media_unavailable" not in orig_history[0]["files"][0]

        new_img_ticket = refreshed[0]["images"][0]["media_ticket"]
        assert new_img_ticket != "stale-old-ticket"
        assert pwa.auth.verify_media_ticket_status(new_img_ticket, mid) == "valid"
        assert pwa.auth.verify_media_ticket_status(refreshed[0]["attachments"][0]["media_ticket"], mid) == "valid"
        assert refreshed[0]["files"][0].get("media_unavailable") is True

        # Seed active history so hello payload reflects refreshed ticket on connect
        pwa._slot_history["ide:conv-hist"] = orig_history
        pwa._active_slot = "ide:conv-hist"

        # 1. Valid cross-origin /dl/ succeeds
        st_ok, body_ok, hdr_ok = await asyncio.to_thread(
            _http_call,
            f"http://127.0.0.1:{cfg.web_pwa_port}/dl/{mid}?ticket={old_ticket}",
            headers={"Origin": GITHUB_PAGES_ORIGIN},
        )
        assert st_ok == 200 and body_ok == img_bytes
        assert hdr_ok.get("Access-Control-Allow-Origin") == GITHUB_PAGES_ORIGIN

        # 2. Revoke all tokens -> old media ticket becomes invalid across epochs
        ok_rev, _, new_ep = await pwa.revoke_all_tokens()
        assert ok_rev is True and new_ep >= 2

        # 12 stale /dl/ fetches from browser timeline must return 401 b"" WITHOUT locking login IP
        for _ in range(12):
            st_401, b_401, _ = await asyncio.to_thread(
                _http_call,
                f"http://127.0.0.1:{cfg.web_pwa_port}/dl/{mid}?ticket={old_ticket}",
                headers={"Origin": GITHUB_PAGES_ORIGIN},
            )
            assert st_401 == 401 and b_401 == b""
        assert pwa.auth.is_ip_locked("127.0.0.1") is False

        # Seed post-revoke registered media entry with stale ticket in _slot_history to verify hello refreshes it without mutating stored dict
        mid_post = pwa.register_media(img_file)
        post_history = [
            {
                "role": "assistant",
                "text": "post ![shot](/dl/" + mid_post + ")",
                "images": [{"media_id": mid_post, "media_ticket": "stale-post-ticket", "name": "screen_a.png"}],
                "files": [{"media_id": mid, "media_ticket": old_ticket, "name": "revoked.png"}],
            }
        ]
        pwa._slot_history["ide:conv-hist-post"] = post_history
        pwa._active_slot = "ide:conv-hist-post"

        # 3. Same IP can immediately POST /api/pair, connect WS with hello.history refreshed tickets, and download 200
        pair_code = pwa.auth.issue_pairing_code(ttl_sec=60.0)
        st_pair, _, hdr_pair = await asyncio.to_thread(
            _http_call,
            f"http://127.0.0.1:{cfg.web_pwa_port}/api/pair",
            method="POST",
            data=b"",
            headers={
                "X-Pair-Code": pair_code,
                "Origin": f"http://127.0.0.1:{cfg.web_pwa_port}",
                "Sec-Fetch-Site": "same-origin",
            },
        )
        assert st_pair == 200
        cookie_kv = (hdr_pair.get("Set-Cookie") or "").split(";", 1)[0].strip()
        assert cookie_kv

        async with websockets.connect(
            f"ws://127.0.0.1:{cfg.web_pwa_port}/ws",
            origin=GITHUB_PAGES_ORIGIN,
            additional_headers={"Cookie": cookie_kv},
        ) as ws:
            hello = json.loads(await asyncio.wait_for(ws.recv(), timeout=4.0))
            assert hello["type"] == "hello"
            fresh_t = hello["history"][0]["images"][0]["media_ticket"]
            assert fresh_t != "stale-post-ticket"
            assert post_history[0]["images"][0]["media_ticket"] == "stale-post-ticket"
            assert hello["history"][0]["files"][0].get("media_unavailable") is True

            st_fresh, b_fresh, _ = await asyncio.to_thread(
                _http_call,
                f"http://127.0.0.1:{cfg.web_pwa_port}/dl/{mid_post}?ticket={fresh_t}",
                headers={"Origin": GITHUB_PAGES_ORIGIN},
            )
            assert st_fresh == 200 and b_fresh == img_bytes

        # 4. Expired current-epoch ticket returns 401 with 0 media failure count
        pwa.auth.clear_media_failures("127.0.0.1")
        orig_auth_time = auth_mod.time.time
        base_now = orig_auth_time()
        try:
            auth_mod.time.time = lambda: base_now - 3600.0
            exp_t = pwa.auth.issue_media_ticket(mid_post, ttl_sec=60.0)
        finally:
            auth_mod.time.time = orig_auth_time
        assert pwa.auth.verify_media_ticket_status(exp_t, mid_post) == "expired"
        st_exp, b_exp, _ = await asyncio.to_thread(
            _http_call,
            f"http://127.0.0.1:{cfg.web_pwa_port}/dl/{mid_post}?ticket={exp_t}",
            headers={"Origin": GITHUB_PAGES_ORIGIN},
        )
        assert st_exp == 401 and b_exp == b""
        assert len(pwa.auth._failed_media_auth.get("127.0.0.1", ())) == 0

        # 5. 24 invalid current-epoch media tries -> 429 on /dl/ ONLY, cleared on successful POST /api/pair
        for i in range(24):
            st_bad, b_bad, _ = await asyncio.to_thread(
                _http_call,
                f"http://127.0.0.1:{cfg.web_pwa_port}/dl/{mid_post}?ticket=tampered-{i}",
                headers={"Origin": GITHUB_PAGES_ORIGIN},
            )
            assert st_bad == 401 and b_bad == b""
        assert pwa.auth.is_media_ip_locked("127.0.0.1") is True
        assert pwa.auth.is_ip_locked("127.0.0.1") is False

        st_429, b_429, _ = await asyncio.to_thread(
            _http_call,
            f"http://127.0.0.1:{cfg.web_pwa_port}/dl/{mid_post}?ticket=tampered-over",
            headers={"Origin": GITHUB_PAGES_ORIGIN},
        )
        assert st_429 == 429 and b_429 == b""

        pair2 = pwa.auth.issue_pairing_code(ttl_sec=60.0)
        st_pair2, _, _ = await asyncio.to_thread(
            _http_call,
            f"http://127.0.0.1:{cfg.web_pwa_port}/api/pair",
            method="POST",
            data=b"",
            headers={
                "X-Pair-Code": pair2,
                "Origin": f"http://127.0.0.1:{cfg.web_pwa_port}",
                "Sec-Fetch-Site": "same-origin",
            },
        )
        assert st_pair2 == 200
        assert pwa.auth.is_media_ip_locked("127.0.0.1") is False

        # Deleted file returns 404 even with valid ticket
        fresh_t2 = pwa.auth.issue_media_ticket(mid_post)
        img_file.unlink()
        st_404, _, _ = await asyncio.to_thread(
            _http_call,
            f"http://127.0.0.1:{cfg.web_pwa_port}/dl/{mid_post}?ticket={fresh_t2}",
            headers={"Origin": GITHUB_PAGES_ORIGIN},
        )
        assert st_404 == 404
    finally:
        stop_event.set()
        await asyncio.wait_for(task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_codex_oversized_stdout_kills_child_and_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify >STREAM_BUFFER_LIMIT stdout line terminates Codex child promptly without hang, then next turn works."""
    monkeypatch.setattr(web_pwa_mod, "STREAM_BUFFER_LIMIT", 256)
    pid_file = tmp_path / "codex_oversize.pid"
    mock_py = tmp_path / "mock_codex_oversize.py"
    mock_py.write_text(
        "import json, pathlib, sys, time\n"
        "sys.stdin.reconfigure(encoding='utf-8', errors='replace')\n"
        "sys.stdout.reconfigure(encoding='utf-8', errors='replace')\n"
        "payload = sys.stdin.read()\n"
        f"pathlib.Path({str(pid_file)!r}).write_text(str(__import__('os').getpid()), encoding='utf-8')\n"
        "if 'OVERSIZE' in payload:\n"
        "    sys.stdout.buffer.write((b'A' * 600) + b'\\n')\n"
        "    sys.stdout.buffer.flush()\n"
        "    time.sleep(30)\n"
        "else:\n"
        "    print(json.dumps({'type':'item.completed','item':{'type':'agent_message','text':'CODEX_RECOVERED_OK'}}), flush=True)\n",
        encoding="utf-8",
    )
    mock_cmd = tmp_path / ("mock_codex_oversize.cmd" if sys.platform == "win32" else "mock_codex_oversize.sh")
    if sys.platform == "win32":
        mock_cmd.write_text(
            f'@chcp 65001 >nul\r\n@"{sys.executable}" -X utf8 "{mock_py}" %*\r\n',
            encoding="utf-8",
        )
    else:
        mock_cmd.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" -X utf8 "{mock_py}" "$@"\n',
            encoding="utf-8",
        )
        mock_cmd.chmod(0o755)

    cfg = _make_cfg(tmp_path)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=cfg.web_access_token,
        codex_cli_path=mock_cmd,
    )

    async def _noop(*_a: object) -> None:
        return None

    t0 = time.monotonic()
    res1 = await pwa._try_run_codex_cli_turn(
        chat_slot="codex:oversize",
        codex_cid="",
        workspace=tmp_path,
        prompt_text="TRIGGER OVERSIZE LINE",
        reply_id="r-1",
        on_delta=_noop,
        on_tool=_noop,
        on_status=_noop,
    )
    elapsed = time.monotonic() - t0
    assert isinstance(res1, TurnResult) and res1.status == "ERROR"
    assert elapsed < 4.0

    child_pid = int(pid_file.read_text(encoding="utf-8").strip())
    for _ in range(20):
        if not _is_pid_alive(child_pid):
            break
        await asyncio.sleep(0.05)
    assert not _is_pid_alive(child_pid)

    res2 = await pwa._try_run_codex_cli_turn(
        chat_slot="codex:oversize",
        codex_cid="",
        workspace=tmp_path,
        prompt_text="normal turn",
        reply_id="r-2",
        on_delta=_noop,
        on_tool=_noop,
        on_status=_noop,
    )
    assert isinstance(res2, TurnResult) and res2.status == "SUCCESS"
    assert "CODEX_RECOVERED_OK" in res2.response


def test_launcher_health_poll_race_exception_safe_and_stale_beacon_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify LauncherApp poll state machine (no re-entrancy + force rerun after exception), _tunnel_proc service tracking, and stale-token beacon guard."""
    # 1. Non-reentrancy + queued force=True rerun + exception safety
    app = object.__new__(launcher_mod.LauncherApp)
    app._poll_state_lock = threading.Lock()
    app._poll_running = False
    app._poll_rerun_pending = False
    app._closing = False
    app._enqueue_log = lambda *_a, **_kw: None

    entered_first = threading.Event()
    release_first = threading.Event()
    calls: list[bool] = []
    active = 0
    max_active = 0
    state_lock = threading.Lock()

    def _fake_poll_once(force: bool = False) -> None:
        nonlocal active, max_active
        with state_lock:
            active += 1
            max_active = max(max_active, active)
            call_idx = len(calls) + 1
            calls.append(force)
        try:
            if call_idx == 1:
                entered_first.set()
                release_first.wait(timeout=3.0)
                raise RuntimeError("transient_poll_error")
        finally:
            with state_lock:
                active -= 1

    app._health_poll_once = _fake_poll_once  # type: ignore[method-assign]
    t1 = threading.Thread(target=app._health_poll_worker, kwargs={"force": False}, daemon=True)
    t1.start()
    assert entered_first.wait(timeout=2.0)

    # Second concurrent force=True caller queues rerun instead of entering concurrently
    app._health_poll_worker(force=True)
    release_first.set()
    t1.join(timeout=3.0)

    assert max_active == 1
    assert calls == [False, True]
    assert app._poll_running is False
    assert app._poll_rerun_pending is False

    # 2. _has_running_managed_services tracks _tunnel_proc even when _server_proc is None
    app._server_proc = None
    app._tunnel_proc = SimpleNamespace(poll=lambda: None)
    assert app._has_running_managed_services() is True
    app._tunnel_proc = SimpleNamespace(poll=lambda: 0)
    assert app._has_running_managed_services() is False

    # 3. Stale-token guard in _sync_ios_beacon_worker
    app.settings = SimpleNamespace(
        beacon_enabled=True,
        web_pwa_port=8766,
        project_dir=tmp_path,
        web_access_token="OLD_TOKEN",
        beacon_git_remote="",
        beacon_branch="gh-pages",
        beacon_allow_upstream=False,
    )
    app._ios_pages_url = "https://example.github.io/stayy/"
    app._tunnel_gen = 1
    app._host_id = "host-stayy-001"
    app._beacon_state = ""
    app._beacon_pending_nonce = ""
    app._beacon_synced = False
    app._post_ui = lambda *_a, **_kw: None

    def _stale_publish(*_a, **kwargs):
        assert kwargs["access_token"] == "OLD_TOKEN"
        app.settings.web_access_token = "NEW_TOKEN_AFTER_REVOKE"
        return True, "verified", "https://example.github.io/stayy/"

    monkeypatch.setattr(launcher_mod, "publish_ios_pwa_and_beacon", _stale_publish)
    app._sync_ios_beacon_worker("https://tun-a.trycloudflare.com", tun_gen=1)
    assert app._beacon_synced is False


def test_beacon_dynamic_shell_hash_and_frontend_ticket_precedence(tmp_path: Path) -> None:
    """Verify `build_static_pwa_bundle` injects `data-beacon-branch` and HTML SHA-256 cache suffix while preserving v3, and frontend prefers ticketMap over stale URL ticket."""
    proj_root = Path(__file__).resolve().parents[1]
    stage = tmp_path / "stage_pages"
    build_static_pwa_bundle(
        proj_root,
        stage,
        owner="alice",
        repo="stayy-pages",
        access_token="beacon-secret-2026",
        tunnel_url="https://stayy.trycloudflare.com",
        lan_url="",
        host_id="host-stayy-test-001",
        beacon_branch="pages-alt",
    )
    out_html = (stage / "index.html").read_text(encoding="utf-8")
    out_sw = (stage / "sw.js").read_text(encoding="utf-8")
    expected_hash = hashlib.sha256(out_html.encode("utf-8")).hexdigest()[:10]
    assert 'data-beacon-repo="alice/stayy-pages"' in out_html
    assert 'data-beacon-branch="pages-alt"' in out_html
    assert "CACHE_PREFIX + 'v3'" in out_sw
    assert expected_hash in out_sw and "__SHELL_HASH__" not in out_sw

    src_html = (proj_root / "src" / "stayy" / "static" / "index.html").read_text(encoding="utf-8")
    assert "const ticket = (ticketMap && ticketMap.get(decId)) || mediaTicketCache.get(decId) || qTicket || '';" in src_html

    node_bin = shutil.which("node")
    if node_bin:
        m = re.search(
            r"(function escapeHtml\(s\)\s*\{.*?function formatInlineMarkdown\(escapedLine, ticketMap = null\)\s*\{.*?\n  \})",
            src_html,
            re.S,
        )
        assert m is not None
        js_probe = tmp_path / "stayy_fmt_probe.js"
        js_probe.write_text(
            "const apiBase = 'https://tun.trycloudflare.com';\n"
            "const mediaTicketCache = new Map();\n"
            "function mediaUrl(mid, ticket) { return `${apiBase}/dl/${encodeURIComponent(mid)}${ticket ? '?ticket=' + encodeURIComponent(ticket) : ''}`; }\n"
            + m.group(1)
            + "\n"
            "const rendered = formatInlineMarkdown('![pic](/dl/m1?ticket=OLD_Q)', new Map([['m1', 'FRESH_T']]));\n"
            "if (!rendered.includes('https://tun.trycloudflare.com/dl/m1?ticket=FRESH_T')) { throw new Error('Wrong ticket precedence: ' + rendered); }\n",
            encoding="utf-8",
        )
        proc = subprocess.run([node_bin, str(js_probe)], capture_output=True, text=True, check=False)
        assert proc.returncode == 0, proc.stderr or proc.stdout
