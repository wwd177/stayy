from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import websockets

from stayy.agents.base import AgentTurnCallbacks
from stayy.agents.cli_adapters import run_cli_agent_turn
from stayy.agents.openai_compat import run_openai_compat_turn
from stayy.agents.registry import AgentRegistry
from stayy.agy_session import SessionManager, TurnResult
from stayy.config import BridgeConfig
from stayy.desktop_tools import (
    get_workspace_file_diff,
    inspect_workspace_git,
    is_sensitive_path,
    list_workspace_directory,
    read_workspace_file_preview,
)
from stayy.maintenance import is_quota_or_capacity_error
from stayy.setup_wizard import run_doctor
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
        web_access_token="reg-master-token-sec-001",
    )
    base.update(overrides)
    return BridgeConfig(**base)


@pytest.mark.asyncio
async def test_reg1_chunked_utf8_sse_multiline_and_http200_json_error(tmp_path: Path) -> None:
    """Verify chunked SSE UTF-8 split framing, multi-line data events, HTTP 200 JSON errors, and key masking."""
    secret_key = "sk-secret-reg1-leak-value"

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            _ = self.rfile.read(length) if length > 0 else b""
            if self.path.startswith("/sse/"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()

                frame1 = (
                    'data: {"choices":[{"delta":{"content":"你好，世界"}}]}\n\n'.encode("utf-8")
                )
                # Deliberately split inside multibyte UTF-8 bytes of "世" across HTTP chunks
                split_idx = frame1.index("世".encode("utf-8")) + 1
                part_a = frame1[:split_idx]
                part_b = frame1[split_idx:]
                # Multi-line SSE event split across two `data:` lines terminated by blank line
                frame2 = (
                    'data: {"choices":[{"delta":\n'
                    'data: {"content":"跨行测试"}}]}\n\n'
                    "data: [DONE]\n\n"
                ).encode("utf-8")

                for chunk_bytes in (part_a, part_b, frame2):
                    self.wfile.write(f"{len(chunk_bytes):x}\r\n".encode("ascii") + chunk_bytes + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
                return

            body = json.dumps(
                {"error": {"message": f"invalid api key {secret_key}"}},
                ensure_ascii=False,
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            return

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_thread.start()
    try:
        deltas: list[str] = []

        async def _on_delta(d: str) -> None:
            deltas.append(d)

        res_ok = await run_openai_compat_turn(
            store="deepseek_api",
            base_url=f"http://127.0.0.1:{port}/sse/v1",
            api_key=secret_key,
            model="deepseek-chat",
            prompt="测试分块",
            workspace=str(tmp_path),
            runtime_dir=tmp_path / ".runtime",
            allow_local_ports=(port,),
            callbacks=AgentTurnCallbacks(on_delta=_on_delta),
        )
        assert res_ok.ok is True
        assert "你好，世界" in res_ok.text
        assert "跨行测试" in res_ok.text
        assert "".join(deltas) == "你好，世界跨行测试"

        res_err = await run_openai_compat_turn(
            store="deepseek_api",
            base_url=f"http://127.0.0.1:{port}/err/v1",
            api_key=secret_key,
            model="deepseek-chat",
            prompt="测试报错",
            workspace=str(tmp_path),
            runtime_dir=tmp_path / ".runtime",
            allow_local_ports=(port,),
        )
        assert res_err.ok is False
        assert secret_key not in res_err.error
        assert "***" in res_err.error
        assert "invalid api key" in res_err.error
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.asyncio
async def test_reg2_revocation_isolates_slow_turn_and_clears_followups(tmp_path: Path) -> None:
    """Verify revoke_all_tokens isolates slow in-flight turns, clears follow-ups/media/live frames, and allows epoch 2."""
    env_file = tmp_path / ".env"
    tok1 = "reg2-init-master-tok-001"
    env_file.write_text(f"WEB_ACCESS_TOKEN={tok1}\nWEB_PWA_PORT=8766\n", encoding="utf-8")
    rt_dir = tmp_path / ".runtime"

    turn1_started = threading.Event()
    release_turn1 = threading.Event()
    turn_counter = {"n": 0}
    server_calls: list[int] = []

    class _SlowSseHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            _ = self.rfile.read(length) if length > 0 else b""
            turn_counter["n"] += 1
            cur_n = turn_counter["n"]
            server_calls.append(cur_n)

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.end_headers()
            if cur_n == 1:
                c1 = f"data: {json.dumps({'choices': [{'delta': {'content': '第一代半截输出'}}]}, ensure_ascii=False)}\n\n".encode("utf-8")
                self.wfile.write(c1)
                self.wfile.flush()
                turn1_started.set()
                release_turn1.wait(timeout=4.0)
                try:
                    c2 = f"data: {json.dumps({'choices': [{'delta': {'content': '不该落盘的尾巴'}}]}, ensure_ascii=False)}\n\n".encode("utf-8")
                    self.wfile.write(c2)
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                except OSError:
                    pass
                return

            ok_chunk = f"data: {json.dumps({'choices': [{'delta': {'content': '第二代全新响应'}}]}, ensure_ascii=False)}\n\n".encode("utf-8")
            self.wfile.write(ok_chunk)
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

        def log_message(self, *_args) -> None:
            return

    sse_srv = ThreadingHTTPServer(("127.0.0.1", 0), _SlowSseHandler)
    sse_port = sse_srv.server_address[1]
    sse_thread = threading.Thread(target=sse_srv.serve_forever, daemon=True)
    sse_thread.start()

    cfg = _make_cfg(
        tmp_path,
        web_access_token=tok1,
        deepseek_base_url=f"http://127.0.0.1:{sse_port}/v1",
        deepseek_api_key="reg2-ds-key",
        deepseek_model="deepseek-chat",
        stayy_allow_local_llm_ports=(sse_port,),
    )
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok1,
        env_path=env_file,
        runtime_dir=rt_dir,
        ide_store_dir=tmp_path / "ide",
        cli_store_dir=tmp_path / "cli",
        codex_store_dir=tmp_path / "cdx",
        dsh_store_dir=tmp_path / "dsh",
        workbuddy_store_dir=tmp_path / "wb",
        copilot_store_dir=tmp_path / "cop",
        ecosystem_project_dir=tmp_path,
    )
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        for _ in range(50):
            if pwa.admin_port > 0:
                break
            await asyncio.sleep(0.05)
        assert pwa.admin_port > 0

        dummy_media = tmp_path / "m.png"
        dummy_media.write_bytes(b"png-bytes")
        pwa.register_media(dummy_media)
        pwa.register_live_frame(dummy_media)

        slot_name = ""
        async with websockets.connect(f"ws://127.0.0.1:{cfg.web_pwa_port}/ws?token={tok1}") as ws1:
            _ = json.loads(await asyncio.wait_for(ws1.recv(), timeout=3.0))
            await ws1.send(json.dumps({"type": "new_conversation", "target": "deepseek_api", "req_id": "n1"}))
            for _ in range(10):
                ev = json.loads(await asyncio.wait_for(ws1.recv(), timeout=3.0))
                if ev.get("type") == "meta_update" and ev.get("active_store") == "deepseek_api":
                    slot_name = str(ev["slot"])
                    break
            assert slot_name

            await ws1.send(json.dumps({"type": "chat", "slot": slot_name, "client_id": "c-slow-1", "text": "慢请求"}))
            for _ in range(12):
                ev = json.loads(await asyncio.wait_for(ws1.recv(), timeout=3.0))
                if ev.get("type") == "stream_start":
                    break
            assert await asyncio.to_thread(turn1_started.wait, 3.0)

            await ws1.send(json.dumps({"type": "chat", "slot": slot_name, "client_id": "c-follow-2", "text": "旧排队消息"}))
            for _ in range(10):
                ev = json.loads(await asyncio.wait_for(ws1.recv(), timeout=3.0))
                if ev.get("type") == "chat_ack" and ev.get("stage") == "queued_followup":
                    break

            ok_rev, closed_cnt, new_ep = await pwa.revoke_all_tokens()
            assert ok_rev is True
            assert closed_cnt == 1
            assert new_ep == 2

            with pytest.raises(websockets.exceptions.ConnectionClosed) as close_exc:
                for _ in range(10):
                    raw_after = await asyncio.wait_for(ws1.recv(), timeout=2.0)
                    assert "不该落盘的尾巴" not in raw_after
            assert close_exc.value.rcvd is not None and close_exc.value.rcvd.code == 4001

        release_turn1.set()
        await asyncio.sleep(0.25)

        assert not pwa._slot_followup_queue
        assert slot_name not in pwa._slot_inflight
        assert len(pwa._media_registry) == 0
        assert len(pwa._live_frame_registry) == 0
        hist = pwa._slot_history.get(slot_name, [])
        assert all("不该落盘的尾巴" not in str(m.get("text") or "") for m in hist if m.get("role") == "assistant")
        assert all("第一代半截输出" not in str(m.get("text") or "") for m in hist if m.get("role") == "assistant")

        # Extract newly rotated token from .env and verify epoch 2 executes cleanly on same slot
        new_tok = ""
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("WEB_ACCESS_TOKEN="):
                new_tok = line.split("=", 1)[1].strip()
        assert new_tok and new_tok != tok1

        async with websockets.connect(f"ws://127.0.0.1:{cfg.web_pwa_port}/ws?token={new_tok}") as ws2:
            hello2 = json.loads(await asyncio.wait_for(ws2.recv(), timeout=3.0))
            assert hello2["auth_epoch"] == 2
            await ws2.send(json.dumps({"type": "chat", "slot": slot_name, "client_id": "c-ep2-1", "text": "新纪元提问"}))
            done_item = None
            for _ in range(15):
                ev = json.loads(await asyncio.wait_for(ws2.recv(), timeout=4.0))
                if ev.get("type") == "stream_end":
                    done_item = ev["item"]
                    break
            assert done_item is not None
            assert "第二代全新响应" in done_item["text"]
        assert server_calls == [1, 2]
    finally:
        release_turn1.set()
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()
        sse_srv.shutdown()
        sse_srv.server_close()


@pytest.mark.asyncio
async def test_reg3_live_frame_isolation_and_dl_missing_file_404(tmp_path: Path) -> None:
    """Verify live frames never evict persistent media and deleted /dl/ targets cleanly return HTTP 404."""
    tok = "reg3-master-token-sec-001"
    cfg = _make_cfg(tmp_path, web_access_token=tok)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        env_path=tmp_path / ".env",
        runtime_dir=tmp_path / ".runtime",
        ide_store_dir=tmp_path / "ide",
        cli_store_dir=tmp_path / "cli",
        codex_store_dir=tmp_path / "cdx",
        ecosystem_project_dir=tmp_path,
    )
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        for _ in range(50):
            if pwa.admin_port > 0:
                break
            await asyncio.sleep(0.05)

        keep_file = tmp_path / "keep.png"
        keep_file.write_bytes(b"\x89PNG\r\n\x1a\nkept-media")
        keep_id = pwa.register_media(keep_file)

        live_files: list[Path] = []
        last_live_id = ""
        for idx in range(40):
            lf = tmp_path / f"frame_{idx}.jpg"
            lf.write_bytes(b"\xff\xd8\xff\xe0frame")
            live_files.append(lf)
            last_live_id = pwa.register_live_frame(lf)

        assert keep_id in pwa._media_registry
        assert len(pwa._live_frame_registry) <= 24

        def _fetch(mid: str) -> bytes:
            with urllib.request.urlopen(f"http://127.0.0.1:{cfg.web_pwa_port}/dl/{mid}?token={tok}", timeout=3.0) as r:
                return r.read()

        assert await asyncio.to_thread(_fetch, keep_id) == b"\x89PNG\r\n\x1a\nkept-media"
        assert await asyncio.to_thread(_fetch, last_live_id) == b"\xff\xd8\xff\xe0frame"

        live_files[-1].unlink()
        with pytest.raises(urllib.error.HTTPError) as http_err:
            await asyncio.to_thread(_fetch, last_live_id)
        try:
            assert http_err.value.code == 404
        finally:
            http_err.value.close()
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_reg4_multi_agent_slot_identity_clear_history_target_store_and_exception_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify ecosystem store identity survives slot inspection/clear_history and unhandled turn errors release slot."""
    tok = "reg4-master-token-sec-001"
    cfg = _make_cfg(tmp_path, web_access_token=tok, deepseek_api_key="reg4-ds-key")
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        env_path=tmp_path / ".env",
        runtime_dir=tmp_path / ".runtime",
        ide_store_dir=tmp_path / "ide",
        cli_store_dir=tmp_path / "cli",
        codex_store_dir=tmp_path / "cdx",
        dsh_store_dir=tmp_path / "dsh",
        workbuddy_store_dir=tmp_path / "wb",
        copilot_store_dir=tmp_path / "cop",
        ecosystem_project_dir=tmp_path,
    )

    for st in ("deepseek_api", "workbuddy", "dsh"):
        test_slot = f"new:{st}"
        pwa._slot_meta[test_slot] = {"conversation_id": "", "title": st, "store": st}
        sess = pwa._session_for_slot(test_slot)
        cid, eff_store = pwa._effective_slot_identity(test_slot, sess)
        assert cid == ""
        assert eff_store == st

    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        for _ in range(50):
            if pwa.admin_port > 0:
                break
            await asyncio.sleep(0.05)

        async with websockets.connect(f"ws://127.0.0.1:{cfg.web_pwa_port}/ws?token={tok}") as ws:
            _ = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
            await ws.send(json.dumps({"type": "new_conversation", "target": "deepseek_api", "req_id": "req-ds"}))
            seen_clear = None
            seen_meta = None
            for _ in range(10):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev.get("type") == "clear_history":
                    seen_clear = ev
                elif ev.get("type") == "meta_update":
                    seen_meta = ev
                if seen_clear and seen_meta:
                    break
            assert seen_clear is not None and seen_clear.get("target_store") == "deepseek_api"
            assert seen_meta is not None and seen_meta.get("active_store") == "deepseek_api"
            cur_slot = str(seen_meta["slot"])

            # `/new` slash command must also preserve `target_store == deepseek_api`
            await ws.send(json.dumps({"type": "chat", "slot": cur_slot, "client_id": "c-slash-new", "text": "/new"}))
            slash_clear = None
            slash_meta = None
            for _ in range(12):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev.get("type") == "clear_history":
                    slash_clear = ev
                elif ev.get("type") == "meta_update":
                    slash_meta = ev
                if slash_clear and slash_meta:
                    break
            assert slash_clear is not None and slash_clear.get("target_store") == "deepseek_api"
            assert slash_meta is not None and slash_meta.get("active_store") == "deepseek_api"
            cur_slot = str(slash_meta["slot"])

            call_idx = {"n": 0}

            async def _boom_then_ok(**_kwargs) -> TurnResult:
                call_idx["n"] += 1
                if call_idx["n"] == 1:
                    raise RuntimeError("boom-unexpected")
                return TurnResult(status="SUCCESS", response="恢复成功", conversation_id="ds-conv-1", active_model="DeepSeek API")

            monkeypatch.setattr(pwa, "_try_run_ecosystem_agent_turn", _boom_then_ok)

            await ws.send(json.dumps({"type": "chat", "slot": cur_slot, "client_id": "c-boom-1", "text": "触发异常"}))
            end_err = None
            for _ in range(12):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev.get("type") == "stream_end":
                    end_err = ev["item"]
                    break
            assert end_err is not None and "boom-unexpected" in end_err["text"]
            assert cur_slot not in pwa._slot_inflight

            await ws.send(json.dumps({"type": "chat", "slot": cur_slot, "client_id": "c-ok-2", "text": "恢复测试"}))
            end_ok = None
            for _ in range(12):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev.get("type") == "stream_end":
                    end_ok = ev["item"]
                    break
            assert end_ok is not None and "恢复成功" in end_ok["text"]
            assert cur_slot not in pwa._slot_inflight
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_reg5_tools_wizard_registry_and_cli_adapter_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify run_doctor no-env resilience, sensitive-path rename/diff blocking, quota regex, Copilot cap, and no-DNS refresh."""
    # 1. run_doctor with missing and malformed .env must succeed cleanly without BridgeConfig TypeError
    no_env_dir = tmp_path / "no_env_proj"
    no_env_dir.mkdir()
    doc1 = run_doctor(
        no_env_dir,
        ide_store_dir=tmp_path / "ide_empty",
        codex_store_dir=tmp_path / "cdx_empty",
        ide_exe_override=tmp_path / "missing_ide.exe",
    )
    eco1 = next(c for c in doc1["checks"] if c["name"] == "ecosystem")
    assert "异常" not in eco1["detail"]

    bad_env_dir = tmp_path / "bad_env_proj"
    bad_env_dir.mkdir()
    (bad_env_dir / ".env").write_text("WEB_ACCESS_TOKEN=bad\nDEEPSEEK_API_KEY=\n", encoding="utf-8")
    doc2 = run_doctor(
        bad_env_dir,
        ide_store_dir=tmp_path / "ide_empty2",
        codex_store_dir=tmp_path / "cdx_empty2",
        ide_exe_override=tmp_path / "missing_ide.exe",
    )
    eco2 = next(c for c in doc2["checks"] if c["name"] == "ecosystem")
    assert "异常" not in eco2["detail"]

    # 2. desktop_tools sensitive path blocking across listing, preview, diff, and git rename (`->`)
    repo = tmp_path / "git_sec"
    repo.mkdir()
    secret_names = [".env", ".env.secret", "agents.local.json", "admin.json", "beacon_state.json", "cert.pem", "priv.key"]
    for sn in secret_names:
        assert is_sensitive_path(sn) is True
        (repo / sn).write_text("TOP_SECRET_VALUE=123\n", encoding="utf-8")
    (repo / "safe.txt").write_text("hello world\n", encoding="utf-8")

    listing = list_workspace_directory(repo)
    listed_names = {e["name"] for e in listing["entries"]}
    assert "safe.txt" in listed_names
    assert listed_names.isdisjoint(set(secret_names))

    for sn in secret_names:
        assert read_workspace_file_preview(repo, sn)["ok"] is False
        assert get_workspace_file_diff(repo, sn)["ok"] is False

    big_file = repo / "big.txt"
    big_file.write_text("A" * 300_000, encoding="utf-8")
    prev_big = read_workspace_file_preview(repo, "big.txt", max_chars=2048)
    assert prev_big["ok"] is True
    assert prev_big["truncated"] is True
    assert len(prev_big["content"]) <= 2048

    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@stayy.local"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Stayy Test"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "add", "-f", ".env", "safe.txt"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "mv", ".env", "renamed_note.txt"], cwd=str(repo), check=True, capture_output=True)

    git_info = inspect_workspace_git(repo)
    paths_seen = {c["path"] for c in git_info["changes"]}
    assert ".env" not in paths_seen
    assert "renamed_note.txt" not in paths_seen
    diff_renamed = get_workspace_file_diff(repo, "renamed_note.txt")
    assert diff_renamed["ok"] is False

    # 3. maintenance quota status regex precision
    assert is_quota_or_capacity_error("SyntaxError on line 429 of foo.py") is False
    assert is_quota_or_capacity_error("error code 5031") is False
    assert is_quota_or_capacity_error("HTTP 429 Too Many Requests") is True
    assert is_quota_or_capacity_error("upstream status: 503") is True

    # 4. cli_adapters Copilot prompt cap (>24000) & non-zero exit must never pass via plain_lines
    cop_res = await run_cli_agent_turn(
        store="copilot",
        install_info={"exe": "copilot.exe"},
        prompt="x" * 24001,
        workspace=tmp_path,
    )
    assert cop_res.ok is False
    assert "24000" in cop_res.error

    fake_fail_wb = tmp_path / "fake_fail_wb.py"
    fake_fail_wb.write_text(
        "import sys\n_ = sys.stdin.read()\nprint('partial plain stdout line', flush=True)\nsys.exit(1)\n",
        encoding="utf-8",
    )
    wb_fail = await run_cli_agent_turn(
        store="workbuddy",
        install_info={"node_exe": sys.executable, "cli_mjs": str(fake_fail_wb)},
        prompt="hi",
        workspace=tmp_path,
    )
    assert wb_fail.ok is False

    # 5. AgentRegistry.refresh() skips DNS validation for unconfigured API providers
    def _no_dns(*_args, **_kwargs):
        raise AssertionError("validate_llm_endpoint_url must not run for unconfigured API providers")

    monkeypatch.setattr("stayy.agents.registry.validate_llm_endpoint_url", _no_dns)
    cfg_reg = _make_cfg(
        tmp_path,
        doubao_ark_base_url="https://unconfigured.example.invalid/v1",
        doubao_ark_api_key="",
        doubao_ark_model="ep-demo",
    )
    reg = AgentRegistry(
        cfg_reg,
        project_dir=tmp_path,
        runtime_dir=tmp_path / ".runtime",
        ide_store_dir=tmp_path / "ide_r",
        local_app_data=tmp_path / "la_r",
    )
    assert reg.get_agent("doubao_api") is not None
    assert reg.get_agent("doubao_api").configured is False
