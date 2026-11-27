from __future__ import annotations

import asyncio
import http.server
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

import pytest
import websockets

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from stayy.agents import (
    AgentRegistry,
    AgentTurnCallbacks,
    is_path_safe_no_reparse,
    make_composite_slot_key,
)
from stayy.agents.cli_adapters import (
    build_copilot_command,
    build_dsh_command,
    build_workbuddy_command,
    discover_copilot_installation,
    discover_dsh_installation,
    discover_workbuddy_installation,
    run_cli_agent_turn,
)
from stayy.agents.desktop_apps import (
    discover_desktop_ai_apps,
    is_pe_executable_file,
    launch_desktop_ai_app,
)
from stayy.agents.openai_compat import (
    _safe_session_id,
    load_api_session_history,
    run_openai_compat_turn,
    validate_llm_endpoint_url,
)
from stayy.agy_session import SessionManager
from stayy.auth import atomic_update_env_vars
from stayy.beacon import (
    detect_candidate_beacon_remote,
    encrypt_beacon_payload,
    load_beacon_state,
    publish_ios_pwa_and_beacon,
    save_beacon_state,
    verify_published_beacon,
)
from stayy.config import BridgeConfig
from stayy.conversations import SAFE_CONV_ID_RE, list_local_conversations, load_conversation_detail
from stayy.setup_wizard import run_doctor
from stayy.web_pwa import WebPwaServer

MOCK_AGY = Path(__file__).resolve().parent / "mock_agy.py"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _make_config(tmp_path: Path, **overrides: Any) -> BridgeConfig:
    defaults: dict[str, Any] = {
        "agy_executable": sys.executable,
        "agy_workspace": tmp_path,
        "agy_model": "balanced-test",
        "agy_timeout_seconds": 30,
        "web_pwa_enabled": True,
        "web_pwa_host": "127.0.0.1",
        "web_pwa_port": _free_port(),
        "web_access_token": "eco-test-master-token-" + secrets.token_hex(6),
    }
    defaults.update(overrides)
    return BridgeConfig(**defaults)


# ---------------------------------------------------------------------------
# E1: App / Manifest / SW / Opt-in Beacon Gates
# ---------------------------------------------------------------------------


def test_e1_beacon_remote_protection_push_failure_and_state_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proj = tmp_path / "repo"
    proj.mkdir()
    subprocess.run(["git", "init"], cwd=proj, check=True, capture_output=True)

    # Protected upstream repo MUST be blocked by detect_candidate_beacon_remote
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/wwd177/antigravity-remote-assistant.git"],
        cwd=proj,
        check=True,
        capture_output=True,
    )
    assert detect_candidate_beacon_remote(proj) is None

    # User-owned repo MUST be allowed as opt-in candidate
    subprocess.run(
        ["git", "remote", "set-url", "origin", "https://github.com/demo-owner/demo-stayy-pwa.git"],
        cwd=proj,
        check=True,
        capture_output=True,
    )
    cand = detect_candidate_beacon_remote(proj)
    assert cand is not None
    _, owner, repo, pages_url = cand
    assert (owner, repo) == ("demo-owner", "demo-stayy-pwa")
    assert pages_url == "https://demo-owner.github.io/demo-stayy-pwa/"

    # Minimal static assets required by build_static_pwa_bundle
    (proj / "src" / "stayy" / "static").mkdir(parents=True)
    (proj / "src" / "stayy" / "static" / "index.html").write_text("<html></html>", encoding="utf-8")
    (proj / "assets").mkdir()
    for ico in ("icon-180.png", "icon-192.png", "icon-512.png"):
        (proj / "assets" / ico).write_bytes(b"\x89PNG\r\n\x1a\n")

    env_file = proj / ".env"
    env_file.write_text("BEACON_ENABLED=false\nWEB_ACCESS_TOKEN=abc1234567890123\n", encoding="utf-8")
    runtime_dir = proj / ".runtime"

    # Point to an unreachable local file-URL bare repo path that does not exist -> push MUST fail cleanly
    missing_remote = (tmp_path / "missing-remote.git").as_uri()
    meta: dict[str, Any] = {}
    ok, code, _ = publish_ios_pwa_and_beacon(
        proj,
        access_token="abc1234567890123",
        tunnel_url="",
        lan_url="http://192.168.1.10:8766",
        host_id="host-demo-1",
        beacon_enabled=True,
        explicit_remote=missing_remote,
        verify_live=False,
        runtime_dir=runtime_dir,
        out_meta=meta,
    )
    # Non-github remote fails resolution safely without modifying .env
    assert not ok
    assert code == "disabled" or not meta.get("pushed")
    assert "BEACON_ENABLED=false" in env_file.read_text(encoding="utf-8")

    # Test GitHub remote where `git push` fails -> `push_failed` & `.env` untouched;
    # Also confirm direct publish onto protected upstream repo emits 0 git push calls
    real_run = subprocess.run
    push_calls: list[list[str]] = []

    def _mock_git_push_fail(cmd: list[str], *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if isinstance(cmd, list) and cmd and cmd[0] == "git" and "push" in cmd:
            push_calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="simulated push error")
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr("stayy.beacon.subprocess.run", _mock_git_push_fail)
    ok_prot, code_prot, _ = publish_ios_pwa_and_beacon(
        proj,
        access_token="abc1234567890123",
        tunnel_url="",
        lan_url="http://192.168.1.10:8766",
        host_id="host-demo-1",
        beacon_enabled=True,
        explicit_remote="https://github.com/wwd177/antigravity-remote-assistant.git",
        verify_live=False,
        runtime_dir=runtime_dir,
        out_meta=meta,
    )
    assert not ok_prot and code_prot == "disabled" and push_calls == []

    ok_gh, code_gh, _ = publish_ios_pwa_and_beacon(
        proj,
        access_token="abc1234567890123",
        tunnel_url="",
        lan_url="http://192.168.1.10:8766",
        host_id="host-demo-1",
        beacon_enabled=True,
        explicit_remote="https://github.com/demo-owner/demo-stayy-pwa.git",
        verify_live=False,
        runtime_dir=runtime_dir,
        out_meta=meta,
    )
    assert not ok_gh and code_gh == "push_failed" and len(push_calls) >= 1
    assert not meta.get("pushed")
    assert "BEACON_ENABLED=false" in env_file.read_text(encoding="utf-8")

    # Test save/load beacon state roundtrip across simulated restart
    state_payload = {
        "state": "pages_not_ready",
        "owner": owner,
        "repo": repo,
        "remote": "https://github.com/demo-owner/demo-stayy-pwa.git",
        "branch": "gh-pages",
        "pages_url": pages_url,
        "host_id": "host-demo-1",
        "pending_nonce": "nonce-xyz",
        "pushed": True,
        "updated_ms": 123456789,
    }
    save_beacon_state(runtime_dir, state_payload)
    reloaded = load_beacon_state(runtime_dir)
    assert reloaded["state"] == "pages_not_ready"
    assert reloaded["pending_nonce"] == "nonce-xyz"

    # Simulate git push failure against GitHub-shaped remote with failing git push via monkeypatch check on atomic_update
    atomic_update_env_vars(env_file, {"STAYY_TEST_KEY": "val1"})
    txt = env_file.read_text(encoding="utf-8")
    assert "BEACON_ENABLED=false" in txt and "STAYY_TEST_KEY=val1" in txt


def test_e1_verify_published_beacon_rejects_404_and_stale_nonce() -> None:
    tok = "beacon-verify-secret-key-2026"
    host_id = "host-aa-11"
    stale_env = encrypt_beacon_payload(
        {
            "v": 2,
            "host_id": host_id,
            "nonce": "old-stale-nonce",
            "tunnel_url": "https://example.trycloudflare.com",
            "lan_url": "http://192.168.1.9:8766",
            "ts": int(time.time() * 1000),
        },
        tok,
    )

    mode = {"kind": "404"}

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if mode["kind"] == "404":
                self.send_response(404)
                self.end_headers()
                return
            if mode["kind"] == "403":
                self.send_response(403)
                self.end_headers()
                return
            payload = json.dumps(stale_env).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args: Any) -> None:
            return

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base_url = f"http://127.0.0.1:{port}"
        ok_404, code_404, _ = verify_published_beacon(base_url, tok, host_id, "new-nonce-99", timeout=3.0)
        assert not ok_404 and code_404 == "pages_not_ready"

        mode["kind"] = "403"
        ok_403, code_403, _ = verify_published_beacon(base_url, tok, host_id, "new-nonce-99", timeout=3.0)
        assert not ok_403 and code_403 == "auth_denied"

        mode["kind"] = "stale_200"
        ok_stale, code_stale, _ = verify_published_beacon(base_url, tok, host_id, "new-nonce-99", timeout=3.0)
        assert not ok_stale and code_stale == "pages_not_ready"

        ok_match, code_match, _ = verify_published_beacon(base_url, tok, host_id, "old-stale-nonce", timeout=3.0)
        assert ok_match and code_match == "verified"
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.asyncio
async def test_e1_manifest_and_sw_installability_endpoints(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=cfg.web_access_token,
        runtime_dir=tmp_path / ".runtime",
        ide_store_dir=tmp_path / "ide",
        cli_store_dir=tmp_path / "cli",
        codex_store_dir=tmp_path / "cdx",
    )
    stop_event = asyncio.Event()
    srv_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        await asyncio.sleep(0.25)
        m_bytes = await asyncio.to_thread(
            lambda: urllib.request.urlopen(f"http://127.0.0.1:{cfg.web_pwa_port}/manifest.json", timeout=3.0).read()
        )
        manifest = json.loads(m_bytes.decode("utf-8"))
        assert manifest["id"] == "./"
        assert manifest["scope"] == "./"
        assert manifest["start_url"] == "./"
        assert manifest["display"] == "standalone"
        assert any("maskable" in str(i.get("purpose", "")) for i in manifest["icons"])

        sw_bytes = await asyncio.to_thread(
            lambda: urllib.request.urlopen(f"http://127.0.0.1:{cfg.web_pwa_port}/sw.js", timeout=3.0).read()
        )
        sw_js = sw_bytes.decode("utf-8")
        assert "addEventListener('fetch'" in sw_js or 'addEventListener("fetch"' in sw_js
    finally:
        stop_event.set()
        await asyncio.wait_for(srv_task, timeout=5.0)
        await sessions.shutdown_all()


# ---------------------------------------------------------------------------
# E2: CLI Adapters (Read-Only Default, Streaming, Cancel/Timeout, History, Real Binaries)
# ---------------------------------------------------------------------------


def test_e2_cli_command_builders_enforce_read_only_defaults() -> None:
    dsh_cmd, dsh_env = build_dsh_command(
        {"mode": "electron_node", "exe": "C:/DSH/DeepSeek Harness.exe", "cli_js": "cli.js"},
        session_id="dsh-123",
        allow_write=False,
    )
    assert dsh_env.get("ELECTRON_RUN_AS_NODE") == "1"
    assert "--permission-mode" in dsh_cmd and dsh_cmd[dsh_cmd.index("--permission-mode") + 1] == "read-only"
    assert "--approval-policy" in dsh_cmd and dsh_cmd[dsh_cmd.index("--approval-policy") + 1] == "never"
    assert "--session-id" in dsh_cmd and "dsh-123" in dsh_cmd

    dsh_wr, _ = build_dsh_command({"mode": "direct", "exe": "dsh.exe"}, allow_write=True)
    assert dsh_wr[dsh_wr.index("--permission-mode") + 1] == "workspace-write"

    wb_cmd, wb_env = build_workbuddy_command(
        {"node_exe": "node.exe", "cli_mjs": "codebuddy-lite-wb.mjs", "product_json": "product.json"},
        session_id="wb-1",
        allow_write=False,
    )
    assert wb_env.get("CODEBUDDY_SKIP_GIT_BASH_CHECK") == "1"
    assert "-y" not in wb_cmd and "--dangerously-skip-permissions" not in wb_cmd
    assert wb_cmd[wb_cmd.index("--permission-mode") + 1] == "dontAsk"
    assert wb_cmd[wb_cmd.index("--tools") + 1] == "Read,Glob,Grep,LS"
    assert "--resume" in wb_cmd and "wb-1" in wb_cmd

    cop_cmd, _ = build_copilot_command({"exe": "copilot.exe"}, prompt="hi", session_id="cop-9", allow_write=False)
    assert "--no-ask-user" in cop_cmd
    assert "--allow-all" not in cop_cmd and "--allow-all-tools" not in cop_cmd
    assert "--deny-tool" in cop_cmd and "write" in cop_cmd and "shell" in cop_cmd
    assert "--resume=cop-9" in cop_cmd


@pytest.mark.asyncio
async def test_e2_cli_streaming_cancel_and_timeout_kill_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_wb = tmp_path / "fake_wb.py"
    fake_wb.write_text(
        """
import json, sys, time
_ = sys.stdin.read()
if "--sleep" in sys.argv:
    time.sleep(30)
print(json.dumps({"type": "system", "session_id": "wb-sess-42"}), flush=True)
print(json.dumps({"type": "stream_event", "event": {"type": "content_block_delta", "delta": {"type": "thinking_delta", "thinking": "思考片段"}}}), flush=True)
print(json.dumps({"type": "stream_event", "event": {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "WorkBuddy "}}}), flush=True)
print(json.dumps({"type": "stream_event", "event": {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "流式回复"}}}), flush=True)
print(json.dumps({"type": "result", "is_error": False, "result": "WorkBuddy 流式回复"}), flush=True)
""".strip(),
        encoding="utf-8",
    )

    deltas: list[str] = []
    thoughts: list[str] = []
    sids: list[str] = []

    async def _on_sid(s: str) -> None:
        sids.append(s)

    async def _on_d(d: str) -> None:
        deltas.append(d)

    async def _on_t(t: str) -> None:
        thoughts.append(t)

    res = await run_cli_agent_turn(
        store="workbuddy",
        install_info={"node_exe": sys.executable, "cli_mjs": str(fake_wb)},
        prompt="检查仓库",
        workspace=tmp_path,
        callbacks=AgentTurnCallbacks(on_session=_on_sid, on_delta=_on_d, on_thought=_on_t),
    )
    assert res.ok is True
    assert res.session_id == "wb-sess-42"
    assert res.text == "WorkBuddy 流式回复"
    assert thoughts == ["思考片段"]
    assert sids == ["wb-sess-42"]
    assert "".join(deltas) == "WorkBuddy 流式回复"

    # DSH NDJSON stream + tool demotion check (using python wrapper via build_dsh_command monkeypatch)
    fake_dsh = tmp_path / "fake_dsh.py"
    fake_dsh.write_text(
        """
import json, sys
mode = sys.argv[1]
if mode == "stream":
    _ = sys.stdin.read()
    print(json.dumps({"sessionId": "dsh-abc", "type": "text_delta", "delta": "先尝试说明"}), flush=True)
    print(json.dumps({"sessionId": "dsh-abc", "type": "tool_start", "toolName": "read_file"}), flush=True)
    print(json.dumps({"sessionId": "dsh-abc", "type": "text_delta", "delta": "最终答案"}), flush=True)
elif mode == "hang":
    import time
    time.sleep(30)
""".strip(),
        encoding="utf-8",
    )
    demoted = {"n": 0}
    tools: list[str] = []

    async def _on_demote() -> None:
        demoted["n"] += 1

    async def _on_tool(name: str, _d: str) -> None:
        tools.append(name)

    monkeypatch.setattr(
        "stayy.agents.cli_adapters.build_dsh_command",
        lambda *_a, **_kw: ([sys.executable, str(fake_dsh), "stream"], {}),
    )
    res_dsh = await run_cli_agent_turn(
        store="dsh",
        install_info={"mode": "direct", "exe": "ignored"},
        prompt="hello dsh",
        workspace=tmp_path,
        callbacks=AgentTurnCallbacks(on_demote_to_thought=_on_demote, on_tool=_on_tool),
    )
    assert res_dsh.ok and res_dsh.session_id == "dsh-abc"
    assert res_dsh.text == "最终答案"
    assert demoted["n"] == 1 and tools == ["read_file"]

    # Test cancellation + timeout tree kill
    monkeypatch.setattr(
        "stayy.agents.cli_adapters.build_dsh_command",
        lambda *_a, **_kw: ([sys.executable, str(fake_dsh), "hang"], {}),
    )
    cancel_ev = asyncio.Event()
    asyncio.get_running_loop().call_later(0.25, cancel_ev.set)
    res_cancel = await run_cli_agent_turn(
        store="dsh",
        install_info={"mode": "direct", "exe": "ignored"},
        prompt="hang",
        workspace=tmp_path,
        cancel_event=cancel_ev,
        timeout_sec=10.0,
    )
    assert res_cancel.aborted is True and not res_cancel.ok

    res_to = await run_cli_agent_turn(
        store="dsh",
        install_info={"mode": "direct", "exe": "ignored"},
        prompt="hang-to",
        workspace=tmp_path,
        timeout_sec=0.35,
    )
    assert not res_to.ok and "安全终止" in res_to.error


def test_e2_read_only_conversation_parsers_for_dsh_wb_and_api(tmp_path: Path) -> None:
    ide_dir = tmp_path / "ide"
    cli_dir = tmp_path / "cli"
    dsh_dir = tmp_path / "dsh"
    wb_dir = tmp_path / "workbuddy"
    api_dir = tmp_path / ".runtime" / "api_sessions"

    (dsh_dir / "storages" / "session_projcache" / "sessions").mkdir(parents=True)
    (dsh_dir / "storages" / "session_projcache" / "sessions" / "sess_dsh_001.json").write_text(
        json.dumps(
            {
                "record": {
                    "identity": {"cwd": str(tmp_path), "createdAt": 1700000000000},
                    "rows": {
                        "title": {"val": "分析 Stayy 架构"},
                        "turnOutline": [{"prompt": "看看结构", "summary": "已完成结构分析", "ts": 1700000001000}],
                    },
                }
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    wb_proj = wb_dir / "projects" / "demo-ws"
    wb_proj.mkdir(parents=True)
    (wb_proj / "wb-conv-99.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"type": "message", "role": "user", "cwd": str(tmp_path), "content": [{"type": "text", "text": "优化接口性能"}]}),
                json.dumps({"type": "message", "role": "assistant", "content": [{"type": "text", "text": "建议添加缓存"}]}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (api_dir / "doubao_api").mkdir(parents=True)
    (api_dir / "doubao_api" / "ark-chat-1.json").write_text(
        json.dumps(
            {
                "session_id": "ark-chat-1",
                "store": "doubao_api",
                "title": "豆包云端问答",
                "workspace": str(tmp_path),
                "updated_ms": 1700000002000,
                "messages": [
                    {"role": "user", "text": "你好豆包"},
                    {"role": "assistant", "text": "你好，有什么可以帮你？"},
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    items = list_local_conversations(
        limit=50,
        ide_dir=ide_dir,
        cli_dir=cli_dir,
        dsh_dir=dsh_dir,
        workbuddy_dir=wb_dir,
        api_sessions_dir=api_dir,
    )
    by_store = {it.store: it for it in items}
    assert {"dsh", "workbuddy", "doubao_api"}.issubset(by_store.keys())

    dsh_det = load_conversation_detail("sess_dsh_001", store="dsh", dsh_dir=dsh_dir)
    assert dsh_det is not None and len(dsh_det.messages) == 2 and "已完成结构分析" in dsh_det.messages[1].text

    wb_det = load_conversation_detail("wb-conv-99", store="workbuddy", workbuddy_dir=wb_dir)
    assert wb_det is not None and len(wb_det.messages) == 2 and "建议添加缓存" in wb_det.messages[1].text

    ark_det = load_conversation_detail("ark-chat-1", store="doubao_api", api_sessions_dir=api_dir)
    assert ark_det is not None and len(ark_det.messages) == 2 and "你好豆包" in ark_det.messages[0].text


def test_e2_real_local_binaries_readonly_help_smoke(tmp_path: Path) -> None:
    """Smoke-check real DSH / WorkBuddy / Copilot CLI binaries installed on this host using read-only `--help` in empty tmp_path."""
    dsh = discover_dsh_installation()
    if dsh:
        cmd, extra = build_dsh_command(dsh, allow_write=False)
        res = subprocess.run(
            cmd[:-1] + ["--help"],
            cwd=tmp_path,
            env={**os.environ, **extra},
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        out = res.stdout + res.stderr
        assert res.returncode == 0 and "--permission-mode" in out and "--approval-policy" in out

    wb = discover_workbuddy_installation()
    if wb:
        cmd, extra = build_workbuddy_command(wb, allow_write=False)
        res = subprocess.run(
            [cmd[0], cmd[1], "--help"],
            cwd=tmp_path,
            env={**os.environ, **extra},
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        out = res.stdout + res.stderr
        assert res.returncode == 0 and "--permission-mode" in out and "--tools" in out

    cop = discover_copilot_installation()
    if cop:
        cmd, extra = build_copilot_command(cop, prompt="ping", allow_write=False)
        res = subprocess.run(
            [cmd[0], "--help"],
            cwd=tmp_path,
            env={**os.environ, **extra},
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        out = res.stdout + res.stderr
        assert res.returncode == 0 and "--deny-tool" in out and "--no-ask-user" in out


# ---------------------------------------------------------------------------
# E2 OpenAI-Compatible APIs + SSRF + Secret Redaction + Composite Lock
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e2_openai_compat_sse_timeout_ssrf_and_no_secret_leak(tmp_path: Path) -> None:
    mode = {"kind": "ok"}

    class _SseHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            _ = self.rfile.read(length) if length > 0 else b""
            if mode["kind"] == "redirect":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.end_headers()
            if mode["kind"] == "slow":
                time.sleep(1.5)
                return
            chunks = [
                {"choices": [{"delta": {"reasoning_content": "分析问题中..."}}]},
                {"choices": [{"delta": {"content": "你好，" + ("多轮记忆已命中" if "请核对" in str(_) else "我是豆包测试版")}}]},
                "[DONE]",
            ]
            for c in chunks:
                line = f"data: {json.dumps(c, ensure_ascii=False) if isinstance(c, dict) else c}\n\n".encode("utf-8")
                self.wfile.write(line)
                self.wfile.flush()

        def log_message(self, *_args: Any) -> None:
            return

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SseHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        # SSRF gate assertions
        ok_bad_port, msg_bad_port, _, _ = validate_llm_endpoint_url(f"http://127.0.0.1:8766/v1", allow_local_ports=(11434, port))
        assert not ok_bad_port and "白名单" in msg_bad_port

        ok_meta, _, _, _ = validate_llm_endpoint_url("http://169.254.169.254/v1", allow_local_ports=(11434,))
        assert not ok_meta

        ok_plain_pub, _, _, _ = validate_llm_endpoint_url("http://example.com/v1", allow_local_ports=(11434,))
        assert not ok_plain_pub

        ok_ollama, _, _, is_lb = validate_llm_endpoint_url("http://127.0.0.1:11434/v1", allow_local_ports=(11434,))
        assert ok_ollama and is_lb

        runtime_dir = tmp_path / ".runtime"
        secret_key = "sk-ark-sentinel-never-leak-2026"
        res1 = await run_openai_compat_turn(
            store="doubao_api",
            base_url=f"http://127.0.0.1:{port}/v1",
            api_key=secret_key,
            model="ep-test-doubao",
            prompt="你好",
            workspace=str(tmp_path),
            session_id="ark-session-1",
            runtime_dir=runtime_dir,
            allow_local_ports=(port,),
        )
        assert res1.ok and "我是豆包测试版" in res1.text and "分析问题中" in res1.thought

        # Redirect MUST be rejected
        mode["kind"] = "redirect"
        res_redir = await run_openai_compat_turn(
            store="doubao_api",
            base_url=f"http://127.0.0.1:{port}/v1",
            api_key=secret_key,
            model="ep-test-doubao",
            prompt="重定向测试",
            workspace=str(tmp_path),
            runtime_dir=runtime_dir,
            allow_local_ports=(port,),
        )
        assert not res_redir.ok and "SSRF" in res_redir.error

        # Slow stream MUST abort on total_timeout_sec
        mode["kind"] = "slow"
        res_slow = await run_openai_compat_turn(
            store="doubao_api",
            base_url=f"http://127.0.0.1:{port}/v1",
            api_key=secret_key,
            model="ep-test-doubao",
            prompt="慢流测试",
            workspace=str(tmp_path),
            runtime_dir=runtime_dir,
            allow_local_ports=(port,),
            chunk_timeout_sec=0.35,
            total_timeout_sec=0.4,
        )
        assert not res_slow.ok

        # Secret zero-leak verification across Registry catalog + run_doctor
        ds_secret = "sk-deepseek-sentinel-never-leak-888"
        env_file = tmp_path / ".env"
        env_file.write_text(
            f"WEB_ACCESS_TOKEN=master-tok-for-doctor-check-12345\n"
            f"DEEPSEEK_API_KEY={ds_secret}\n"
            f"DOUBAO_ARK_API_KEY={secret_key}\n"
            f"DOUBAO_ARK_BASE_URL=http://127.0.0.1:{port}/v1\n"
            f"DOUBAO_ARK_MODEL=ep-test-doubao\n"
            f"STAYY_ALLOW_LOCAL_LLM_PORTS={port}\n",
            encoding="utf-8",
        )
        cfg = BridgeConfig.from_env(env_file)
        reg = AgentRegistry(cfg, project_dir=tmp_path, runtime_dir=runtime_dir, local_app_data=tmp_path / "empty_la")
        cat_dump = json.dumps(reg.public_catalog(), ensure_ascii=False)
        assert secret_key not in cat_dump and ds_secret not in cat_dump

        doc = run_doctor(tmp_path, ide_store_dir=tmp_path / "no_ide", codex_store_dir=tmp_path / "no_cdx")
        doc_dump = json.dumps(doc, ensure_ascii=False)
        assert secret_key not in doc_dump and ds_secret not in doc_dump
        assert doc["ecosystem"]["allow_agent_write"] is False
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.asyncio
async def test_e3_composite_slot_key_and_concurrent_resume_isolation(tmp_path: Path) -> None:
    ws_a = tmp_path / "ws_a"
    ws_b = tmp_path / "ws_b"
    ws_a.mkdir()
    ws_b.mkdir()
    k1 = make_composite_slot_key("workbuddy", str(ws_a), "same-cid")
    k2 = make_composite_slot_key("workbuddy", str(ws_a), "same-cid")
    k3 = make_composite_slot_key("workbuddy", str(ws_b), "same-cid")
    assert k1 == k2 and k1 != k3

    cfg = _make_config(tmp_path)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=cfg.web_access_token,
        runtime_dir=tmp_path / ".runtime",
        ide_store_dir=tmp_path / "ide",
        cli_store_dir=tmp_path / "cli",
        codex_store_dir=tmp_path / "cdx",
    )

    wb_dir = tmp_path / "wb"
    (wb_dir / "projects" / "demo").mkdir(parents=True)
    (wb_dir / "projects" / "demo" / "wb-shared-id.jsonl").write_text(
        json.dumps({"type": "message", "role": "user", "cwd": str(ws_a), "content": [{"type": "text", "text": "hello"}]}) + "\n",
        encoding="utf-8",
    )
    pwa.workbuddy_store_dir = wb_dir

    from stayy.agents.base import AgentSpec

    pwa.agent_registry._specs["workbuddy"] = AgentSpec(
        id="workbuddy",
        name="WorkBuddy",
        vendor="腾讯",
        kind="native_cli",
        store="workbuddy",
        installed=True,
        configured=True,
        internal_meta={"install": {"node_exe": sys.executable, "cli_mjs": "unused"}},
    )

    fake_script = tmp_path / "slow_wb.py"
    fake_script.write_text(
        """
import json, sys, time
_ = sys.stdin.read()
time.sleep(0.45)
print(json.dumps({"type": "result", "is_error": False, "result": "done-in-wb"}), flush=True)
""".strip(),
        encoding="utf-8",
    )
    pwa.agent_registry._specs["workbuddy"].internal_meta["install"] = {
        "node_exe": sys.executable,
        "cli_mjs": str(fake_script),
    }

    events_seen: list[str] = []

    async def _noop(*_a: Any, **_kw: Any) -> None:
        return None

    async def _on_st(s: str) -> None:
        events_seen.append(s)

    t1 = asyncio.create_task(
        pwa._try_run_ecosystem_agent_turn(
            chat_slot="slot-a",
            store="workbuddy",
            conv_id="wb-shared-id",
            workspace=ws_a,
            prompt_text="first",
            conn_epoch=pwa.auth.current_epoch(),
            on_delta=_noop,
            on_reset=_noop,
            on_tool=_noop,
            on_status=_on_st,
        )
    )
    await asyncio.sleep(0.1)
    # Same (store, workspace, conv_id) across another slot MUST be rejected
    r_dup = await pwa._try_run_ecosystem_agent_turn(
        chat_slot="slot-dup",
        store="workbuddy",
        conv_id="wb-shared-id",
        workspace=ws_a,
        prompt_text="second",
        conn_epoch=pwa.auth.current_epoch(),
        on_delta=_noop,
        on_reset=_noop,
        on_tool=_noop,
        on_status=_on_st,
    )
    assert r_dup is not None and r_dup.status == "ERROR" and "正在另一路执行" in r_dup.error

    # Different workspace with identical `wb-shared-id` MUST proceed concurrently
    r_diff_ws = await pwa._try_run_ecosystem_agent_turn(
        chat_slot="slot-b",
        store="workbuddy",
        conv_id="wb-shared-id",
        workspace=ws_b,
        prompt_text="other-ws",
        conn_epoch=pwa.auth.current_epoch(),
        on_delta=_noop,
        on_reset=_noop,
        on_tool=_noop,
        on_status=_on_st,
    )
    r1 = await t1
    assert r1 is not None and r1.status == "SUCCESS"
    assert r_diff_ws is not None and r_diff_ws.status == "SUCCESS"
    await sessions.shutdown_all()


# ---------------------------------------------------------------------------
# E2 Desktop AI Apps Zero-Trust Discovery & Revocation-Locked Launch
# ---------------------------------------------------------------------------


def test_e2_desktop_app_pe_guards_junction_drift_and_uac(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_dir = tmp_path / "real_app"
    real_dir.mkdir()
    real_exe = real_dir / "FakeDoubao.exe"
    real_exe.write_bytes(b"MZ" + b"\x00" * 64)
    assert is_path_safe_no_reparse(real_exe) is True
    assert is_pe_executable_file(real_exe) is True

    bad_non_mz = real_dir / "NotExe.exe"
    bad_non_mz.write_bytes(b"NO" + b"\x00" * 64)
    assert is_pe_executable_file(bad_non_mz) is False

    # Windows directory junction reparse point test (unprivileged on Windows via mklink /J)
    junc_dir = tmp_path / "junction_app"
    if sys.platform == "win32":
        mk = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junc_dir), str(real_dir)],
            capture_output=True,
            text=True,
        )
        if mk.returncode == 0:
            junc_exe = junc_dir / "FakeDoubao.exe"
            assert is_path_safe_no_reparse(junc_exe) is False
            assert is_pe_executable_file(junc_exe) is False

    discovered = discover_desktop_ai_apps(
        custom_apps=[
            {"id": "fake_doubao", "name": "Fake Doubao", "exe_path": str(real_exe)},
            {"id": "../evil", "name": "Bad", "exe_path": str(real_exe)},
        ]
    )
    assert "fake_doubao" in discovered
    assert "../evil" not in discovered
    entry = discovered["fake_doubao"]

    # Reject bad app_id
    ok_bad, _, _ = launch_desktop_ai_app("../evil", entry)
    assert not ok_bad

    # Reject snapshot path drift
    drifted = {**entry, "exe_path": str(tmp_path / "other" / "FakeDoubao.exe")}
    ok_drift, _, _ = launch_desktop_ai_app("fake_doubao", drifted)
    assert not ok_drift

    # Reject post-discovery replacement with a directory junction reparse point
    if sys.platform == "win32":
        swap_dir = tmp_path / "swap_app"
        swap_real = tmp_path / "swap_real"
        swap_real.mkdir()
        swap_exe = swap_dir / "FakeDoubao.exe"
        swap_dir.mkdir()
        swap_exe.write_bytes(b"MZ" + b"\x00" * 64)
        snap = {
            "id": "fake_doubao",
            "name": "Fake Doubao",
            "exe_path": str(swap_exe.resolve()),
            "process_stem": "FakeDoubao",
        }
        swap_exe.unlink()
        swap_dir.rmdir()
        (swap_real / "FakeDoubao.exe").write_bytes(b"MZ" + b"\x00" * 64)
        mk2 = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(swap_dir), str(swap_real)],
            capture_output=True,
            text=True,
        )
        if mk2.returncode == 0:
            ok_junc_launch, _, msg_junc = launch_desktop_ai_app("fake_doubao", snap)
            assert not ok_junc_launch and "重解析" in msg_junc

    # Reject post-discovery PE content swap on the same path
    orig_bytes = real_exe.read_bytes()
    real_exe.write_bytes(b"MZ" + b"\xff" * 64)
    ok_swapped, _, msg_swapped = launch_desktop_ai_app("fake_doubao", entry)
    assert not ok_swapped and "发生变化" in msg_swapped
    real_exe.write_bytes(orig_bytes)

    # Reject elevated Stayy process
    monkeypatch.setattr("stayy.agents.desktop_apps.is_process_elevated", lambda: True)
    ok_elev, _, msg_elev = launch_desktop_ai_app("fake_doubao", entry)
    assert not ok_elev and "管理员权限" in msg_elev


@pytest.mark.asyncio
async def test_e3_ws_desktop_app_launch_blocked_after_revoke(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path, remote_desktop_enabled=True)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=cfg.web_access_token,
        runtime_dir=tmp_path / ".runtime",
        ide_store_dir=tmp_path / "ide",
        cli_store_dir=tmp_path / "cli",
        codex_store_dir=tmp_path / "cdx",
        desktop_input_handler=lambda *_a: (True, "ok"),
    )

    launch_calls: list[str] = []

    def _mock_launch(app_id: str) -> tuple[bool, bool, str]:
        launch_calls.append(app_id)
        return True, True, "launched"

    pwa.agent_registry.launch_desktop_app = _mock_launch  # type: ignore[method-assign]

    stop_event = asyncio.Event()
    srv_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        await asyncio.sleep(0.25)
        async with websockets.connect(f"ws://127.0.0.1:{cfg.web_pwa_port}/ws?token={cfg.web_access_token}") as ws:
            hello = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
            assert "agents" in hello
            assert cfg.web_access_token not in json.dumps(hello["agents"])

            await ws.send(json.dumps({"type": "desktop_app_launch", "app_id": "doubao"}))
            ev = None
            for _ in range(5):
                m = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if m["type"] == "desktop_app_launched":
                    ev = m
                    break
            assert ev is not None and ev["ok"] is True and ev["focused"] is True
            assert launch_calls == ["doubao"]

            # Revoke session -> subsequent desktop launch on the stale socket MUST be blocked with 0 calls
            req = urllib.request.Request(
                f"http://127.0.0.1:{pwa.admin_port}/admin/revoke",
                data=b"{}",
                method="POST",
                headers={"X-Admin-Token": pwa.admin_secret},
            )
            await asyncio.to_thread(lambda: urllib.request.urlopen(req, timeout=3.0).read())

            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await ws.send(json.dumps({"type": "desktop_app_launch", "app_id": "doubao"}))
                for _ in range(4):
                    await asyncio.wait_for(ws.recv(), timeout=2.0)
            assert launch_calls == ["doubao"]
    finally:
        stop_event.set()
        await asyncio.wait_for(srv_task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_edge_guards_sse_fast_cancel_partial_error_session_id_and_sandboxing(tmp_path: Path) -> None:
    """Verify edge bug fixes: SAFE_CONV_ID_RE compat, copilot leading-dash guard, sandboxed desktop apps,
    fast <1s SSE cancel interruption, and partial-error non-persistence."""
    for raw in ("a.b/../../x", "s", "", "x" * 120):
        sid = _safe_session_id(raw)
        assert SAFE_CONV_ID_RE.match(sid), f"Invalid session id generated: {sid!r}"

    cop_cmd, _ = build_copilot_command({"exe": "copilot.exe"}, prompt="--version 解释")
    p_idx = cop_cmd.index("-p")
    assert cop_cmd[p_idx + 1].startswith(" --version"), f"Expected leading space guard: {cop_cmd}"

    # Passing local_app_data MUST isolate discovery completely from real host apps (F:\, ProgramFiles, etc.)
    empty_la = tmp_path / "empty_la"
    empty_la.mkdir()
    assert discover_desktop_ai_apps(local_app_data=empty_la) == {}

    mode = {"kind": "hang_after_header"}

    class _EdgeSseHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            _ = self.rfile.read(length) if length > 0 else b""
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.end_headers()
            if mode["kind"] == "hang_after_header":
                # Keep socket open without sending DONE so cancel_event has to close the underlying socket
                for _ in range(40):
                    time.sleep(0.1)
                return
            if mode["kind"] == "partial_then_drop":
                line = f"data: {json.dumps({'choices': [{'delta': {'content': '半截输出'}}]}, ensure_ascii=False)}\n\n".encode("utf-8")
                self.wfile.write(line)
                self.wfile.flush()
                time.sleep(1.5)

        def log_message(self, *_args: Any) -> None:
            return

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _EdgeSseHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        runtime_dir = tmp_path / ".runtime"
        cancel_ev = asyncio.Event()
        asyncio.get_running_loop().call_later(0.15, cancel_ev.set)
        t0 = time.monotonic()
        res_cancel = await run_openai_compat_turn(
            store="doubao_api",
            base_url=f"http://127.0.0.1:{port}/v1",
            api_key="test-key-123",
            model="ep-demo",
            prompt="hello",
            workspace=str(tmp_path),
            session_id="fast-cancel-id",
            runtime_dir=runtime_dir,
            allow_local_ports=(port,),
            chunk_timeout_sec=30.0,
            total_timeout_sec=30.0,
            cancel_event=cancel_ev,
        )
        elapsed = time.monotonic() - t0
        assert res_cancel.aborted is True and not res_cancel.ok
        assert elapsed < 1.2, f"Expected sub-second SSE cancel interruption, took {elapsed:.2f}s"

        mode["kind"] = "partial_then_drop"
        res_partial_err = await run_openai_compat_turn(
            store="doubao_api",
            base_url=f"http://127.0.0.1:{port}/v1",
            api_key="test-key-123",
            model="ep-demo",
            prompt="partial",
            workspace=str(tmp_path),
            session_id="partial-drop-id",
            runtime_dir=runtime_dir,
            allow_local_ports=(port,),
            chunk_timeout_sec=0.3,
            total_timeout_sec=0.35,
        )
        assert not res_partial_err.ok
        assert load_api_session_history(runtime_dir, "doubao_api", "partial-drop-id") == []
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.asyncio
async def test_e3_unknown_store_no_agy_fallback_and_dsh_thought_plus_local_history_mirror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify unknown plugin stores never fall back to agy.exe, and DSH thought callbacks + sidebar reload preserve turns."""
    from stayy.agents.base import AgentSpec

    cfg = _make_config(tmp_path)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=cfg.web_access_token,
        runtime_dir=tmp_path / ".runtime",
        ide_store_dir=tmp_path / "ide",
        cli_store_dir=tmp_path / "cli",
        codex_store_dir=tmp_path / "cdx",
        dsh_store_dir=tmp_path / "dsh",
        local_app_data=tmp_path / "empty_la",
    )

    dsh_proj_dir = tmp_path / "dsh" / "storages" / "session_projcache" / "sessions"
    dsh_proj_dir.mkdir(parents=True)
    dsh_cid = "sess_dsh_edge_01"

    fake_dsh = tmp_path / "fake_dsh_edge.py"
    fake_dsh.write_text(
        f"""
import json, pathlib, sys
_ = sys.stdin.read()
cid = {dsh_cid!r}
print(json.dumps({{"sessionId": cid, "type": "thinking", "delta": "正在推理边界条件"}}), flush=True)
print(json.dumps({{"sessionId": cid, "type": "text_delta", "delta": "DSH 已精准回答！"}}), flush=True)
# Write projcache metadata WITHOUT turnOutline body (real DSH compressed archive shape)
p = pathlib.Path({str(dsh_proj_dir)!r}) / f"{{cid}}.json"
p.write_text(json.dumps({{"record": {{"identity": {{"cwd": {str(tmp_path)!r}, "createdAt": 1700000005000}}, "rows": {{"title": {{"val": "DSH 边界验证"}}}}}}}}), encoding="utf-8")
""".strip(),
        encoding="utf-8",
    )

    pwa.agent_registry._specs["dsh"] = AgentSpec(
        id="dsh",
        name="DeepSeek Harness",
        vendor="DeepSeek",
        kind="native_cli",
        store="dsh",
        installed=True,
        configured=True,
        read_only_enforced=True,
        capabilities={"chat": True, "stream": True, "history": True, "resume": True, "cancel": True, "read_only_default": True},
        internal_meta={"install": {"mode": "direct", "exe": "ignored"}},
    )
    monkeypatch.setattr(
        "stayy.agents.cli_adapters.build_dsh_command",
        lambda *_a, **_kw: ([sys.executable, str(fake_dsh)], {}),
    )

    stop_event = asyncio.Event()
    srv_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        await asyncio.sleep(0.25)
        async with websockets.connect(f"ws://127.0.0.1:{cfg.web_pwa_port}/ws?token={cfg.web_access_token}") as ws:
            _hello = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))

            # 1. Select `dsh` -> run turn -> observe `深度思考中` status & full preserved text after sidebar reload!
            await ws.send(json.dumps({"type": "new_conversation", "target": "dsh", "open_pc_window": False}))
            for _ in range(8):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "meta_update" and ev.get("active_store") == "dsh":
                    break

            await ws.send(json.dumps({"type": "chat", "client_id": "dsh-c1", "text": "验证思考进度和正文保留"}))
            saw_thought_status = False
            saw_stream_end = False
            for _ in range(25):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "stream_status" and "深度思考中" in str(ev.get("status") or ""):
                    saw_thought_status = True
                if ev["type"] == "stream_end":
                    saw_stream_end = True
                    break
            assert saw_thought_status and saw_stream_end

            # Switch away then select back `dsh:<cid>` from sidebar -> local mirrored history MUST preserve user + assistant text!
            await ws.send(json.dumps({"type": "new_conversation", "target": "cli", "open_pc_window": False}))
            for _ in range(8):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "meta_update" and ev.get("active_store") == "cli":
                    break

            await ws.send(json.dumps({"type": "select_conversation", "conversation_id": dsh_cid, "store": "dsh"}))
            loaded = None
            for _ in range(10):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "conversation_loaded" and ev.get("conversation_id") == dsh_cid:
                    loaded = ev
                    break
            assert loaded is not None
            hist_txt = "\n".join(str(x.get("text") or "") for x in loaded.get("history") or [])
            assert "验证思考进度和正文保留" in hist_txt and "DSH 已精准回答" in hist_txt

            # 2. Directly route slot to a deleted/unknown plugin store -> MUST error clearly and NEVER invoke agy.exe!
            bad_slot = pwa._active_slot
            pwa._slot_meta[bad_slot] = {"conversation_id": "x-1", "title": "bad", "store": "api:deleted_model"}
            pwa._session_for_slot(bad_slot).linked_store = "api:deleted_model"
            turns_before = pwa._session_for_slot(bad_slot).num_turns
            await ws.send(json.dumps({"type": "chat", "client_id": "bad-c2", "text": "不要走agy"}))
            err_end = None
            for _ in range(15):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "stream_end":
                    err_end = ev
                    break
            assert err_end is not None and "未找到已注册的 AI 代理" in str(err_end["item"].get("text") or "")
            assert pwa._session_for_slot(bad_slot).num_turns == turns_before
    finally:
        stop_event.set()
        await asyncio.wait_for(srv_task, timeout=5.0)
        await sessions.shutdown_all()
