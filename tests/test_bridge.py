from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest
import websockets

from stayy.agy_session import SessionManager
from stayy.config import BridgeConfig
from stayy.conversations import (
    list_local_conversations,
    load_conversation_detail,
)
from stayy.desktop_tools import (
    get_workspace_file_diff,
    inspect_workspace_git,
    is_safe_outbound_file,
    list_workspace_directory,
    read_workspace_file_preview,
)
from stayy.maintenance import (
    ModelFailoverPool,
    is_quota_or_capacity_error,
    run_safe_cache_cleanup,
)
from stayy.web_pwa import WebPwaServer, extract_pwa_media_and_text

MOCK_AGY = Path(__file__).parent / "mock_agy.py"


def _make_config(tmp_path: Path, **overrides) -> BridgeConfig:
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
        web_pwa_port=0,
        web_access_token="secret-pwa-token-123456",
    )
    base.update(overrides)
    return BridgeConfig(**base)


def test_quota_detection_and_failover_pool() -> None:
    assert is_quota_or_capacity_error("RESOURCE_EXHAUSTED: model quota exceeded (429)")
    assert is_quota_or_capacity_error("Model is overloaded, please try again later")
    assert not is_quota_or_capacity_error("这一步跑了超过 300s，已安全中断")
    assert not is_quota_or_capacity_error("FileNotFoundError: foo.txt")

    pool = ModelFailoverPool(
        primary_model="claude-sonnet-5-5-medium",
        fallback_models=("claude-sonnet-5-5-low", "gemini-4-neon-medium"),
        cooldown_seconds=3600,
    )
    assert pool.pick_best_available() == "claude-sonnet-5-5-medium"
    nxt = pool.next_after("claude-sonnet-5-5-medium", {"claude-sonnet-5-5-medium"})
    assert nxt == "claude-sonnet-5-5-low"
    assert pool.pick_best_available() == "claude-sonnet-5-5-low"
    assert len(pool.cooldown_summary()) == 1


def test_safe_cache_cleanup_protects_configs_and_prunes_old_files(tmp_path: Path) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    protected = tmp_path / "config"
    protected.mkdir()
    secret = protected / "token.json"
    secret.write_text("keep-me", encoding="utf-8")

    old_file = inbox / "old.png"
    old_file.write_bytes(b"12345")
    old_ts = time.time() - 48 * 3600
    os.utime(old_file, (old_ts, old_ts))

    fresh_file = inbox / "fresh.png"
    fresh_file.write_bytes(b"abcde")

    rep = run_safe_cache_cleanup([(inbox, 24.0, 10), (protected, 0.0, 1)])
    assert rep.deleted_files == 1
    assert not old_file.exists()
    assert fresh_file.exists()
    assert secret.exists()


def test_media_extraction_and_secret_blocking(tmp_path: Path) -> None:
    img = tmp_path / "shot.png"
    img.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 64)
    env_file = tmp_path / ".env"
    env_file.write_text("WEB_ACCESS_TOKEN=secret", encoding="utf-8")

    assert is_safe_outbound_file(img, image_only=True)
    assert not is_safe_outbound_file(env_file, image_only=False)

    txt, imgs, files = extract_pwa_media_and_text(
        f"<thought>internal</thought>结果如下\n[SEND_IMAGE: {img}]\n[SEND_FILE: {env_file}]"
    )
    assert txt == "结果如下"
    assert imgs == [img.resolve()]
    assert files == []


@pytest.mark.asyncio
async def test_persona_and_memory_injected_only_on_first_turn(tmp_path: Path) -> None:
    mem = tmp_path / "user_profile.md"
    mem.write_text("- 常用目录 F:\\Projects", encoding="utf-8")
    cfg = _make_config(
        tmp_path,
        agy_system_prompt="你是反重力助手，优先搜索GitHub开源方案",
        user_memory_file=mem,
    )
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    s = sessions.get("owner")
    try:
        r1 = await s.ask("帮我写个工具")
        assert "你是反重力助手" in r1.response
        assert "F:\\Projects" in r1.response
        assert "帮我写个工具" in r1.response

        r2 = await s.ask("好的谢谢")
        assert "你是反重力助手" not in r2.response
        assert "好的谢谢" in r2.response
    finally:
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_quota_auto_failover_switches_model_and_preserves_conversation(tmp_path: Path) -> None:
    cfg = _make_config(
        tmp_path,
        agy_model="exhausted-primary-model",
        agy_fallback_models=("exhausted-primary-model", "healthy-backup-model"),
    )
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    s = sessions.get("owner")
    try:
        r1 = await s.ask("触发自动切换 __QUOTA_ON_MODEL__:exhausted-primary-model")
        assert r1.status == "SUCCESS"
        assert r1.switched_from_model == "exhausted-primary-model"
        assert r1.active_model == "healthy-backup-model"
        assert s.model == "healthy-backup-model"
    finally:
        await sessions.shutdown_all()


def test_complete_pc_conversations_no_ghost_overwrite_and_codex_support(tmp_path: Path) -> None:
    """Verify:
    1. Stale CLI DB copies of PC IDE chats NEVER overwrite or hide real IDE chats.
    2. IDE DB mirrored CLI prewarm rows (`CORTEX_TRAJECTORY_SOURCE_CLI`) are filtered out of IDE store.
    3. Unindexed top-level `brain/<id>` chats are discovered while `nesting_depth > 0` subagents stay hidden.
    4. OpenAI Codex Desktop (`state_5.sqlite` + `session_index.jsonl` + rollout `.jsonl`) chats are discovered & parsed cleanly.
    """
    ide_dir = tmp_path / "antigravity"
    cli_dir = tmp_path / "antigravity-cli"
    codex_dir = tmp_path / "codex"
    proj_dir = tmp_path / "my_app"
    proj_dir.mkdir()

    # 1. Real IDE conversation in IDE store
    ide_cid = "c63c3f37-e9d8-4ea1-a261-cbf3867a7336"
    ide_tf = ide_dir / "brain" / ide_cid / ".system_generated" / "logs" / "transcript.jsonl"
    ide_tf.parent.mkdir(parents=True)
    ide_tf.write_text(
        "\n".join(
            [
                json.dumps({"step_index": 0, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "<USER_REQUEST>\n第一个问题\n</USER_REQUEST>"}, ensure_ascii=False),
                json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "source": "MODEL", "content": "第一个回答"}, ensure_ascii=False),
                json.dumps({"step_index": 2, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "<USER_REQUEST>\n第二个问题\n</USER_REQUEST>"}, ensure_ascii=False),
                json.dumps({"step_index": 3, "type": "PLANNER_RESPONSE", "source": "MODEL", "content": "第二个回答"}, ensure_ascii=False),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # 2. Subagent folder inside IDE brain (must NOT appear as top-level chat!)
    sub_cid = "subagent-1111-2222-3333-444444444444"
    sub_tf = ide_dir / "brain" / sub_cid / ".system_generated" / "logs" / "transcript.jsonl"
    sub_tf.parent.mkdir(parents=True)
    sub_tf.write_text(
        json.dumps({"step_index": 0, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "subagent task"}) + "\n",
        encoding="utf-8",
    )

    # 3. Unindexed top-level brain folder (NOT in SQLite DB, MUST still be discovered!)
    unindexed_cid = "06cd3358642d3a22283cdb848f660c8b"
    un_tf = ide_dir / "brain" / unindexed_cid / ".system_generated" / "logs" / "transcript.jsonl"
    un_tf.parent.mkdir(parents=True)
    un_tf.write_text(
        json.dumps(
            {
                "step_index": 0,
                "type": "USER_INPUT",
                "source": "USER_EXPLICIT",
                "content": "<USER_REQUEST>\n独立未入库桌面对话\n</USER_REQUEST>",
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    # Populate IDE SQLite DB (including a mirrored CLI ghost row!)
    con_ide = sqlite3.connect(ide_dir / "conversation_summaries.db")
    con_ide.execute(
        "CREATE TABLE conversation_summaries ("
        "conversation_id TEXT, title TEXT, preview TEXT, step_count INT, "
        "last_modified_time TEXT, workspace_uris TEXT, status TEXT, "
        "source TEXT, app_data_dir TEXT, nesting_depth INT, killed INT)"
    )
    con_ide.execute(
        "INSERT INTO conversation_summaries VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (ide_cid, "反重力重构主对话", "最新进度", 120, "2026-11-25 02:00:00+00:00", json.dumps([proj_dir.as_uri()]), "CASCADE_RUN_STATUS_RUNNING", "", str(ide_dir), 0, 0),
    )
    con_ide.execute(
        "INSERT INTO conversation_summaries VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (sub_cid, "Browser Subagent", "", 10, "2026-11-25 02:00:00+00:00", "", "IDLE", "", str(ide_dir), 1, 0),
    )
    con_ide.execute(
        "INSERT INTO conversation_summaries VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("cli-prewarm-ghost-999", "", "", 2, "2026-11-25 02:01:00+00:00", "", "IDLE", "CORTEX_TRAJECTORY_SOURCE_CLI", str(ide_dir), 0, 0),
    )
    con_ide.commit()
    con_ide.close()

    # Populate CLI SQLite DB with a STALE ghost snapshot of `ide_cid` + one genuine CLI chat
    cli_dir.mkdir(parents=True)
    real_cli_cid = "real-mobile-chat-888888"
    cli_tf = cli_dir / "brain" / real_cli_cid / ".system_generated" / "logs" / "transcript.jsonl"
    cli_tf.parent.mkdir(parents=True)
    cli_tf.write_text(
        json.dumps({"step_index": 0, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "手机发起的真实对话"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    con_cli = sqlite3.connect(cli_dir / "conversation_summaries.db")
    con_cli.execute(
        "CREATE TABLE conversation_summaries ("
        "conversation_id TEXT, title TEXT, preview TEXT, step_count INT, "
        "last_modified_time TEXT, workspace_uris TEXT, status TEXT, "
        "source TEXT, app_data_dir TEXT, nesting_depth INT, killed INT)"
    )
    # Stale snapshot of IDE conversation inside CLI DB!
    con_cli.execute(
        "INSERT INTO conversation_summaries VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (ide_cid, "反重力重构主对话", "昨天旧快照", 12, "2026-11-24 01:00:00+00:00", "", "IDLE", "", str(ide_dir), 0, 0),
    )
    con_cli.execute(
        "INSERT INTO conversation_summaries VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (real_cli_cid, "", "", 6, "2026-11-25 01:30:00+00:00", "", "IDLE", "", str(cli_dir), 0, 0),
    )
    con_cli.commit()
    con_cli.close()

    # 4. Populate Codex Desktop store (`state_5.sqlite` + `session_index.jsonl` + rollout)
    codex_sess_dir = codex_dir / "sessions" / "2026" / "11" / "25"
    codex_sess_dir.mkdir(parents=True)
    codex_cid = "01a20d71-386d-7930-b242-359877d30271"
    rollout = codex_sess_dir / f"rollout-2026-11-25T09-00-00-{codex_cid}.jsonl"
    rollout.write_text(
        "\n".join(
            [
                json.dumps({"type": "session_meta", "payload": {"id": codex_cid, "cwd": f"\\\\?\\{proj_dir}"}}),
                json.dumps({"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "# AGENTS.md instructions for test"}]}}),
                json.dumps({"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "帮我重构 Codex 插件架构"}]}}),
                json.dumps({"type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "commentary", "content": [{"type": "output_text", "text": "正在检查目录..."}]}}),
                json.dumps({"type": "response_item", "payload": {"type": "message", "role": "assistant", "phase": "final_answer", "content": [{"type": "output_text", "text": "已完成插件架构重构。"}]}}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (codex_dir / "session_index.jsonl").write_text(
        json.dumps({"id": codex_cid, "thread_name": "重构 Codex 插件架构"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    con_cdx = sqlite3.connect(codex_dir / "state_5.sqlite")
    con_cdx.execute(
        "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, updated_at INT, source TEXT, cwd TEXT, title TEXT, archived INT)"
    )
    con_cdx.execute(
        "INSERT INTO threads VALUES (?,?,?,?,?,?,?)",
        (codex_cid, str(rollout), 1795572000, "vscode", f"\\\\?\\{proj_dir}", "raw title", 0),
    )
    con_cdx.execute(
        "INSERT INTO threads VALUES (?,?,?,?,?,?,?)",
        ("sub-codex-99999999", str(rollout), 1795572000, '{"subagent":{"other":"guardian"}}', "", "", 0),
    )
    con_cdx.commit()
    con_cdx.close()

    items = list_local_conversations(limit=100, ide_dir=ide_dir, cli_dir=cli_dir, codex_dir=codex_dir)
    by_id = {it.conversation_id: it for it in items}

    # IDE chat stayed `store == "ide"` with latest step_count=120 (NOT overwritten by CLI ghost!)
    assert ide_cid in by_id
    assert by_id[ide_cid].store == "ide"
    assert by_id[ide_cid].step_count == 120
    assert by_id[ide_cid].running is True

    # Unindexed brain chat was found; subagent & CLI prewarm ghost were excluded!
    assert unindexed_cid in by_id
    assert by_id[unindexed_cid].store == "ide"
    assert "独立未入库桌面对话" in by_id[unindexed_cid].title
    assert sub_cid not in by_id
    assert "cli-prewarm-ghost-999" not in by_id

    # Genuine CLI chat is present under `cli`
    assert real_cli_cid in by_id
    assert by_id[real_cli_cid].store == "cli"

    # Codex PC chat is present under `codex` with human index title, and guardian subagent excluded
    assert codex_cid in by_id
    assert by_id[codex_cid].store == "codex"
    assert by_id[codex_cid].title == "重构 Codex 插件架构"
    assert by_id[codex_cid].workspace == str(proj_dir)
    assert "sub-codex-99999999" not in by_id

    # Verify pagination (`has_more`) on IDE chat when max_messages=2
    det_paged = load_conversation_detail(ide_cid, "ide", max_messages=2, ide_dir=ide_dir, cli_dir=cli_dir, codex_dir=codex_dir)
    assert det_paged is not None
    assert len(det_paged.messages) == 2
    assert det_paged.has_more is True
    assert det_paged.total_messages >= 4

    # Verify Codex detail parsing (AGENTS.md stripped, final_answer supersedes intermediate commentary)
    det_cdx = load_conversation_detail(codex_cid, "codex", max_messages=50, ide_dir=ide_dir, cli_dir=cli_dir, codex_dir=codex_dir)
    assert det_cdx is not None
    assert len(det_cdx.messages) == 2
    assert det_cdx.messages[0].role == "user"
    assert det_cdx.messages[0].text == "帮我重构 Codex 插件架构"
    assert det_cdx.messages[1].role == "assistant"
    assert det_cdx.messages[1].text == "已完成插件架构重构。"


def test_workspace_git_diff_and_file_inspector(tmp_path: Path) -> None:
    repo = tmp_path / "demo_repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "dev@example.com"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Dev"], cwd=str(repo), check=True, capture_output=True)

    app_py = repo / "app.py"
    app_py.write_text("def hello():\n    return 'v1'\n", encoding="utf-8")
    (repo / ".env").write_text("SECRET=123", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo), check=True, capture_output=True)

    app_py.write_text("def hello():\n    return 'v2-antigravity'\n", encoding="utf-8")

    git_state = inspect_workspace_git(repo)
    assert git_state["is_git"] is True
    paths = [c["path"] for c in git_state["changes"]]
    assert "app.py" in paths
    assert ".env" not in paths  # Sensitive file hidden!

    diff_res = get_workspace_file_diff(repo, "app.py")
    assert diff_res["ok"] is True
    assert "+    return 'v2-antigravity'" in diff_res["diff"]

    # Path traversal and .env preview must be blocked
    assert read_workspace_file_preview(repo, "../outside.txt")["ok"] is False
    assert read_workspace_file_preview(repo, ".env")["ok"] is False

    dir_res = list_workspace_directory(repo, "")
    assert dir_res["ok"] is True
    names = [e["name"] for e in dir_res["entries"]]
    assert "app.py" in names
    assert ".env" not in names

    prev_res = read_workspace_file_preview(repo, "app.py")
    assert prev_res["ok"] is True
    assert "v2-antigravity" in prev_res["content"]


@pytest.mark.asyncio
async def test_web_pwa_e2e_streaming_upload_inspector_and_pc_sync(tmp_path: Path) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    ide_store = tmp_path / "ide_store"
    cli_store = tmp_path / "cli_store"
    codex_store = tmp_path / "codex_store"
    ide_cid = "ide-live-sync-12345"
    tf = ide_store / "brain" / ide_cid / ".system_generated" / "logs" / "transcript.jsonl"
    tf.parent.mkdir(parents=True)
    tf.write_text(
        json.dumps({"step_index": 0, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "电脑端第一句"}, ensure_ascii=False)
        + "\n"
        + json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "source": "MODEL", "content": "电脑端第一轮回复"}, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )

    tok = "super-secret-antigravity-token-999"
    cfg = _make_config(tmp_path, web_pwa_port=port, web_access_token=tok)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=ide_store,
        cli_store_dir=cli_store,
        codex_store_dir=codex_store,
    )
    pwa.ide_watch_interval = 0.2  # type: ignore[attr-defined]
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))

    try:
        await asyncio.sleep(0.25)

        # 1. Verify HTML & Manifest carry Stayy brand + Set-Cookie NEVER issued on GET /?token=... (POST /api/auth/login required)
        def _fetch_root_and_login() -> tuple[str, str, str]:
            r_get = urllib.request.urlopen(f"http://127.0.0.1:{port}/?token={tok}", timeout=5)
            html_body = r_get.read().decode("utf-8")
            get_cookie = r_get.headers.get("Set-Cookie") or ""
            req_login = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/auth/login",
                method="POST",
                data=b"",
                headers={
                    "Authorization": f"Bearer {tok}",
                    "Origin": f"http://127.0.0.1:{port}",
                    "Sec-Fetch-Site": "same-origin",
                },
            )
            with urllib.request.urlopen(req_login, timeout=5) as resp_login:
                assert resp_login.status == 200
                post_cookie = resp_login.headers.get("Set-Cookie") or ""
            return html_body, get_cookie, post_cookie

        html_text, get_cookie_hdr, cookie_hdr = await asyncio.to_thread(_fetch_root_and_login)
        assert "Stayy" in html_text
        assert get_cookie_hdr == ""
        assert "stayy_session=" in cookie_hdr
        sess_cookie_val = cookie_hdr.split("stayy_session=", 1)[1].split(";", 1)[0].strip()
        assert sess_cookie_val and sess_cookie_val != tok

        manifest_raw = await asyncio.to_thread(
            lambda: urllib.request.urlopen(f"http://127.0.0.1:{port}/manifest.json", timeout=5).read().decode("utf-8")
        )
        manifest_data = json.loads(manifest_raw)
        assert manifest_data["name"] == "Stayy"
        assert manifest_data["start_url"] == "./"
        assert tok not in manifest_raw

        # 2. Connect via signed stayy_session Cookie (no query token) to verify iOS standalone PWA auth fallback
        async with websockets.connect(
            f"ws://127.0.0.1:{port}/ws",
            additional_headers={"Cookie": f"stayy_session={sess_cookie_val}"},
        ) as ws:
            hello = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
            assert hello["type"] == "hello"

            # Workspace inspector WS call
            (tmp_path / "readme_demo.md").write_text("# Hello Assistant", encoding="utf-8")
            await ws.send(json.dumps({"type": "workspace_inspect", "rel_dir": ""}))
            ws_state = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
            assert ws_state["type"] == "workspace_state"
            assert any(e["name"] == "readme_demo.md" for e in ws_state["dir"]["entries"])

            # Select PC IDE conversation & verify live auto-watch push when transcript grows
            await ws.send(json.dumps({"type": "select_conversation", "conversation_id": ide_cid, "store": "ide"}))
            loaded = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
            assert loaded["type"] == "conversation_loaded"
            assert len(loaded["history"]) == 2

            with tf.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"step_index": 2, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "电脑端新增第二句"}, ensure_ascii=False) + "\n")
            pushed = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
            assert pushed["type"] == "conversation_loaded"
            assert pushed["silent"] is True
            assert len(pushed["history"]) == 3

            # Chunked upload + streaming continuation reply
            payload = b"test attachment content"
            await ws.send(json.dumps({"type": "upload_init", "upload_id": "u1", "name": "doc.txt", "size": len(payload)}))
            assert json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))["type"] == "upload_ack"
            await ws.send(json.dumps({"type": "upload_chunk", "upload_id": "u1", "data": base64.b64encode(payload).decode("ascii")}))
            assert json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))["type"] == "upload_progress"
            await ws.send(json.dumps({"type": "upload_complete", "upload_id": "u1"}))
            up_done = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
            assert up_done["type"] == "upload_done"

            await ws.send(
                json.dumps(
                    {
                        "type": "chat",
                        "text": "在手机上接着电脑对话往下做",
                        "attachments": [{"media_id": up_done["media_id"], "name": "doc.txt", "is_image": False}],
                    }
                )
            )
            final_item = None
            for _ in range(25):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "stream_end":
                    final_item = ev["item"]
                    break
            assert final_item is not None
            assert "电脑端第一轮回复" in final_item["text"]
            assert "在手机上接着电脑对话往下做" in final_item["text"]
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


def test_markdown_and_generic_tool_screenshot_extraction(tmp_path: Path) -> None:
    from stayy.web_pwa import harvest_recent_cli_turn_images

    shot1 = tmp_path / "Antigravity-窗口.png"
    shot1.write_bytes(b"\x89PNG\r\n\x1a\n" + b"1" * 80)
    shot2 = tmp_path / "step_6_media_0.png"
    shot2.write_bytes(b"\x89PNG\r\n\x1a\n" + b"2" * 80)

    # 1. Angle-bracketed Markdown image syntax (`![alt](<C:/path/中文.png>)`) used by Codex & Antigravity
    clean_txt, imgs, _ = extract_pwa_media_and_text(
        f"这是最新工作画面：\n\n![桌面工作截图](<{shot1.as_posix()}>)"
    )
    assert clean_txt == "这是最新工作画面："
    assert imgs == [shot1.resolve()]

    # 2. Antigravity IDE/CLI transcript `GENERIC` step carrying MCP screenshot `media`
    ide_store = tmp_path / "ide"
    cid = "shot-conv-99999999"
    tf = ide_store / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"
    tf.parent.mkdir(parents=True)
    tf.write_text(
        "\n".join(
            [
                json.dumps({"step_index": 0, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "帮我截个图"}, ensure_ascii=False),
                json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "source": "MODEL", "content": ""}, ensure_ascii=False),
                json.dumps({"step_index": 2, "type": "GENERIC", "media": [{"mime_type": "image/png", "uri": shot2.as_uri()}], "content": "Cursor Position"}, ensure_ascii=False),
                json.dumps({"step_index": 3, "type": "PLANNER_RESPONSE", "source": "MODEL", "content": "截好啦！"}, ensure_ascii=False),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    det = load_conversation_detail(cid, "ide", ide_dir=ide_store, cli_dir=tmp_path / "cli", codex_dir=tmp_path / "cdx")
    assert det is not None
    assert len(det.messages) == 2
    assert det.messages[1].image_paths == [shot2.resolve()]

    # 3. Live CLI turn media auto-harvesting when tool saves screenshot into logs/media/
    cli_store = tmp_path / "cli_live"
    live_cid = "live-cli-shot-111"
    media_dir = cli_store / "brain" / live_cid / ".system_generated" / "logs" / "media"
    media_dir.mkdir(parents=True)
    t_before = time.time()
    live_shot = media_dir / "step_4_media_0.png"
    live_shot.write_bytes(b"\x89PNG\r\n\x1a\n" + b"3" * 80)
    harvested = harvest_recent_cli_turn_images(cli_store, live_cid, t_before)
    assert harvested == [live_shot.resolve()]


def test_segno_qr_png_save_works() -> None:
    import io
    import segno

    buf = io.BytesIO()
    segno.make("http://127.0.0.1:8765/?token=demo", error="m").save(
        buf, kind="png", scale=4, border=2, dark="#ECECEC", light="#212121"
    )
    data = buf.getvalue()
    assert data.startswith(b"\x89PNG\r\n\x1a\n")


@pytest.mark.asyncio
async def test_switching_conversations_never_kills_running_command(tmp_path: Path) -> None:
    """Regression test: sending a command in Chat A and switching to view Chat B mid-run must NOT cancel Chat A."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    ide_store = tmp_path / "ide_iso"
    for cid, prompt in (("chat-a-111111", "对话A初始内容"), ("chat-b-222222", "对话B初始内容")):
        tf = ide_store / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"
        tf.parent.mkdir(parents=True)
        tf.write_text(
            json.dumps({"step_index": 0, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": prompt}, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    tok = "iso-secret-token-12345678"
    cfg = _make_config(tmp_path, web_pwa_port=port, web_access_token=tok)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=ide_store,
        cli_store_dir=tmp_path / "cli_iso",
        codex_store_dir=tmp_path / "cdx_iso",
    )
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))

    try:
        await asyncio.sleep(0.2)
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws:
            await asyncio.wait_for(ws.recv(), timeout=5.0)  # hello

            # 1. Open Chat A and start a slow command (__SLOW_STREAM__ sleeps 0.65s)
            await ws.send(json.dumps({"type": "select_conversation", "conversation_id": "chat-a-111111", "store": "ide"}))
            assert json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))["type"] == "conversation_loaded"

            await ws.send(json.dumps({"type": "chat", "text": "执行耗时命令 __SLOW_STREAM__"}))
            # Wait until stream starts in Chat A
            for _ in range(10):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "stream_delta":
                    break

            # 2. Switch to Chat B WHILE Chat A is still running!
            await ws.send(json.dumps({"type": "select_conversation", "conversation_id": "chat-b-222222", "store": "ide"}))
            for _ in range(10):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "conversation_loaded" and ev["conversation_id"] == "chat-b-222222":
                    assert ev["busy"] is False
                    break

            # Wait for background completion toast from Chat A
            for _ in range(15):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "toast" and "已完成回复" in ev["text"]:
                    break

            # 3. Switch back to Chat A — command and full reply must be preserved!
            await ws.send(json.dumps({"type": "select_conversation", "conversation_id": "chat-a-111111", "store": "ide"}))
            reloaded_a = None
            for _ in range(10):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "conversation_loaded" and ev["conversation_id"] == "chat-a-111111":
                    reloaded_a = ev
                    break
            assert reloaded_a is not None
            texts_a = [m["text"] for m in reloaded_a["history"]]
            assert any("前半段流式输出...后半段圆满结束！" in t for t in texts_a)
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_live_pc_ide_window_delivery_and_transcript_streaming(tmp_path: Path) -> None:
    """Verify sending a prompt inside an open PC Antigravity IDE conversation drives the PC window directly,
    streams live transcript deltas + screenshots back to mobile, and never duplicates turns on refresh.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    ide_store = tmp_path / "ide_pc_live"
    ide_cid = "0318a60f-e198-4f1d-8d52-e88a0cae38cc"
    tf = ide_store / "brain" / ide_cid / ".system_generated" / "logs" / "transcript.jsonl"
    tf.parent.mkdir(parents=True)
    tf.write_text(
        json.dumps({"step_index": 0, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "初始桌面消息"}, ensure_ascii=False)
        + "\n"
        + json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "source": "MODEL", "content": "初始桌面回复"}, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )

    db_path = ide_store / "conversation_summaries.db"
    con = sqlite3.connect(db_path)
    con.execute(
        "CREATE TABLE conversation_summaries ("
        "conversation_id TEXT, title TEXT, preview TEXT, step_count INT, "
        "last_modified_time TEXT, workspace_uris TEXT, status TEXT, "
        "source TEXT, app_data_dir TEXT, nesting_depth INT, killed INT)"
    )
    con.execute(
        "INSERT INTO conversation_summaries VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (ide_cid, "ChatGPT UI Browser Extension", "初始桌面回复", 2, "2026-11-25 04:00:00+00:00", "", "CASCADE_RUN_STATUS_IDLE", "", str(ide_store), 0, 0),
    )
    con.commit()
    con.close()

    shot_file = tmp_path / "pc_live_shot.png"
    shot_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"S" * 120)

    delivered_calls: list[tuple[str, str, str]] = []

    def _fake_pc_window_sender(cid: str, title: str, prompt: str) -> tuple[bool, str]:
        delivered_calls.append((cid, title, prompt))

        def _simulate_pc_ide_execution() -> None:
            time.sleep(0.08)
            c1 = sqlite3.connect(db_path)
            c1.execute("UPDATE conversation_summaries SET status = 'CASCADE_RUN_STATUS_RUNNING' WHERE conversation_id = ?", (cid,))
            c1.commit()
            c1.close()
            with tf.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"step_index": 2, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": f"<USER_REQUEST>{prompt}</USER_REQUEST>"}, ensure_ascii=False) + "\n")
                fh.write(json.dumps({"step_index": 3, "type": "PLANNER_RESPONSE", "source": "MODEL", "content": "正在检查电脑端页面...", "tool_calls": [{"name": "mcp_windows-mcp_Screenshot"}]}, ensure_ascii=False) + "\n")

            time.sleep(0.18)
            with tf.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"step_index": 4, "type": "GENERIC", "media": [{"mime_type": "image/png", "uri": shot_file.as_uri()}], "content": "Captured"}, ensure_ascii=False) + "\n")
                fh.write(json.dumps({"step_index": 5, "type": "PLANNER_RESPONSE", "source": "MODEL", "content": "电脑端同步修复已完成！"}, ensure_ascii=False) + "\n")

            c2 = sqlite3.connect(db_path)
            c2.execute("UPDATE conversation_summaries SET status = 'CASCADE_RUN_STATUS_IDLE' WHERE conversation_id = ?", (cid,))
            c2.commit()
            c2.close()

        import threading
        threading.Thread(target=_simulate_pc_ide_execution, daemon=True).start()
        return (True, "已投递至电脑端 Antigravity 窗口")

    tok = "pc-live-win-token-88888888"
    cfg = _make_config(tmp_path, web_pwa_port=port, web_access_token=tok)
    # Deliberately pass a non-existent CLI command so test FAILS if it ever falls back to headless agy.exe!
    sessions = SessionManager(cfg, command_override=[sys.executable, "-c", "import sys; sys.exit(99)"])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=ide_store,
        cli_store_dir=tmp_path / "cli_unused",
        codex_store_dir=tmp_path / "cdx_unused",
        pc_window_sender=_fake_pc_window_sender,
    )
    pwa.pc_ide_poll_interval = 0.08
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))

    try:
        await asyncio.sleep(0.2)
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws:
            await asyncio.wait_for(ws.recv(), timeout=5.0)  # hello

            await ws.send(json.dumps({"type": "select_conversation", "conversation_id": ide_cid, "store": "ide"}))
            loaded = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
            assert loaded["type"] == "conversation_loaded"
            assert len(loaded["history"]) == 2

            await ws.send(json.dumps({"type": "chat", "text": "进行bug检查与优化"}))

            saw_delta = False
            end_item = None
            for _ in range(30):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "stream_delta":
                    saw_delta = True
                elif ev["type"] == "stream_end":
                    end_item = ev["item"]
                    break

            assert len(delivered_calls) == 1
            assert delivered_calls[0] == (ide_cid, "ChatGPT UI Browser Extension", "进行bug检查与优化")
            assert saw_delta is True
            assert end_item is not None
            assert end_item["model"] == "Antigravity 电脑端"
            assert "正在检查电脑端页面..." in end_item["text"]
            assert "电脑端同步修复已完成！" in end_item["text"]
            assert len(end_item["images"]) == 1
            assert end_item["images"][0]["name"] == "pc_live_shot.png"

            # Refresh conversation and ensure zero duplicate turns!
            await ws.send(json.dumps({"type": "select_conversation", "conversation_id": ide_cid, "store": "ide"}))
            reloaded = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
            assert reloaded["type"] == "conversation_loaded"
            assert len(reloaded["history"]) == 4
            assert reloaded["history"][-2]["text"] == "进行bug检查与优化"
            assert "电脑端同步修复已完成！" in reloaded["history"][-1]["text"]
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


def test_encrypted_ios_pwa_beacon_roundtrip_and_tamper_rejection(tmp_path: Path) -> None:
    from stayy.beacon import (
        build_static_pwa_bundle,
        decrypt_beacon_payload,
        encrypt_beacon_payload,
    )

    secret = "my-secret-ios-pwa-token-2026"
    orig = {
        "tunnel_url": "https://fast-nebula-orbit.trycloudflare.com",
        "lan_url": "http://192.168.1.88:8765",
        "ts": 1795580000000,
    }
    env = encrypt_beacon_payload(orig, secret)
    assert "fast-nebula-orbit" not in json.dumps(env)
    assert "192.168.1.88" not in json.dumps(env)

    dec = decrypt_beacon_payload(env, secret)
    assert dec == orig

    # Wrong token or tampered ciphertext MUST fail MAC check before decryption!
    with pytest.raises(ValueError, match="MAC"):
        decrypt_beacon_payload(env, "wrong-token-000000")

    tampered = dict(env)
    tampered["ct"] = ("A" if env["ct"][0] != "A" else "B") + env["ct"][1:]
    with pytest.raises(ValueError, match="MAC"):
        decrypt_beacon_payload(tampered, secret)

    # Verify static iOS PWA bundle builder injects repo metadata, host_id/nonce & relative start_url
    proj_root = Path(__file__).resolve().parents[1]
    stage = tmp_path / "gh_pages_out"
    bundle_env, pub_nonce = build_static_pwa_bundle(
        proj_root,
        stage,
        owner="wwd177",
        repo="stayy",
        access_token=secret,
        tunnel_url=orig["tunnel_url"],
        lan_url=orig["lan_url"],
        host_id="host-stayy-01",
        nonce="nonce-stayy-01",
    )
    assert pub_nonce == "nonce-stayy-01"
    dec_bundle = decrypt_beacon_payload(bundle_env, secret)
    assert dec_bundle["host_id"] == "host-stayy-01"
    assert dec_bundle["nonce"] == "nonce-stayy-01"
    assert (stage / "index.html").is_file()
    assert 'data-beacon-repo="wwd177/stayy"' in (stage / "index.html").read_text(encoding="utf-8")
    assert (stage / "apple-touch-icon.png").is_file()
    assert (stage / "beacon.json").is_file()
    manifest_obj = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
    assert manifest_obj["start_url"] == "./"


@pytest.mark.asyncio
async def test_create_new_pc_ide_conversation_from_mobile_and_continue(tmp_path: Path) -> None:
    """Verify tapping `new_conversation` on mobile opens a new PC Antigravity window chat,
    creates a new IDE conversation ID on first prompt, streams live reply, and routes turn 2 to that new PC ID.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    ide_store = tmp_path / "ide_new_pc"
    ide_store.mkdir(parents=True)
    db_path = ide_store / "conversation_summaries.db"
    con = sqlite3.connect(db_path)
    con.execute(
        "CREATE TABLE conversation_summaries ("
        "conversation_id TEXT, title TEXT, preview TEXT, step_count INT, "
        "last_modified_time TEXT, workspace_uris TEXT, status TEXT, "
        "source TEXT, app_data_dir TEXT, nesting_depth INT, killed INT)"
    )
    con.commit()
    con.close()

    opened_count = 0
    created_prompts: list[str] = []
    followup_calls: list[tuple[str, str, str]] = []
    new_pc_cid = "new-pc-agent-88889999"

    def _fake_new_opener() -> tuple[bool, str]:
        nonlocal opened_count
        opened_count += 1
        return (True, "已在电脑端打开新对话窗口")

    def _fake_new_sender(prompt: str) -> tuple[bool, str, str]:
        created_prompts.append(prompt)
        tf = ide_store / "brain" / new_pc_cid / ".system_generated" / "logs" / "transcript.jsonl"
        tf.parent.mkdir(parents=True, exist_ok=True)

        def _sim_new() -> None:
            time.sleep(0.06)
            c1 = sqlite3.connect(db_path)
            c1.execute(
                "INSERT INTO conversation_summaries VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (new_pc_cid, prompt[:24], "", 1, "2026-11-25 08:30:00+00:00", "", "CASCADE_RUN_STATUS_RUNNING", "", str(ide_store), 0, 0),
            )
            c1.commit()
            c1.close()
            tf.write_text(
                json.dumps({"step_index": 0, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": prompt}, ensure_ascii=False)
                + "\n"
                + json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "source": "MODEL", "content": "已在电脑端成功创建新窗口并完成第一轮回复！"}, ensure_ascii=False)
                + "\n",
                encoding="utf-8",
            )
            time.sleep(0.12)
            c2 = sqlite3.connect(db_path)
            c2.execute("UPDATE conversation_summaries SET status = 'CASCADE_RUN_STATUS_IDLE' WHERE conversation_id = ?", (new_pc_cid,))
            c2.commit()
            c2.close()

        import threading
        threading.Thread(target=_sim_new, daemon=True).start()
        return (True, new_pc_cid, "已在电脑端新建 Antigravity 会话并发送")

    def _fake_followup_sender(cid: str, title: str, prompt: str) -> tuple[bool, str]:
        followup_calls.append((cid, title, prompt))
        tf = ide_store / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"

        def _sim_followup() -> None:
            time.sleep(0.06)
            c1 = sqlite3.connect(db_path)
            c1.execute("UPDATE conversation_summaries SET status = 'CASCADE_RUN_STATUS_RUNNING' WHERE conversation_id = ?", (cid,))
            c1.commit()
            c1.close()
            with tf.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"step_index": 2, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": prompt}, ensure_ascii=False) + "\n")
                fh.write(json.dumps({"step_index": 3, "type": "PLANNER_RESPONSE", "source": "MODEL", "content": "新窗口第二轮继续执行完毕！"}, ensure_ascii=False) + "\n")
            time.sleep(0.12)
            c2 = sqlite3.connect(db_path)
            c2.execute("UPDATE conversation_summaries SET status = 'CASCADE_RUN_STATUS_IDLE' WHERE conversation_id = ?", (cid,))
            c2.commit()
            c2.close()

        import threading
        threading.Thread(target=_sim_followup, daemon=True).start()
        return (True, "OK")

    tok = "new-pc-chat-token-77777777"
    cfg = _make_config(tmp_path, web_pwa_port=port, web_access_token=tok)
    sessions = SessionManager(cfg, command_override=[sys.executable, "-c", "import sys; sys.exit(99)"])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=ide_store,
        cli_store_dir=tmp_path / "cli_unused2",
        codex_store_dir=tmp_path / "cdx_unused2",
        pc_window_new_opener=_fake_new_opener,
        pc_window_new_sender=_fake_new_sender,
        pc_window_sender=_fake_followup_sender,
    )
    pwa.pc_ide_poll_interval = 0.08
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))

    try:
        await asyncio.sleep(0.2)
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws:
            await asyncio.wait_for(ws.recv(), timeout=5.0)  # hello

            # 1. Tap "新建电脑端对话" on mobile
            await ws.send(json.dumps({"type": "new_conversation", "workspace": "", "target": "ide"}))
            saw_ide_meta = False
            for _ in range(8):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "meta_update" and ev.get("active_store") == "ide":
                    saw_ide_meta = True
                if ev["type"] == "toast":
                    break
            assert opened_count == 1
            assert saw_ide_meta is True

            # 2. Send first prompt -> creates `new_pc_cid` on PC IDE window!
            await ws.send(json.dumps({"type": "chat", "text": "帮我在电脑新建一个数据分析项目"}))
            end1 = None
            bound_cid = ""
            for _ in range(30):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "meta_update" and ev.get("active_conversation_id"):
                    bound_cid = ev["active_conversation_id"]
                elif ev["type"] == "stream_end":
                    end1 = ev["item"]
                    break
            assert created_prompts == ["帮我在电脑新建一个数据分析项目"]
            assert bound_cid == new_pc_cid
            assert end1 is not None
            assert "已在电脑端成功创建新窗口并完成第一轮回复！" in end1["text"]

            # 3. Send second follow-up prompt -> must route to existing `new_pc_cid` via `pc_window_sender`!
            await ws.send(json.dumps({"type": "chat", "text": "继续添加可视化图表"}))
            end2 = None
            for _ in range(30):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "stream_end":
                    end2 = ev["item"]
                    break
            assert len(followup_calls) == 1
            assert followup_calls[0][0] == new_pc_cid
            assert followup_calls[0][2] == "继续添加可视化图表"
            assert end2 is not None
            assert "新窗口第二轮继续执行完毕！" in end2["text"]
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_duplicate_inflight_chat_guard_and_new_codex_thread(tmp_path: Path) -> None:
    """Verify:
    1. Sending a duplicate `chat` frame while the same slot is mid-stream emits a clean toast without corrupting the stream.
    2. Creating a brand-new `codex` conversation (`target='codex'`) runs `codex exec`, binds `thread_id`, and extracts title from rollout.
    3. `index.html` scopes `.drawer-tab[data-f]` so `.new-target-tab` onclick handlers are never overwritten.
    """
    html_src = (Path(__file__).resolve().parents[1] / "src" / "stayy" / "static" / "index.html").read_text(encoding="utf-8")
    assert ".drawer-tab[data-f]" in html_src
    assert "querySelectorAll('.drawer-tab')" not in html_src

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    # Mock `codex` CLI script that emits `thread.started` + `agent_message` and writes rollout JSONL
    codex_dir = tmp_path / "codex_new"
    sess_dir = codex_dir / "sessions" / "2026" / "11" / "25"
    sess_dir.mkdir(parents=True)
    new_cdx_id = "cdx-brand-new-77889900"
    rollout = sess_dir / f"rollout-2026-11-25T17-00-00-{new_cdx_id}.jsonl"

    mock_codex_py = tmp_path / "mock_codex.py"
    mock_codex_py.write_text(
        "import json, sys\n"
        "prompt = sys.stdin.read().strip()\n"
        f"open({str(rollout)!r}, 'w', encoding='utf-8').write("
        f"json.dumps({{'type':'response_item','payload':{{'type':'message','role':'user','content':[{{'type':'input_text','text':prompt}}]}}}}, ensure_ascii=False) + '\\n')\n"
        f"print(json.dumps({{'type':'thread.started','thread_id':{new_cdx_id!r}}}), flush=True)\n"
        "print(json.dumps({'type':'item.completed','item':{'type':'agent_message','text':'Codex 新会话创建成功！'}}, ensure_ascii=False), flush=True)\n",
        encoding="utf-8",
    )
    mock_codex_cmd = tmp_path / ("mock_codex.cmd" if sys.platform == "win32" else "mock_codex.sh")
    if sys.platform == "win32":
        mock_codex_cmd.write_text(f'@chcp 65001 >nul\r\n@"{sys.executable}" "{mock_codex_py}" %*\r\n', encoding="utf-8")
    else:
        mock_codex_cmd.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{mock_codex_py}" "$@"\n', encoding="utf-8")
        mock_codex_cmd.chmod(0o755)

    con_cdx = sqlite3.connect(codex_dir / "state_5.sqlite")
    con_cdx.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, updated_at INT, source TEXT, cwd TEXT, title TEXT, archived INT)")
    con_cdx.execute("INSERT INTO threads VALUES (?,?,?,?,?,?,?)", (new_cdx_id, str(rollout), 1795598000, "exec", str(tmp_path), "", 0))
    con_cdx.commit()
    con_cdx.close()

    tok = "guard-and-codex-token-6666"
    cfg = _make_config(tmp_path, web_pwa_port=port, web_access_token=tok)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=tmp_path / "ide_g",
        cli_store_dir=tmp_path / "cli_g",
        codex_store_dir=codex_dir,
        codex_cli_path=mock_codex_cmd,
    )
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))

    try:
        await asyncio.sleep(0.2)
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws:
            await asyncio.wait_for(ws.recv(), timeout=5.0)  # hello

            # 1. Start slow turn & immediately fire duplicate `chat` on same slot
            await ws.send(json.dumps({"type": "chat", "text": "第一条慢请求 __SLOW_STREAM__"}))
            for _ in range(10):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "stream_start":
                    break
            await ws.send(json.dumps({"type": "chat", "text": "重复连点第二条"}))

            saw_guard_toast = False
            saw_end = False
            for _ in range(20):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "toast" and "正在执行中" in ev["text"]:
                    saw_guard_toast = True
                elif ev["type"] == "stream_end":
                    saw_end = True
                    break
            assert saw_guard_toast is True
            assert saw_end is True

            # 2. Start brand-new Codex PC conversation (`target='codex'`)
            await ws.send(json.dumps({"type": "new_conversation", "workspace": str(tmp_path), "target": "codex"}))
            for _ in range(12):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "toast" and "Codex" in ev.get("text", ""):
                    break

            await ws.send(json.dumps({"type": "chat", "text": "帮我初始化 Codex 后端服务"}))
            cdx_end = None
            for _ in range(25):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "stream_end":
                    cdx_end = ev["item"]
                    break
            assert cdx_end is not None
            assert "Codex 新会话创建成功！" in cdx_end["text"]

            # Verify empty-title Codex thread peeks human title from rollout JSONL!
            items = list_local_conversations(limit=20, ide_dir=tmp_path / "ide_g", cli_dir=tmp_path / "cli_g", codex_dir=codex_dir)
            cdx_item = next((x for x in items if x.conversation_id == new_cdx_id), None)
            assert cdx_item is not None
            assert "帮我初始化 Codex 后端服务" in cdx_item.title
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_security_cswsh_port_identity_codex_reconnect_and_no_double_exec(tmp_path: Path) -> None:
    """Regression suite for Neon x GPT-6.2 Astra joint red-team audit:
    1. `probe_stayy_gateway_identity` distinguishes genuine Antigravity gateway (`'stayy'`) from an unrelated HTTP listener (`'foreign'`).
    2. Cookie-authenticated WebSocket rejects cross-origin `Origin` (CSWSH defense), while same-origin Cookie WS succeeds.
    3. Direct non-loopback peers cannot spoof `CF-Connecting-IP` to bypass rate-limiting, and `manifest.json` does not echo HttpOnly Cookie tokens.
    4. Reconnecting mid-Codex turn cleanly serializes `hello.inflight` (no `Process` JSON crash), and if Codex fails AFTER `thread.started`, it reports `ERROR` WITHOUT double-submitting the prompt to `agy`.
    5. Aborted chunk uploads clean up `.part` files on disconnect, and frontend HTML enforces `no-referrer` + safe DOM creation.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import threading
    from websockets.datastructures import Headers
    from stayy.beacon import decrypt_beacon_payload, encrypt_beacon_payload
    from stayy.launcher import probe_stayy_gateway_identity

    # Static frontend safety assertions
    html_src = (Path(__file__).resolve().parents[1] / "src" / "stayy" / "static" / "index.html").read_text(encoding="utf-8")
    assert '<meta name="referrer" content="no-referrer" />' in html_src
    assert 'id="bub-${id}"' not in html_src
    assert r"/^\s*(?:>|&gt;)/.test(lines[i])" in html_src

    # Beacon inner timestamp freshness check
    stale_env = encrypt_beacon_payload({"tunnel_url": "https://a.trycloudflare.com", "lan_url": "", "ts": 1000}, "tok-123")
    with pytest.raises(ValueError, match="expired"):
        decrypt_beacon_payload(stale_env, "tok-123", max_age_sec=60.0)
    fresh_env = encrypt_beacon_payload(
        {"tunnel_url": "https://a.trycloudflare.com", "lan_url": "", "ts": int(time.time() * 1000)},
        "tok-123",
    )
    assert decrypt_beacon_payload(fresh_env, "tok-123", max_age_sec=60.0)["tunnel_url"] == "https://a.trycloudflare.com"

    # 1. Foreign HTTP listener on random port MUST be detected as `'foreign'`
    class _ForeignHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"hello":"other-app"}')

        def log_message(self, *args) -> None:
            pass

    foreign_httpd = HTTPServer(("127.0.0.1", 0), _ForeignHandler)
    f_port = foreign_httpd.server_address[1]
    f_thread = threading.Thread(target=foreign_httpd.serve_forever, daemon=True)
    f_thread.start()
    try:
        assert probe_stayy_gateway_identity("127.0.0.1", f_port) == "foreign"
    finally:
        foreign_httpd.shutdown()
        foreign_httpd.server_close()

    # 2. Spin up WebPwaServer with a mock Codex script that sleeps briefly, emits `thread.started`, then exits 1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    mock_cdx_fail_py = tmp_path / "mock_cdx_midfail.py"
    mock_cdx_fail_py.write_text(
        "import json, sys, time\n"
        "_ = sys.stdin.read()\n"
        "print(json.dumps({'type':'thread.started','thread_id':'cdx-midfail-999'}), flush=True)\n"
        "sys.stderr.write('simulated mid-turn failure after thread started\\n')\n"
        "sys.stderr.flush()\n"
        "time.sleep(0.35)\n"
        "sys.exit(2)\n",
        encoding="utf-8",
    )
    mock_cdx_cmd = tmp_path / ("mock_cdx_midfail.cmd" if sys.platform == "win32" else "mock_cdx_midfail.sh")
    if sys.platform == "win32":
        mock_cdx_cmd.write_text(f'@chcp 65001 >nul\r\n@"{sys.executable}" "{mock_cdx_fail_py}" %*\r\n', encoding="utf-8")
    else:
        mock_cdx_cmd.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{mock_cdx_fail_py}" "$@"\n', encoding="utf-8")
        mock_cdx_cmd.chmod(0o755)

    tok = "astra-redteam-token-999"
    cfg = _make_config(tmp_path, web_pwa_port=port, web_access_token=tok)
    agy_calls: list[str] = []
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=tmp_path / "ide_sec",
        cli_store_dir=tmp_path / "cli_sec",
        codex_store_dir=tmp_path / "cdx_sec",
        codex_cli_path=mock_cdx_cmd,
    )

    # Verify non-loopback peer cannot spoof `CF-Connecting-IP`
    class _FakeLanConn:
        remote_address = ("192.168.1.88", 54321)

    hdr_spoof = Headers([("CF-Connecting-IP", "8.8.8.8")])
    assert pwa._client_ip(_FakeLanConn(), hdr_spoof) == "192.168.1.88"  # type: ignore[arg-type]

    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        await asyncio.sleep(0.2)
        assert (await asyncio.to_thread(probe_stayy_gateway_identity, "127.0.0.1", port)) == "stayy"

        sec_sess = pwa.auth.issue_session_token()

        # Cookie-only GET /manifest.json MUST NOT echo secret token into `start_url`
        def _fetch_manifest_with_cookie() -> dict:
            req_m = urllib.request.Request(
                f"http://127.0.0.1:{port}/manifest.json",
                headers={"Cookie": f"stayy_session={sec_sess}"},
            )
            with urllib.request.urlopen(req_m, timeout=3) as resp_m:
                return json.loads(resp_m.read().decode("utf-8"))

        manifest_obj = await asyncio.to_thread(_fetch_manifest_with_cookie)
        assert manifest_obj["start_url"] == "./"

        # Cookie-authenticated cross-origin WebSocket MUST be rejected with 4003 (CSWSH block!)
        async with websockets.connect(
            f"ws://127.0.0.1:{port}/ws",
            origin="https://evil.example",
            additional_headers={"Cookie": f"stayy_session={sec_sess}"},
        ) as ws_evil:
            with pytest.raises(websockets.exceptions.ConnectionClosed) as exc_info:
                await asyncio.wait_for(ws_evil.recv(), timeout=3.0)
            assert exc_info.value.rcvd is not None and exc_info.value.rcvd.code == 4003

        # Aborted upload MUST NOT leave `.part` or partial files behind on disconnect
        from stayy.desktop_tools import PROJECT_INBOX_DIR

        before_parts = set(PROJECT_INBOX_DIR.glob("*.part")) if PROJECT_INBOX_DIR.is_dir() else set()
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws_up:
            await asyncio.wait_for(ws_up.recv(), timeout=3.0)
            await ws_up.send(json.dumps({"type": "upload_init", "upload_id": "abort1", "name": "half.bin", "size": 100}))
            await asyncio.wait_for(ws_up.recv(), timeout=3.0)  # upload_ack
            await ws_up.send(json.dumps({"type": "upload_chunk", "upload_id": "abort1", "data": base64.b64encode(b"12345").decode()}))
            await asyncio.wait_for(ws_up.recv(), timeout=3.0)  # upload_progress
        await asyncio.sleep(0.15)
        after_parts = set(PROJECT_INBOX_DIR.glob("*.part")) if PROJECT_INBOX_DIR.is_dir() else set()
        assert after_parts - before_parts == set()

        # Reconnect while Codex turn is in-flight + verify NO fallback double-exec to `agy` when Codex fails post-accept
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws1:
            await asyncio.wait_for(ws1.recv(), timeout=3.0)  # hello
            await ws1.send(json.dumps({"type": "new_conversation", "workspace": str(tmp_path), "target": "codex"}))
            for _ in range(6):
                ev = json.loads(await asyncio.wait_for(ws1.recv(), timeout=3.0))
                if ev["type"] == "meta_update":
                    cdx_slot = ev["slot"]
                    break
            else:
                cdx_slot = ""
            assert cdx_slot

            orig_ask = pwa._session_for_slot(cdx_slot).ask

            async def _spy_ask(p: str, **kw):  # type: ignore[no-untyped-def]
                agy_calls.append(p)
                return await orig_ask(p, **kw)

            pwa._session_for_slot(cdx_slot).ask = _spy_ask  # type: ignore[method-assign]

            await ws1.send(json.dumps({"type": "chat", "slot": cdx_slot, "text": "只允许执行一次的修改指令"}))
            for _ in range(8):
                ev = json.loads(await asyncio.wait_for(ws1.recv(), timeout=3.0))
                if ev["type"] == "stream_start":
                    break

            # Open a second WS client mid-Codex turn -> `hello` MUST serialize cleanly without `TypeError: Process`!
            async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws2:
                hello2 = json.loads(await asyncio.wait_for(ws2.recv(), timeout=3.0))
                assert hello2["type"] == "hello"
                assert hello2["busy"] is True
                assert isinstance(hello2["inflight"], dict)
                assert "codex_proc" not in hello2["inflight"]

            final_item = None
            for _ in range(20):
                ev = json.loads(await asyncio.wait_for(ws1.recv(), timeout=5.0))
                if ev["type"] == "stream_end":
                    final_item = ev["item"]
                    break
            assert final_item is not None
            assert "simulated mid-turn failure" in final_item["text"]
            # CRITICAL: `agy` fallback MUST NOT have been called!
            assert agy_calls == []
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_ergonomic_and_expert_upgrades_e2e(tmp_path: Path) -> None:
    """Verify user & expert power upgrades:
    1. `client_id` idempotent deduplication + `chat_ack` delivery receipts prevent duplicate execution on mobile reconnect.
    2. Background slot completion populates `slots_overview.unread` and clears upon `select_conversation`.
    3. One-time IDE approval `action_token` cannot be replayed twice, and `perform_desktop_remote_input` rejects non-whitelisted keys.
    4. `pc_system_inspect`, `pc_clipboard_set`, `pc_clipboard_get`, and `desktop_input` round-trip cleanly over WebSocket.
    5. Frontend `index.html` includes hunk diff quoting, collapsible long code cards, touch desktop toggle, and per-slot drafts.
    """
    from stayy.approvals import deny_auto_invoke
    from stayy.desktop_tools import (
        invoke_antigravity_ide_action,
        perform_desktop_remote_input,
        set_pc_clipboard_text,
    )

    html_src = (Path(__file__).resolve().parents[1] / "src" / "stayy" / "static" / "index.html").read_text(encoding="utf-8")
    assert "code-expand-bar" in html_src
    assert "diff-hunk-card" in html_src
    assert "toggleTouchBtn" in html_src
    assert "stayy_slot_drafts_v1" in html_src
    assert "slashMenu" in html_src

    # Whitelist, NaN/Inf, & size guards on desktop tools
    ok_bad_key, msg_bad_key = perform_desktop_remote_input("key", key_name="f12_evil")
    assert ok_bad_key is False and "白名单" in msg_bad_key
    ok_nan, msg_nan = perform_desktop_remote_input("click", x_ratio=float("nan"), y_ratio=0.5)
    assert ok_nan is False and "有限" in msg_nan
    ok_oob, _ = perform_desktop_remote_input("click", x_ratio=1.5, y_ratio=0.5)
    assert ok_oob is False
    ok_bad_act, _ = perform_desktop_remote_input("drag_drop")
    assert ok_bad_act is False
    ok_huge_clip, _ = set_pc_clipboard_text("x" * 70000)
    assert ok_huge_clip is False

    # Branch B: direct blind IDE action invocation MUST always be rejected with zero desktop action
    ok_exp, note_exp = invoke_antigravity_ide_action("any-tok-1")
    assert ok_exp is False and "放大镜" in note_exp
    ok_deny, code_deny, _ = deny_auto_invoke()
    assert ok_deny is False and code_deny == "manual_screen_required"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    clip_box = {"text": "initial-pc-clip"}
    invoked_tokens: list[str] = []
    remote_inputs: list[tuple[str, float, float, str]] = []

    def _mock_inspect_actions(cid: str) -> list[dict]:
        return [{"action_token": "tok-proceed-once", "label": "Proceed", "conversation_id": cid}]

    def _mock_invoke_action(tok: str) -> tuple[bool, str]:
        if tok in invoked_tokens:
            return (False, "确认按钮已过期或已使用")
        invoked_tokens.append(tok)
        return (True, "已在电脑端触发「Proceed」")

    def _mock_desk_input(act: str, xr: float, yr: float, kn: str) -> tuple[bool, str]:
        remote_inputs.append((act, xr, yr, kn))
        return (True, f"已执行 {act}")

    tok = "ergonomic-upgrade-tok-777"
    cfg = _make_config(
        tmp_path,
        web_pwa_port=port,
        web_access_token=tok,
        remote_desktop_enabled=True,
        remote_clipboard_enabled=True,
    )
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=tmp_path / "ide_erg",
        cli_store_dir=tmp_path / "cli_erg",
        codex_store_dir=tmp_path / "cdx_erg",
        ide_actions_inspector=_mock_inspect_actions,
        ide_action_invoker=_mock_invoke_action,
        desktop_input_handler=_mock_desk_input,
        pc_clipboard_getter=lambda: {"ok": True, "text": clip_box["text"], "truncated": False, "length": len(clip_box["text"])},
        pc_clipboard_setter=lambda t: (clip_box.__setitem__("text", t) or True, "已写入电脑剪贴板"),
        pc_system_inspector=lambda _ws: {
            "cpu_pct": 14,
            "ram_used_gb": 12.4,
            "ram_total_gb": 32.0,
            "ram_pct": 39,
            "disk_free_gb": 180.5,
            "disk_total_gb": 512.0,
            "battery_pct": 88,
            "charging": True,
            "ports": [{"port": 5173, "pid": 4321, "process": "node", "addr": "127.0.0.1"}],
        },
    )
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        await asyncio.sleep(0.2)
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws:
            hello = json.loads(await asyncio.wait_for(ws.recv(), timeout=4.0))
            assert "slots_overview" in hello

            # 1. Idempotent `client_id` deduplication + `chat_ack`
            await ws.send(json.dumps({"type": "chat", "client_id": "idem-msg-001", "text": "测试幂等回执"}))
            saw_ack = False
            saw_end = False
            for _ in range(20):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "chat_ack" and ev["client_id"] == "idem-msg-001":
                    saw_ack = True
                elif ev["type"] == "stream_end":
                    saw_end = True
                    break
            assert saw_ack and saw_end

            turns_after_first = pwa._session_for_slot(hello["slot"]).num_turns
            assert turns_after_first == 1

            # Re-send exact same `client_id` -> must return `duplicate_ignored` and NOT run `ask` again!
            await ws.send(json.dumps({"type": "chat", "client_id": "idem-msg-001", "text": "测试幂等回执"}))
            dup_ack = None
            for _ in range(8):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "chat_ack" and ev.get("stage") == "duplicate_ignored":
                    dup_ack = ev
                    break
            assert dup_ack is not None
            assert pwa._session_for_slot(hello["slot"]).num_turns == 1

            # 2. Branch-B IDE approval read-only inspect & hard-rejected auto-invoke
            await ws.send(json.dumps({"type": "ide_actions_inspect", "conversation_id": "cid-demo"}))
            act_ev = None
            for _ in range(6):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "ide_actions":
                    act_ev = ev
                    break
            assert act_ev is not None
            assert act_ev["mode"] == "manual_screen_only"
            assert act_ev["actions"][0]["label"] == "Proceed"

            await ws.send(json.dumps({"type": "ide_action_invoke", "action_token": "tok-proceed-once"}))
            res_ev = None
            for _ in range(6):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "ide_action_result":
                    res_ev = ev
                    break
            assert res_ev is not None and res_ev["ok"] is False
            assert res_ev["code"] == "manual_screen_required"
            assert invoked_tokens == []

            # 3. PC System + Bidirectional Clipboard Sync
            await ws.send(json.dumps({"type": "pc_system_inspect"}))
            sys_ev = None
            for _ in range(6):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "pc_system_state":
                    sys_ev = ev
                    break
            assert sys_ev is not None
            assert sys_ev["system"]["ports"][0]["port"] == 5173
            assert sys_ev["clipboard"]["text"] == "initial-pc-clip"

            await ws.send(json.dumps({"type": "pc_clipboard_set", "text": "from-iphone-clipboard"}))
            for _ in range(6):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "toast" and "剪贴板" in ev["text"]:
                    break
            assert clip_box["text"] == "from-iphone-clipboard"

            # 4. Invalid `desktop_input` coordinates emit toast WITHOUT killing the WS loop!
            await ws.send(json.dumps({"type": "desktop_input", "action": "click", "x_ratio": "bad-num", "y_ratio": 0.5}))
            err_toast = None
            for _ in range(6):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "toast" and "无效" in ev["text"]:
                    err_toast = ev
                    break
            assert err_toast is not None

            await ws.send(json.dumps({"type": "ping", "ts": 12345}))
            pong_ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
            assert pong_ev["type"] == "pong"
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_chatgpt_ios_ui_steps_timeline_and_canvas_sandbox(tmp_path: Path):
    """Verify ChatGPT iOS v10 UI surface, historical & live step timelines, and null-origin Canvas sandbox."""
    from stayy.beacon import STATIC_PWA_SW_JS
    from stayy.conversations import _humanize_tool_step, load_conversation_detail
    from stayy.web_pwa import STATIC_DIR

    assert "CACHE_PREFIX = 'stayy-ios-shell-' + SCOPE_SLUG + '-'" in STATIC_PWA_SW_JS
    assert "CACHE_NAME = CACHE_PREFIX + 'v3'" in STATIC_PWA_SW_JS
    assert "REQUIRED_SHELL = ['./', './index.html']" in STATIC_PWA_SW_JS
    assert "Promise.allSettled(OPTIONAL_ASSETS" in STATIC_PWA_SW_JS
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert "--app-y" in html and "pageTop" in html
    assert "position: fixed" not in html
    assert "connEpoch" in html
    assert "inboundSeq" in html
    assert "isForActiveSlot" in html
    assert 'content="#000000"' in html
    assert 'id="appStage"' in html
    assert 'id="tabGlider"' in html
    assert 'id="netReconnPill"' in html
    assert "--standalone-h" not in html
    assert "ambient-glow" not in html
    assert 'id="composerCard"' in html
    assert "compact-pill" in html
    assert 'id="centerPlaceholder"' in html
    assert 'id="tabbar"' in html
    assert 'id="stopBtn"' in html
    assert "body.in-conversation:not(.view-more) .tabbar" not in html
    assert 'id="tabAssistant"' in html
    assert 'id="assistantPage"' in html
    assert 'id="drawerNavAssistant"' in html
    assert 'id="morePage"' in html
    assert 'id="drawerNavAgy"' in html
    assert 'id="drawerNavCodex"' in html
    assert "BENTO_MODULES" in html
    assert "AI_SPECIALIST_SKILLS" in html
    assert "cont-deck" in html
    assert 'id="drawerNewChatBtn"' in html
    assert 'id="composerTargetBtn"' in html
    assert "thought-accordion" in html
    assert 'id="inChatSearchBar"' in html
    assert 'id="drawerProjectsBox"' in html
    assert 'id="canvasFrame"' in html
    assert 'sandbox="allow-scripts"' in html
    assert "allow-same-origin" not in html
    assert "new DOMParser()" in html
    assert "doc.head.prepend(cspEl)" in html

    # 1. Tool step humanizer & historical Antigravity IDE transcript step extraction
    assert _humanize_tool_step("read_file", {"Path": "C:/repo/app.py"}) == "读取 app.py"
    assert _humanize_tool_step("edit_file", {"Path": "C:/repo/index.html"}) == "修改 index.html"

    ide_dir = tmp_path / "ide_store"
    cid = "ide-steps-conv-001"
    log_dir = ide_dir / "brain" / cid / ".system_generated" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    transcript_lines = [
        json.dumps({"type": "USER_INPUT", "step_index": 1, "content": "<USER_REQUEST>帮我修一下样式</USER_REQUEST>"}),
        json.dumps(
            {
                "type": "PLANNER_RESPONSE",
                "step_index": 2,
                "content": "",
                "tool_calls": [
                    {"name": "read_file", "args": {"Path": "C:/demo/index.html"}},
                    {"name": "edit_file", "args": {"Path": "C:/demo/index.html"}},
                ],
            }
        ),
        json.dumps({"type": "PLANNER_RESPONSE", "step_index": 3, "content": "已完成样式优化。"}),
    ]
    (log_dir / "transcript.jsonl").write_text("\n".join(transcript_lines) + "\n", encoding="utf-8")

    det = load_conversation_detail(cid, store="ide", ide_dir=ide_dir, cli_dir=tmp_path / "cli", codex_dir=tmp_path / "cdx")
    assert det is not None and len(det.messages) == 2
    assert det.messages[1].steps == ["读取 index.html", "修改 index.html"]

    # 2. Live streaming `steps` & `duration_sec` over WebSocket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    tok = "chatgpt-ios-v10-token"
    cfg = _make_config(tmp_path, web_pwa_port=port, web_access_token=tok)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=ide_dir,
        cli_store_dir=tmp_path / "cli",
        codex_store_dir=tmp_path / "cdx",
    )
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        await asyncio.sleep(0.2)
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws:
            await asyncio.wait_for(ws.recv(), timeout=4.0)  # hello
            await ws.send(json.dumps({"type": "chat", "text": "__TOOL_STEP__ 写个标题预览"}))
            saw_status_steps = False
            end_item = None
            for _ in range(20):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "stream_status" and ev.get("steps"):
                    saw_status_steps = True
                elif ev["type"] == "stream_end":
                    end_item = ev["item"]
                    break
            assert saw_status_steps is True
            assert end_item is not None
            assert len(end_item.get("steps") or []) >= 1
            assert int(end_item.get("duration_sec") or 0) >= 1

            # 3. `new_conversation` echoes `req_id` on `clear_history` so branch-chat drafts never collide
            await ws.send(json.dumps({"type": "new_conversation", "workspace": "", "target": "cli", "req_id": "br-test-99"}))
            clear_ev = None
            for _ in range(10):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "clear_history":
                    clear_ev = ev
                    break
            assert clear_ev is not None and clear_ev.get("req_id") == "br-test-99"

            # 4. Stalled/hung peer socket MUST be evicted via `_safe_send` timeout without blocking healthy clients!
            class _HungPeer:
                async def send(self, _raw: str) -> None:
                    await asyncio.sleep(60.0)

                async def close(self) -> None:
                    return None

            hung_peer = _HungPeer()
            pwa._clients.add(hung_peer)  # type: ignore[arg-type]
            t0 = time.monotonic()
            ok_hung = await pwa._safe_send(hung_peer, {"type": "pong"}, timeout=0.08)  # type: ignore[arg-type]
            assert ok_hung is False
            assert (time.monotonic() - t0) < 1.0
            assert hung_peer not in pwa._clients
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_ide_window_delivery_failure_never_forks_cli_and_watch_syncs(tmp_path: Path) -> None:
    """Verify:
    1. When `slot_store == 'ide'` and `pc_window_sender` fails (e.g. PC locked or input box missing),
       `WebPwaServer` NEVER silently spawns a forked `agy` CLI session or pollutes `.continuation_map.json`,
       and reports `Antigravity 电脑端` rather than a mismatched CLI model.
    2. Subsequent turns typed on the PC IDE window are still live-pushed to mobile via `_ide_watch_loop`
       at the very bottom of the conversation, even if legacy `.continuation_map.json` had a stale entry.
    """
    if sys.platform == "win32":
        from stayy.desktop_tools import _run_powershell_script
        # Ensure scripts >32KB never trigger WinError 206 (`CreateProcess` command-line length limit)!
        huge_comment = "# " + ("超长脚本长度免疫验证_" * 2200) + "\n"
        ps_res = _run_powershell_script(huge_comment + '[Console]::OutputEncoding=[Text.Encoding]::UTF8; Write-Output "OK:UTF8中文正常"', timeout=10)
        assert ps_res.returncode == 0 and "OK:UTF8中文正常" in ps_res.stdout

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    ide_dir = tmp_path / "ide_nofork"
    cli_dir = tmp_path / "cli_nofork"
    cid = "c63c3f37-e9d8-4ea1-a261-cbf3867a7336"
    tf = ide_dir / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"
    tf.parent.mkdir(parents=True, exist_ok=True)
    tf.write_text(
        json.dumps({"step_index": 0, "type": "USER_INPUT", "created_at": "2026-11-25T15:00:00Z", "content": "电脑端已有第一句"}, ensure_ascii=False)
        + "\n"
        + json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "created_at": "2026-11-25T15:00:05Z", "content": "电脑端已有第一轮回复"}, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )

    # Pre-seed a stale polluted continuation_map entry pointing to an old CLI fork
    stale_fork_cid = "413d5d3f-532f-44f4-83d1-ed616fa1f5c2"
    stale_tf = cli_dir / "brain" / stale_fork_cid / ".system_generated" / "logs" / "transcript.jsonl"
    stale_tf.parent.mkdir(parents=True, exist_ok=True)
    stale_tf.write_text(
        json.dumps({"step_index": 0, "type": "PLANNER_RESPONSE", "created_at": "2026-11-25T15:55:00Z", "content": "旧分叉错误回复"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    cont_map_file = tmp_path / "cont_map.json"
    cont_map_file.write_text(json.dumps({f"ide:{cid}": stale_fork_cid, cid: stale_fork_cid}), encoding="utf-8")

    tok = "no-silent-fork-token-2026"
    cfg = _make_config(tmp_path, web_pwa_port=port, web_access_token=tok)
    # Any attempt to spawn fallback `agy` CLI will crash with exit=99!
    sessions = SessionManager(cfg, command_override=[sys.executable, "-c", "import sys; sys.exit(99)"])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=ide_dir,
        cli_store_dir=cli_dir,
        codex_store_dir=tmp_path / "cdx_nofork",
        continuation_map_path=cont_map_file,
        pc_window_sender=lambda _cid, _t, _p: (False, "桌面窗口未处于前台焦点"),
    )
    pwa.ide_watch_interval = 0.15  # type: ignore[attr-defined]
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        await asyncio.sleep(0.2)
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws:
            await asyncio.wait_for(ws.recv(), timeout=4.0)  # hello

            await ws.send(json.dumps({"type": "select_conversation", "conversation_id": cid, "store": "ide"}))
            loaded = json.loads(await asyncio.wait_for(ws.recv(), timeout=4.0))
            assert loaded["type"] == "conversation_loaded"
            # Stale forked CLI turn MUST NOT be appended to live PC IDE conversation!
            assert all("旧分叉错误回复" not in m["text"] for m in loaded["history"])
            assert len(loaded["history"]) == 2

            # Attempt to send while PC window rejects delivery -> must return clean IDE error, ZERO CLI spawn!
            await ws.send(json.dumps({"type": "chat", "text": "测试防分叉保护"}))
            end_ev = None
            for _ in range(15):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=4.0))
                if ev["type"] == "stream_end":
                    end_ev = ev["item"]
                    break
            assert end_ev is not None
            assert end_ev["model"] == "Antigravity 电脑端"
            assert "未能投递到电脑端 Antigravity 聊天窗口" in end_ev["text"]
            assert pwa._session_for_slot(f"ide:{cid}").num_turns == 0

            # Now user types a new turn directly on the PC IDE window -> mobile must live-receive it at the bottom!
            await asyncio.sleep(0.05)
            with tf.open("a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps({"step_index": 2, "type": "USER_INPUT", "created_at": "2026-11-25T16:10:00Z", "content": "电脑端新发送的命令"}, ensure_ascii=False)
                    + "\n"
                    + json.dumps({"step_index": 3, "type": "PLANNER_RESPONSE", "created_at": "2026-11-25T16:10:05Z", "content": "电脑端最新真实回复"}, ensure_ascii=False)
                    + "\n"
                )

            pushed = None
            for _ in range(15):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=4.0))
                if ev["type"] == "conversation_loaded" and ev.get("silent") is True:
                    pushed = ev
                    break
            assert pushed is not None
            assert pushed["history"][-2]["text"] == "电脑端新发送的命令"
            assert pushed["history"][-1]["text"] == "电脑端最新真实回复"
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_mobile_sidebar_dual_entries_noise_filtering_and_gentle_home_switch(tmp_path: Path) -> None:
    """Verify:
    1. Truncated `[系统设定 - ...` DB titles are stripped cleanly and fall back to human transcript prompt.
    2. Internal `【只读协作顾问约束】`, `【反拍马屁红队审查模式】`, and `只回复两个字：收到` threads are excluded.
    3. `new_conversation` with `open_pc_window=False` (Home button) resets cleanly without triggering `pc_window_new_opener`.
    """
    from stayy.conversations import _clean_display_title, list_local_conversations

    assert _clean_display_title("[系统设定 - 请在本次对话全程严格遵守，绝不要在回复中提") == ""
    assert _clean_display_title("[系统设定 - 规则]固定规则[/系统设定]\n帮我优化移动端布局") == "帮我优化移动端布局"

    ide_dir = tmp_path / "ide_clean"
    cli_dir = tmp_path / "cli_clean"
    cdx_dir = tmp_path / "cdx_clean"
    ide_dir.mkdir()
    cli_dir.mkdir()
    cdx_dir.mkdir()

    # 1. Genuine IDE chat whose DB title was truncated inside `[系统设定 - ...`
    good_ide_cid = "good-ide-conv-11223344"
    good_tf = ide_dir / "brain" / good_ide_cid / ".system_generated" / "logs" / "transcript.jsonl"
    good_tf.parent.mkdir(parents=True)
    good_tf.write_text(
        json.dumps(
            {
                "step_index": 0,
                "type": "USER_INPUT",
                "content": "[系统设定 - 请在本次对话全程严格遵守]内部规则[/系统设定]\n排查 Antigravity 登录后无法进入",
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    # 2. Synthetic two-word ping IDE chat -> must be filtered out
    ping_ide_cid = "ping-ide-conv-55667788"
    ping_tf = ide_dir / "brain" / ping_ide_cid / ".system_generated" / "logs" / "transcript.jsonl"
    ping_tf.parent.mkdir(parents=True)
    ping_tf.write_text(
        json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "只回复两个字：收到"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    con_ide = sqlite3.connect(ide_dir / "conversation_summaries.db")
    con_ide.execute(
        "CREATE TABLE conversation_summaries ("
        "conversation_id TEXT, title TEXT, preview TEXT, step_count INT, "
        "last_modified_time TEXT, workspace_uris TEXT, status TEXT, "
        "source TEXT, app_data_dir TEXT, nesting_depth INT, killed INT)"
    )
    con_ide.execute(
        "INSERT INTO conversation_summaries VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            good_ide_cid,
            "[系统设定 - 请在本次对话全程严格遵守，绝不要在回复中提",
            "[系统设定 - 请在本次对话全程严格遵守，绝不要在回复中提",
            4,
            "2026-11-25 17:00:00+00:00",
            "",
            "CASCADE_RUN_STATUS_IDLE",
            "",
            str(ide_dir),
            0,
            0,
        ),
    )
    con_ide.execute(
        "INSERT INTO conversation_summaries VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            ping_ide_cid,
            "只回复两个字：收到",
            "收到",
            2,
            "2026-11-25 17:01:00+00:00",
            "",
            "CASCADE_RUN_STATUS_IDLE",
            "",
            str(ide_dir),
            0,
            0,
        ),
    )
    con_ide.commit()
    con_ide.close()

    # 3. Codex store with 1 real thread and 1 internal `codex-astra` read-only advisor thread
    real_cdx_cid = "cdx-real-thread-0001"
    astra_cdx_cid = "cdx-astra-daemon-0002"
    r_real = cdx_dir / f"{real_cdx_cid}.jsonl"
    r_astra = cdx_dir / f"{astra_cdx_cid}.jsonl"
    r_real.write_text("{}", encoding="utf-8")
    r_astra.write_text("{}", encoding="utf-8")

    con_cdx = sqlite3.connect(cdx_dir / "state_5.sqlite")
    con_cdx.execute(
        "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, updated_at INT, source TEXT, cwd TEXT, title TEXT, archived INT)"
    )
    con_cdx.execute(
        "INSERT INTO threads VALUES (?,?,?,?,?,?,?)",
        (real_cdx_cid, str(r_real), 1795626000, "vscode", str(tmp_path), "客观比较两个协作插件", 0),
    )
    con_cdx.execute(
        "INSERT INTO threads VALUES (?,?,?,?,?,?,?)",
        (
            astra_cdx_cid,
            str(r_astra),
            1795626100,
            "exec",
            str(tmp_path),
            "【只读协作顾问约束】你正在作为 GPT-6.2 Astra 独立专家，与 Antigravity 协同工作",
            0,
        ),
    )
    con_cdx.commit()
    con_cdx.close()

    listed = list_local_conversations(limit=50, ide_dir=ide_dir, cli_dir=cli_dir, codex_dir=cdx_dir)
    listed_ids = {x.conversation_id: x for x in listed}
    assert good_ide_cid in listed_ids
    assert listed_ids[good_ide_cid].title == "排查 Antigravity 登录后无法进入"
    det_good = load_conversation_detail(good_ide_cid, store="ide", ide_dir=ide_dir, cli_dir=cli_dir, codex_dir=cdx_dir)
    assert det_good is not None and det_good.title == "排查 Antigravity 登录后无法进入"
    assert ping_ide_cid not in listed_ids
    assert real_cdx_cid in listed_ids
    assert astra_cdx_cid not in listed_ids

    # 4. Gentle Home switch (`open_pc_window=False`) vs explicit New Chat (`open_pc_window=True`)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    opener_calls = 0

    def _spy_opener() -> tuple[bool, str]:
        nonlocal opener_calls
        opener_calls += 1
        return (True, "已在电脑端打开新对话窗口")

    tok = "dual-entry-home-switch-tok"
    cfg = _make_config(tmp_path, web_pwa_port=port, web_access_token=tok)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=ide_dir,
        cli_store_dir=cli_dir,
        codex_store_dir=cdx_dir,
        pc_window_new_opener=_spy_opener,
        pc_window_new_sender=lambda _p: (True, good_ide_cid, "OK"),
    )
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        await asyncio.sleep(0.2)
        # Simulate a stale CLI session_id sitting on the default slot before mobile connects ->
        # `hello` and `conversations_list` MUST NOT leak that stale CLI id or switch `hello.model` to CLI!
        pwa._session_for_slot("default-chat").conversation_id = "stale-bg-cli-9999"
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws:
            hello_ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=4.0))
            assert hello_ev["active_conversation_id"] == ""
            assert hello_ev["active_store"] == "ide"
            assert hello_ev["model"] == "Antigravity 电脑端"
            await ws.send(json.dumps({"type": "list_conversations"}))
            clist_ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=4.0))
            assert clist_ev["type"] == "conversations_list"
            assert clist_ev["active_id"] == ""
            await ws.send(json.dumps({"type": "new_conversation", "workspace": "", "target": "ide", "open_pc_window": False}))
            saw_clear = False
            for _ in range(6):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "meta_update":
                    assert ev["active_store"] == "ide"
                    break
                if ev["type"] == "clear_history":
                    saw_clear = True
            assert saw_clear is True
            assert opener_calls == 0

            await ws.send(json.dumps({"type": "new_conversation", "workspace": "", "target": "ide", "open_pc_window": True}))
            for _ in range(6):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "toast":
                    break
            assert opener_calls == 1
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_live_midturn_steering_ide_pivot_and_cli_fifo_queue(tmp_path: Path) -> None:
    """Verify:
    1. While a PC Antigravity IDE turn (`R1`) is mid-stream, sending a steering message (`U2`)
       injects `U2` into the live PC window WITHOUT cancelling `R1`, keeps `R1`'s pre-steer output
       strictly above `U2`, and pivots to a new assistant bubble below `U2` for `U2`'s reply.
    2. Sending a steering message to an ALREADY-running PC-started IDE session (`db_running=True`)
       injects directly instead of rejecting with '正在运行上一条任务'.
    3. Sending a follow-up message to a mid-stream CLI session queues and auto-executes in FIFO order.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    ide_dir = tmp_path / "ide_steer"
    cid = "steer-ide-conv-12345678"
    tf = ide_dir / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"
    tf.parent.mkdir(parents=True)
    tf.write_text(
        json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "历史首句"}, ensure_ascii=False)
        + "\n"
        + json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "content": "历史首答"}, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    db_path = ide_dir / "conversation_summaries.db"
    con = sqlite3.connect(db_path)
    con.execute(
        "CREATE TABLE conversation_summaries ("
        "conversation_id TEXT, title TEXT, preview TEXT, step_count INT, "
        "last_modified_time TEXT, workspace_uris TEXT, status TEXT, "
        "source TEXT, app_data_dir TEXT, nesting_depth INT, killed INT)"
    )
    con.execute(
        "INSERT INTO conversation_summaries VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (cid, "远程操控开发", "历史首答", 2, "2026-11-26 02:00:00+00:00", "", "CASCADE_RUN_STATUS_IDLE", "", str(ide_dir), 0, 0),
    )
    con.commit()
    con.close()

    sent_to_pc: list[str] = []

    def _sim_pc_sender(target_cid: str, _title: str, prompt: str) -> tuple[bool, str]:
        assert target_cid == cid
        sent_to_pc.append(prompt)
        import threading

        if len(sent_to_pc) == 1:
            def _run_r1() -> None:
                c1 = sqlite3.connect(db_path)
                c1.execute("UPDATE conversation_summaries SET status = 'CASCADE_RUN_STATUS_RUNNING' WHERE conversation_id = ?", (cid,))
                c1.commit()
                c1.close()
                with tf.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps({"step_index": 2, "type": "USER_INPUT", "content": f"<USER_REQUEST>{prompt}</USER_REQUEST>"}, ensure_ascii=False) + "\n")
                    fh.write(json.dumps({"step_index": 3, "type": "PLANNER_RESPONSE", "content": "第一阶段前置输出", "tool_calls": [{"name": "read_file"}]}, ensure_ascii=False) + "\n")
            threading.Thread(target=_run_r1, daemon=True).start()
        elif len(sent_to_pc) == 2:
            def _run_u2_steer() -> None:
                time.sleep(0.08)
                with tf.open("a", encoding="utf-8") as fh:
                    # R1 tail line BEFORE U2 USER_INPUT -> must stay in R1 bubble!
                    fh.write(json.dumps({"step_index": 4, "type": "PLANNER_RESPONSE", "content": "第一阶段前置输出\n\n第一阶段收尾段"}, ensure_ascii=False) + "\n")
                    # Now IDE consumes queued steering U2!
                    fh.write(json.dumps({"step_index": 5, "type": "USER_INPUT", "content": f"<USER_REQUEST>{prompt}</USER_REQUEST>"}, ensure_ascii=False) + "\n")
                    fh.write(json.dumps({"step_index": 6, "type": "PLANNER_RESPONSE", "content": "已结合引导命令完成最终优化！"}, ensure_ascii=False) + "\n")
                time.sleep(0.14)
                c2 = sqlite3.connect(db_path)
                c2.execute("UPDATE conversation_summaries SET status = 'CASCADE_RUN_STATUS_IDLE' WHERE conversation_id = ?", (cid,))
                c2.commit()
                c2.close()
            threading.Thread(target=_run_u2_steer, daemon=True).start()
        return (True, "OK")

    tok = "live-steer-token-2026"
    cfg = _make_config(tmp_path, web_pwa_port=port, web_access_token=tok)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=ide_dir,
        cli_store_dir=tmp_path / "cli_s",
        codex_store_dir=tmp_path / "cdx_s",
        pc_window_sender=_sim_pc_sender,
    )
    pwa.pc_ide_poll_interval = 0.06
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        await asyncio.sleep(0.2)
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws:
            await asyncio.wait_for(ws.recv(), timeout=4.0)  # hello

            # 1. Select PC IDE conversation, start R1, then inject U2 mid-turn WITHOUT stopping!
            await ws.send(json.dumps({"type": "select_conversation", "conversation_id": cid, "store": "ide"}))
            loaded = json.loads(await asyncio.wait_for(ws.recv(), timeout=4.0))
            assert loaded["type"] == "conversation_loaded"

            await ws.send(json.dumps({"type": "chat", "client_id": "u-r1", "text": "开始全面自查"}))
            # Wait until R1 emits its first delta (still `CASCADE_RUN_STATUS_RUNNING`)
            for _ in range(25):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=4.0))
                if ev["type"] == "stream_delta" and "第一阶段前置输出" in ev["delta"]:
                    break

            # Inject mid-turn steering command U2!
            await ws.send(json.dumps({"type": "chat", "client_id": "u-steer-2", "text": "顺便保留底部三个导航模块", "steer": True}))

            ended_items: list[dict] = []
            for _ in range(50):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "stream_end":
                    ended_items.append(ev["item"])
                    if not ev.get("keep_busy"):
                        break

            assert sent_to_pc == ["开始全面自查", "顺便保留底部三个导航模块"]
            assert len(ended_items) == 2
            # R1 tail stays strictly in bubble 1; U2 reply goes strictly into bubble 2!
            assert "第一阶段收尾段" in ended_items[0]["text"]
            assert "已结合引导命令完成最终优化" not in ended_items[0]["text"]
            assert "已结合引导命令完成最终优化！" in ended_items[1]["text"]

            # Verify chronological order in slot history: [..., u-r1, a1, u-steer-2, a2]
            hist_roles_texts = [(m["role"], m["text"]) for m in pwa._slot_history[f"ide:{cid}"][-4:]]
            assert hist_roles_texts[0] == ("user", "开始全面自查")
            assert hist_roles_texts[1][0] == "assistant" and "第一阶段收尾段" in hist_roles_texts[1][1]
            assert hist_roles_texts[2] == ("user", "顺便保留底部三个导航模块")
            assert hist_roles_texts[3][0] == "assistant" and "已结合引导命令完成最终优化！" in hist_roles_texts[3][1]

            # 2. Verify CLI FIFO follow-up queue auto-executes second message after slow turn finishes
            await ws.send(json.dumps({"type": "new_conversation", "workspace": "", "target": "cli"}))
            for _ in range(6):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev["type"] == "meta_update":
                    break

            await ws.send(json.dumps({"type": "chat", "client_id": "cli-1", "text": "慢速首轮 __SLOW_STREAM__"}))
            for _ in range(12):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=4.0))
                if ev["type"] == "stream_start":
                    break

            await ws.send(json.dumps({"type": "chat", "client_id": "cli-2", "text": "自动续跑的第二条引导命令", "steer": True}))
            cli_ends: list[dict] = []
            for _ in range(40):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                if ev["type"] == "stream_end":
                    cli_ends.append(ev["item"])
                    if len(cli_ends) >= 2:
                        break
            assert len(cli_ends) == 2
            assert "自动续跑的第二条引导命令" in cli_ends[1]["text"]
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_nav_seq_prevents_stale_select_overwrite_and_slash_new_preserves_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify Astra red-team P1-8 fixes:
    1. If a slow `select_conversation` starts BEFORE `new_conversation` and finishes disk I/O AFTER,
       `_nav_seq` drops the stale `select_conversation` so `_active_slot` stays on the newer `codex` chat.
    2. `/new` inside a `codex` slot preserves `active_store == 'codex'` instead of wiping to `''`.
    """
    import stayy.web_pwa as web_pwa_mod

    ide_dir = tmp_path / "ide_nav"
    cid = "slow-conv-0001"
    tf = ide_dir / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"
    tf.parent.mkdir(parents=True)
    tf.write_text(
        json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "旧会话内容"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    real_loader = web_pwa_mod.load_conversation_detail

    def _slow_loader(conv_id: str, *args, **kwargs):  # type: ignore[no-untyped-def]
        if conv_id == cid:
            time.sleep(0.28)
        return real_loader(conv_id, *args, **kwargs)

    monkeypatch.setattr(web_pwa_mod, "load_conversation_detail", _slow_loader)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    tok = "nav-seq-guard-token-2026"
    cfg = _make_config(tmp_path, web_pwa_port=port, web_access_token=tok)
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=ide_dir,
        cli_store_dir=tmp_path / "cli_nav",
        codex_store_dir=tmp_path / "cdx_nav",
    )
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        await asyncio.sleep(0.15)
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws:
            await asyncio.wait_for(ws.recv(), timeout=4.0)  # hello

            # Fire slow `select_conversation` immediately followed by fast `new_conversation` (`codex`)
            await ws.send(json.dumps({"type": "select_conversation", "conversation_id": cid, "store": "ide"}))
            await asyncio.sleep(0.03)
            await ws.send(json.dumps({"type": "new_conversation", "workspace": "", "target": "codex"}))

            await asyncio.sleep(0.42)
            saw_stale_loaded = False
            while True:
                try:
                    ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=0.12))
                    if ev.get("type") == "conversation_loaded" and ev.get("conversation_id") == cid:
                        saw_stale_loaded = True
                except asyncio.TimeoutError:
                    break

            assert saw_stale_loaded is False
            assert pwa._active_slot.startswith("new:")
            assert pwa._slot_meta[pwa._active_slot]["store"] == "codex"

            # `/new` inside `codex` slot must preserve `store == 'codex'`
            await ws.send(json.dumps({"type": "chat", "text": "/new"}))
            meta_after_new = None
            for _ in range(10):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                if ev.get("type") == "meta_update":
                    meta_after_new = ev
                    break
            assert meta_after_new is not None
            assert meta_after_new["active_store"] == "codex"
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


@pytest.mark.asyncio
async def test_precision_remote_desktop_loupe_trackpad_hotkey_and_type_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify Phase 2 Precision Remote Desktop upgrades:
    1. `perform_desktop_remote_input` validates whitelisted `hotkey`, `type_text`, `move`, and rejects unsafe combos/lengths.
    2. `capture_desktop_fast_jpeg_sync` writes into `inbox/previews` without pruning user uploads in `inbox/`.
    3. `WebPwaServer` routes `hotkey`, `type_text`, `move`, `right_click`, and `double_click` with 5-arg handler support.
    4. `index.html` ships the Optical Magnifier Loupe (`#deskLoupeCanvas`), Virtual Trackpad (`#deskModeTrackpad`),
       Immersive toggle (`#toggleImmersiveBtn`), and Direct Unicode Input (`#deskTypeBar`).
    """
    from stayy.desktop_tools import (
        capture_desktop_fast_jpeg_sync,
        get_desktop_cursor_ratio,
        perform_desktop_remote_input,
    )
    from stayy.web_pwa import STATIC_DIR

    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    for required_id in (
        'id="deskLoupeCanvas"',
        'id="deskModeLoupe"',
        'id="deskModeTrackpad"',
        'id="deskVCursor"',
        'id="toggleImmersiveBtn"',
        'id="deskTypeBar"',
    ):
        assert required_id in html

    # Security whitelist checks on new actions
    ok_evil_hk, msg_hk = perform_desktop_remote_input("hotkey", key_name="ctrl+alt+del")
    assert ok_evil_hk is False and "白名单" in msg_hk
    ok_empty_txt, _ = perform_desktop_remote_input("type_text", text="")
    assert ok_empty_txt is False
    ok_long_txt, _ = perform_desktop_remote_input("type_text", text="a" * 2005)
    assert ok_long_txt is False

    cur_info = get_desktop_cursor_ratio()
    assert 0.0 <= float(cur_info["x_ratio"]) <= 1.0
    assert 0.0 <= float(cur_info["y_ratio"]) <= 1.0

    # Ensure `capture_desktop_fast_jpeg_sync` isolates preview frames in `previews/` and NEVER deletes user uploads!
    if sys.platform == "win32":
        import stayy.desktop_tools as _dt

        if os.environ.get("RUN_LIVE_DESKTOP_CAPTURE_TEST") != "1":
            def _fake_fast_cap(dest: Path, max_width: int = 1600, quality: int = 80) -> bool:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01" + (b"\xaa" * 600) + b"\xff\xd9")
                return True

            monkeypatch.setattr(_dt, "_capture_desktop_gdiplus_fast", _fake_fast_cap)
            monkeypatch.setattr(
                _dt.subprocess,
                "run",
                lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("unexpected real screen capture")),
            )

        user_upload = tmp_path / "pwa_important_upload.png"
        user_upload.write_bytes(b"\x89PNG\r\n\x1a\n" + b"U" * 64)
        shot_p = capture_desktop_fast_jpeg_sync(tmp_path, max_width=800, quality=72)
        assert shot_p.is_file() and shot_p.stat().st_size > 500
        shot_bytes = shot_p.read_bytes()
        assert shot_bytes.startswith(b"\xff\xd8") and shot_bytes.endswith(b"\xff\xd9")
        assert shot_p.parent.name == "previews"
        assert user_upload.is_file()

    # End-to-end WebSocket routing of `move`, `hotkey`, and `type_text`
    recorded_desk_ops: list[tuple[str, float, float, str, str]] = []

    def _mock_5arg_handler(act: str, xr: float, yr: float, kn: str, txt: str = "") -> tuple[bool, str]:
        recorded_desk_ops.append((act, xr, yr, kn, txt))
        return (True, f"OK:{act}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    tok = "precision-desk-token-2026"
    cfg = _make_config(
        tmp_path,
        web_pwa_port=port,
        web_access_token=tok,
        remote_desktop_enabled=True,
        remote_clipboard_enabled=True,
    )
    sessions = SessionManager(cfg, command_override=[sys.executable, str(MOCK_AGY)])
    pwa = WebPwaServer(
        cfg,
        session_manager=sessions,
        access_token=tok,
        ide_store_dir=tmp_path / "ide_d",
        cli_store_dir=tmp_path / "cli_d",
        codex_store_dir=tmp_path / "cdx_d",
        desktop_input_handler=_mock_5arg_handler,
    )
    stop_event = asyncio.Event()
    pwa_task = asyncio.create_task(pwa.run(stop_event=stop_event))
    try:
        await asyncio.sleep(0.15)
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={tok}") as ws:
            await asyncio.wait_for(ws.recv(), timeout=4.0)  # hello
            await ws.send(json.dumps({"type": "desktop_input", "action": "move", "x_ratio": 0.25, "y_ratio": 0.75, "quiet": True}))
            await ws.send(json.dumps({"type": "desktop_input", "action": "hotkey", "key": "ctrl+c"}))
            await ws.send(json.dumps({"type": "desktop_input", "action": "type_text", "key": "enter", "text": "你好 Antigravity"}))
            saw_type_toast = False
            for _ in range(12):
                ev = json.loads(await asyncio.wait_for(ws.recv(), timeout=4.0))
                if ev.get("type") == "toast" and "OK:type_text" in ev.get("text", ""):
                    saw_type_toast = True
                    break
            assert saw_type_toast is True
            assert ("move", 0.25, 0.75, "", "") in recorded_desk_ops
            assert ("hotkey", 0.5, 0.5, "ctrl+c", "") in recorded_desk_ops
            assert ("type_text", 0.5, 0.5, "enter", "你好 Antigravity") in recorded_desk_ops
    finally:
        stop_event.set()
        await asyncio.wait_for(pwa_task, timeout=5.0)
        await sessions.shutdown_all()


