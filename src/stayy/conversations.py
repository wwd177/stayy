"""Discover, inspect, and load chat histories from ALL local PC coding stores.

Supports:
- PC Antigravity IDE (`~/.gemini/antigravity` — both SQLite summaries AND unindexed `brain/` folders)
- PC OpenAI Codex Desktop (`~/.codex` — `state_*.sqlite` threads + `session_index.jsonl` + rollout JSONLs)
- Remote / Mobile Antigravity CLI (`~/.gemini/antigravity-cli`)

Eliminates cross-store ghost snapshots (CLI DB copying IDE rows or IDE DB mirroring CLI rows),
prevents subagent / prewarm / health-ping clutter, and supports full-history pagination.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

logger = logging.getLogger(__name__)

SAFE_CONV_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,80}$")
USER_REQ_RE = re.compile(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", re.DOTALL)
CTX_SUMMARY_RE = re.compile(r"<CONTEXT_SUMMARY>.*?</CONTEXT_SUMMARY>\s*", re.DOTALL)
SYS_BLOCK_RE = re.compile(r"\[系统设定[^\]]*\].*?\[/系统设定\]\s*", re.DOTALL)
HANDOFF_BLOCK_RE = re.compile(r"\[承接电脑端对话上下文\].*?\[/承接电脑端对话上下文\]\s*", re.DOTALL)

CODEX_PLUGIN_LINK_RE = re.compile(r"\[(@[^\]]+)\]\(plugin://[^)]+\)")
CODEX_FILE_LINE_RE = re.compile(r"^##\s+[^:\n]+:\s*([A-Za-z]:[\\/][^\r\n]+)$", re.MULTILINE)
CODEX_VIEW_IMG_RE = re.compile(r'view_image\s*\(\s*\{\s*path\s*:\s*["\']([^"\']+)["\']')
SAVED_PATH_RE = re.compile(
    r"(?:Saved screenshot to|saved_path|save_path)\s*[:=]\s*[\"']?([A-Za-z]:[\\/][^\r\n\"'<>|]+?\.(?:png|jpg|jpeg|webp|gif|bmp))",
    re.IGNORECASE,
)
MD_LOCAL_IMG_RE = re.compile(
    r"!\[[^\]]*\]\(\s*<?((?:file:///)?[A-Za-z]:[\\/][^)\r\n>]+?\.(?:png|jpg|jpeg|webp|gif|bmp)|/dl/[a-f0-9]+)>?\s*\)",
    re.IGNORECASE,
)
CODEX_HEARTBEAT_RE = re.compile(
    r"<heartbeat>\s*.*?<decision>\s*([A-Z_]+)\s*</decision>\s*(?:<message>(.*?)</message>)?\s*</heartbeat>",
    re.DOTALL,
)

PREWARM_PROMPT_MARKER = "连接预热完成，只需回复两个字"
SYNTHETIC_PING_PROMPTS = (
    "连接预热完成",
    "请只回复：连接正常",
    "请只回复：antigravity已就绪",
    "只回复ok两个字母",
    "reply with exactly ok",
    "就回两个字：收到",
    "只回复两个字",
    "【只读协作顾问约束】",
    "【反拍马屁红队审查模式】",
)
UNCLOSED_SYS_PREFIX_RE = re.compile(r"^\s*\[(?:系统设定\s*[-—:]|承接电脑端对话上下文\])[\s\S]*$")


def _default_ide_dir() -> Path:
    return Path.home() / ".gemini" / "antigravity"


def _default_cli_dir() -> Path:
    return Path.home() / ".gemini" / "antigravity-cli"


def _default_codex_dir() -> Path:
    return Path.home() / ".codex"


def _parse_iso_to_ms(raw: str) -> int:
    s = (raw or "").strip()
    if not s or s.startswith("0001-01-01"):
        return 0
    try:
        norm = s.replace(" ", "T")
        if norm.endswith("Z"):
            norm = norm[:-1] + "+00:00"
        dt = datetime.fromisoformat(norm)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except Exception:
        return 0


def _epoch_to_ms(val: Any) -> int:
    try:
        n = int(float(val or 0))
    except (TypeError, ValueError):
        return 0
    if n <= 0:
        return 0
    return n * 1000 if n < 10_000_000_000 else n


def _format_relative_time(ts_ms: int) -> str:
    if ts_ms <= 0:
        return ""
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    diff_sec = max(0, (now_ms - ts_ms) // 1000)
    if diff_sec < 60:
        return "刚刚"
    if diff_sec < 3600:
        return f"{diff_sec // 60} 分钟前"
    dt_local = datetime.fromtimestamp(ts_ms / 1000.0).astimezone()
    now_local = datetime.now().astimezone()
    if dt_local.date() == now_local.date():
        return dt_local.strftime("今天 %H:%M")
    if dt_local.year == now_local.year:
        return dt_local.strftime("%m-%d %H:%M")
    return dt_local.strftime("%Y-%m-%d")


def _safe_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _clean_win_path(raw: str) -> str:
    s = (raw or "").strip()
    if s.startswith("\\\\?\\"):
        s = s[4:]
    return s


def _uri_to_local_path(uri_or_path: str) -> Path:
    s = _clean_win_path(uri_or_path)
    if s.startswith("file://"):
        p = unquote(urlparse(s).path)
        if len(p) >= 3 and p[0] == "/" and p[2] == ":":
            p = p[1:]
        return Path(p)
    return Path(s)


def _parse_workspace_uris(raw_uris: str) -> str:
    s = (raw_uris or "").strip()
    if not s:
        return ""
    try:
        arr = json.loads(s) if s.startswith("[") else [s]
        for item in arr:
            if not isinstance(item, str) or not item:
                continue
            if item.startswith("file://"):
                return str(_uri_to_local_path(item))
            return _clean_win_path(item)
    except Exception:
        pass
    return ""


def clean_user_input_text(raw_content: str) -> str:
    """Extract clean human prompt from Antigravity transcript USER_INPUT content."""
    text = CTX_SUMMARY_RE.sub("", raw_content or "")
    m = USER_REQ_RE.search(text)
    if m:
        text = m.group(1)
    else:
        idx = text.find("<ADDITIONAL_METADATA>")
        if idx >= 0:
            text = text[:idx]
    text = SYS_BLOCK_RE.sub("", text)
    text = HANDOFF_BLOCK_RE.sub("", text)
    return text.strip()


def _clean_display_title(raw_text: str, max_len: int = 60) -> str:
    """Sanitize truncated DB titles/previews so unclosed `[系统设定 - ...` blocks never leak into UI."""
    cleaned = clean_user_input_text(raw_text or "")
    cleaned = UNCLOSED_SYS_PREFIX_RE.sub("", cleaned)
    cleaned = cleaned.replace("<USER_REQUEST>", "").replace("</USER_REQUEST>", "").strip()
    if not cleaned:
        return ""
    first_ln = next((ln.strip() for ln in cleaned.splitlines() if ln.strip()), "")
    first_ln = re.sub(r"\s+", " ", first_ln).strip()
    return first_ln[:max_len]


def _is_synthetic_ping(prompt: str) -> bool:
    low = (prompt or "").strip().lower()
    if not low:
        return False
    return any(marker in low for marker in SYNTHETIC_PING_PROMPTS)


def clean_codex_user_text(raw_text: str) -> tuple[str, list[Path]]:
    """Clean Codex user message wrapper blocks while preserving attached local image paths."""
    s = (raw_text or "").strip()
    if not s:
        return ("", [])

    # Ignore injected system / environment prompt envelopes
    if s.startswith(
        (
            "# AGENTS.md instructions",
            "<environment_context>",
            "<permissions instructions>",
            "<collaboration_mode>",
            "<skills_instructions>",
            "<subagent_notification>",
        )
    ):
        return ("", [])

    images: list[Path] = []
    if "# Files mentioned by the user:" in s:
        for m in CODEX_FILE_LINE_RE.finditer(s):
            cand = Path(_clean_win_path(m.group(1).strip()))
            if cand.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"} and cand.is_file():
                images.append(cand)
        req_marker = "## My request:"
        if req_marker in s:
            s = s.split(req_marker, 1)[1].strip()

    if s.startswith("<send_user_message_question_reply>"):
        inner = (
            s.removeprefix("<send_user_message_question_reply>")
            .removesuffix("</send_user_message_question_reply>")
            .strip()
        )
        try:
            arr = json.loads(inner)
            if isinstance(arr, list):
                parts = []
                for q in arr:
                    if isinstance(q, dict):
                        ans = q.get("answer") or q.get("selectedOptions") or q.get("response") or ""
                        if isinstance(ans, list):
                            ans = " / ".join(str(x) for x in ans)
                        if ans:
                            parts.append(f"选择：{ans}")
                if parts:
                    return ("\n".join(parts), images)
        except Exception:
            pass

    s = CODEX_PLUGIN_LINK_RE.sub(r"\1", s)
    return (s.strip(), images)


def _summarize_codex_title(raw_title: str) -> str:
    cleaned, _ = clean_codex_user_text(raw_title)
    if not cleaned:
        cleaned = (raw_title or "").strip()
    if "多 Agent 协作群「" in cleaned:
        m_grp = re.search(r"多 Agent 协作群「([^」]+)」", cleaned)
        grp = m_grp.group(1) if m_grp else "多智能体群聊"
        return f"群聊协作 · {grp}"
    if "【用户消息】" in cleaned:
        cleaned = cleaned.split("【用户消息】", 1)[1].strip()
    first_ln = next((ln.strip() for ln in cleaned.splitlines() if ln.strip()), "")
    return first_ln[:54]


@dataclass
class ConversationItem:
    conversation_id: str
    title: str
    preview: str
    store: str  # "ide", "codex", or "cli"
    source_label: str  # "Antigravity 电脑端", "Codex 电脑端", "手机 / 远程"
    step_count: int
    updated_ms: int
    updated_human: str
    workspace: str
    running: bool = False
    archived: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "title": self.title,
            "preview": self.preview,
            "store": self.store,
            "source_label": self.source_label,
            "step_count": self.step_count,
            "updated_ms": self.updated_ms,
            "updated_human": self.updated_human,
            "workspace": self.workspace,
            "running": self.running,
            "archived": self.archived,
        }


@dataclass
class ChatMessage:
    role: str  # "user" or "assistant"
    text: str
    step_index: int = 0
    ts_ms: int = 0
    image_paths: list[Path] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)


def _humanize_tool_step(tool_name: str, raw_args: Any = None) -> str:
    """Format a raw IDE/Codex tool call into a concise, safe ChatGPT-style step label."""
    tname = (tool_name or "").strip()
    if not tname:
        return ""
    args_dict: dict[str, Any] = {}
    if isinstance(raw_args, dict):
        args_dict = raw_args
    elif isinstance(raw_args, str) and raw_args.strip().startswith("{"):
        try:
            parsed = json.loads(raw_args)
            if isinstance(parsed, dict):
                args_dict = parsed
        except Exception:
            pass

    if tname == "update_focus" and args_dict.get("focus"):
        return str(args_dict["focus"]).strip()[:56]
    if tname == "update_steps":
        return ""

    summary = str(args_dict.get("toolSummary") or args_dict.get("Description") or "").strip()
    target_path = str(args_dict.get("Path") or args_dict.get("TargetFile") or "").strip()
    base_name = Path(target_path.replace("\\", "/")).name if target_path else ""

    low = tname.lower()
    if "read_file" in low or low == "view_file":
        return f"读取 {base_name}" if base_name else "查阅源码文件"
    if "edit_file" in low or "replace_file" in low or "apply_patch" in low:
        return f"修改 {base_name}" if base_name else "修改源码"
    if "write_file" in low:
        return f"写入 {base_name}" if base_name else "创建文件"
    if "search_web" in low or "web_search" in low:
        q = str(args_dict.get("query") or "").strip()[:32]
        return f"检索网页：{q}" if q else "联网检索资料"
    if "grep" in low or "find_by_name" in low:
        return "搜索代码库定位符号"
    if "codex-astra" in low:
        return f"Astra 协同：{summary[:36]}" if summary else "调用 Astra 双核审查"
    if "windows-mcp" in low:
        return f"桌面操作：{summary[:36]}" if summary else "执行桌面视觉操作"
    if "command" in low or "shell" in low or low == "exec_command":
        return f"终端：{summary[:40]}" if summary else "执行终端命令"
    if summary:
        return summary[:48]
    return f"调用 {tname[:36]}"


@dataclass
class ConversationDetail:
    conversation_id: str
    title: str
    store: str  # "ide", "codex", or "cli"
    workspace: str
    running: bool
    messages: list[ChatMessage] = field(default_factory=list)
    total_messages: int = 0
    has_more: bool = False


def _peek_transcript_summary(brain_dir: Path, conv_id: str) -> tuple[str, str, int, bool]:
    """Return (title_from_first_prompt, workspace_guess, user_turn_count, is_synthetic_only)."""
    tfile = brain_dir / conv_id / ".system_generated" / "logs" / "transcript.jsonl"
    if not tfile.is_file():
        return ("", "", 0, False)

    first_prompt = ""
    user_turns = 0
    saw_synthetic = False
    ws_guess = ""

    try:
        with tfile.open("r", encoding="utf-8", errors="replace") as fh:
            for idx in range(80):
                line = fh.readline()
                if not line:
                    break
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("type") != "USER_INPUT":
                    if not ws_guess and idx < 25:
                        m_ws = re.search(r"([A-Za-z]:[\\/][^\s\"'`<>|]{3,80})", str(obj.get("content") or ""))
                        if m_ws:
                            cand = Path(m_ws.group(1))
                            if cand.is_dir():
                                ws_guess = str(cand)
                    continue
                cleaned = clean_user_input_text(str(obj.get("content") or ""))
                if not cleaned:
                    continue
                if PREWARM_PROMPT_MARKER in cleaned or _is_synthetic_ping(cleaned):
                    saw_synthetic = True
                    continue
                user_turns += 1
                if not first_prompt:
                    if "多 Agent 协作群「" in cleaned:
                        m_g = re.search(r"多 Agent 协作群「([^」]+)」", cleaned)
                        first_prompt = f"群聊协作 · {m_g.group(1)}" if m_g else "多智能体协作会话"
                    else:
                        first_prompt = next(
                            (ln.strip() for ln in cleaned.splitlines() if ln.strip()), cleaned
                        )[:54]
                if user_turns >= 2:
                    break
    except OSError:
        pass

    return (first_prompt, ws_guess, user_turns, saw_synthetic and user_turns == 0)


def _table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {str(r[1]) for r in con.execute(f"PRAGMA table_info({table})").fetchall()}
    except Exception:
        return set()


def _query_antigravity_store(
    base_dir: Path,
    other_dir: Path,
    store_key: str,
    source_label: str,
    limit: int,
) -> list[ConversationItem]:
    """Read genuine conversations belonging to `base_dir` (`ide` or `cli`), plus unindexed `brain/` folders."""
    db_path = base_dir / "conversation_summaries.db"
    brain_dir = base_dir / "brain"
    other_brain = other_dir / "brain"

    items_by_id: dict[str, ConversationItem] = {}
    excluded_subagent_or_killed: set[str] = set()

    if db_path.is_file():
        try:
            con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2.0)
            try:
                cols = _table_columns(con, "conversation_summaries")
                sel_source = "source" if "source" in cols else "''"
                sel_appdir = "app_data_dir" if "app_data_dir" in cols else "''"

                # Collect subagent and killed conversation IDs so brain-folder scan never surfaces internal subagents
                for (bad_id,) in con.execute(
                    "SELECT conversation_id FROM conversation_summaries WHERE nesting_depth > 0 OR killed != 0"
                ).fetchall():
                    if bad_id:
                        excluded_subagent_or_killed.add(str(bad_id).strip())

                tables = {
                    str(r[0])
                    for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                }
                if "conversation_parents" in tables:
                    for (child_id,) in con.execute("SELECT conversation_id FROM conversation_parents").fetchall():
                        if child_id:
                            excluded_subagent_or_killed.add(str(child_id).strip())

                rows = con.execute(
                    f"SELECT conversation_id, title, preview, step_count, last_modified_time, "
                    f"workspace_uris, status, {sel_source}, {sel_appdir} "
                    f"FROM conversation_summaries "
                    f"WHERE nesting_depth = 0 AND killed = 0 "
                    f"ORDER BY last_modified_time DESC LIMIT ?",
                    (max(limit * 3, 600),),
                ).fetchall()
            finally:
                con.close()

            for cid, title, preview, steps, mod_time, ws_uris, status, row_src, row_appdir in rows:
                cid_str = str(cid or "").strip()
                if not SAFE_CONV_ID_RE.match(cid_str) or cid_str in excluded_subagent_or_killed:
                    continue

                src_str = str(row_src or "").strip()
                appdir_name = Path(str(row_appdir or "")).name.lower() if row_appdir else ""
                own_tf = brain_dir / cid_str / ".system_generated" / "logs" / "transcript.jsonl"
                other_tf = other_brain / cid_str / ".system_generated" / "logs" / "transcript.jsonl"

                # Cross-store ghost filtering:
                # 1. IDE DB mirrors CLI runs with source='CORTEX_TRAJECTORY_SOURCE_CLI'
                if store_key == "ide":
                    if src_str == "CORTEX_TRAJECTORY_SOURCE_CLI":
                        continue
                    if appdir_name == "antigravity-cli" and not own_tf.is_file():
                        continue
                    if not own_tf.is_file() and other_tf.is_file():
                        continue
                # 2. CLI DB holds stale snapshots of PC IDE conversations (app_data_dir='antigravity')
                elif store_key == "cli":
                    if appdir_name == "antigravity" and not own_tf.is_file():
                        continue
                    if not own_tf.is_file() and other_tf.is_file():
                        continue

                step_cnt = int(steps or 0)
                raw_title_str = str(title or "").strip()
                raw_preview_str = str(preview or "").strip()
                clean_title = _clean_display_title(raw_title_str, 60)
                clean_preview = _clean_display_title(raw_preview_str, 90)

                first_prompt, ws_guess, user_turns, synthetic_only = _peek_transcript_summary(brain_dir, cid_str)
                if synthetic_only:
                    continue
                if user_turns == 0 and step_cnt <= 6 and _is_synthetic_ping(clean_title or raw_title_str):
                    continue

                if not clean_title:
                    clean_title = _clean_display_title(first_prompt, 60) or f"对话 {cid_str[:8]}"
                if not clean_preview:
                    clean_preview = _clean_display_title(first_prompt, 90) or clean_title

                ts_ms = _parse_iso_to_ms(str(mod_time or ""))
                if own_tf.is_file():
                    tf_ms = int(_safe_mtime(own_tf) * 1000)
                    if tf_ms > ts_ms:
                        ts_ms = tf_ms

                ws_path = _parse_workspace_uris(str(ws_uris or "")) or ws_guess
                is_running = "RUNNING" in str(status or "").upper()
                items_by_id[cid_str] = ConversationItem(
                    conversation_id=cid_str,
                    title=clean_title,
                    preview=clean_preview[:90],
                    store=store_key,
                    source_label=source_label,
                    step_count=step_cnt,
                    updated_ms=ts_ms,
                    updated_human=_format_relative_time(ts_ms),
                    workspace=ws_path,
                    running=is_running,
                )
        except Exception as exc:
            logger.warning("Failed reading %s summaries db: %s", store_key, exc)

    # Always supplement with unindexed top-level `brain/<id>` directories (never skip just because DB exists!)
    if brain_dir.is_dir():
        dirs = sorted(
            (
                d
                for d in brain_dir.iterdir()
                if d.is_dir()
                and d.name != "tempmediaStorage"
                and SAFE_CONV_ID_RE.match(d.name)
                and d.name not in items_by_id
                and d.name not in excluded_subagent_or_killed
            ),
            key=_safe_mtime,
            reverse=True,
        )
        for d in dirs[: max(limit, 200)]:
            tf = d / ".system_generated" / "logs" / "transcript.jsonl"
            if not tf.is_file():
                continue
            first_prompt, ws_guess, user_turns, synthetic_only = _peek_transcript_summary(brain_dir, d.name)
            if synthetic_only or user_turns == 0:
                continue
            ts_ms = int(_safe_mtime(tf) * 1000)
            items_by_id[d.name] = ConversationItem(
                conversation_id=d.name,
                title=first_prompt or f"对话 {d.name[:8]}",
                preview=first_prompt or "",
                store=store_key,
                source_label=source_label,
                step_count=user_turns * 2,
                updated_ms=ts_ms,
                updated_human=_format_relative_time(ts_ms),
                workspace=ws_guess,
                running=False,
            )

    ordered = sorted(items_by_id.values(), key=lambda x: x.updated_ms, reverse=True)
    return ordered[:limit]


def _find_codex_state_db(codex_dir: Path) -> Path | None:
    if not codex_dir.is_dir():
        return None
    candidates = sorted(codex_dir.glob("state_*.sqlite"), key=_safe_mtime, reverse=True)
    return candidates[0] if candidates else None


def _load_codex_index_titles(codex_dir: Path) -> dict[str, str]:
    idx_file = codex_dir / "session_index.jsonl"
    titles: dict[str, str] = {}
    if not idx_file.is_file():
        return titles
    try:
        with idx_file.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                tid = str(obj.get("id") or "").strip()
                tname = str(obj.get("thread_name") or "").strip()
                if tid and tname:
                    titles[tid] = tname
    except OSError:
        pass
    return titles


def _query_codex_store(codex_dir: Path, limit: int) -> list[ConversationItem]:
    """Discover all top-level PC OpenAI Codex Desktop chats (`vscode` & `exec`, active + archived)."""
    state_db = _find_codex_state_db(codex_dir)
    if state_db is None:
        return []

    index_titles = _load_codex_index_titles(codex_dir)
    items: list[ConversationItem] = []

    try:
        con = sqlite3.connect(f"file:{state_db}?mode=ro", uri=True, timeout=2.0)
        try:
            rows = con.execute(
                "SELECT id, rollout_path, updated_at, source, cwd, title, archived "
                "FROM threads "
                "WHERE source NOT LIKE '{\"subagent\"%' "
                "ORDER BY updated_at DESC LIMIT ?",
                (max(limit * 2, 400),),
            ).fetchall()
        finally:
            con.close()

        for tid, rollout_raw, updated_at, source, cwd, raw_title, archived in rows:
            cid = str(tid or "").strip()
            if not SAFE_CONV_ID_RE.match(cid):
                continue
            rpath = Path(_clean_win_path(str(rollout_raw or "")))
            if not rpath.is_file():
                continue

            idx_title = index_titles.get(cid, "").strip()
            raw_title_str = str(raw_title or "").strip()
            human_title = idx_title or ("" if _is_synthetic_ping(raw_title_str) else _summarize_codex_title(raw_title_str))
            if not human_title or _is_synthetic_ping(human_title):
                # Inspect rollout JSONL user turns so daemon-only threads are skipped while multi-turn human follow-ups survive
                real_user_title = ""
                saw_daemon_prompt = _is_synthetic_ping(raw_title_str)
                try:
                    with rpath.open("r", encoding="utf-8", errors="replace") as rfh:
                        for _ in range(50):
                            rln = rfh.readline()
                            if not rln:
                                break
                            robj = json.loads(rln)
                            if robj.get("type") == "response_item":
                                rpl = robj.get("payload") or {}
                                if rpl.get("type") == "message" and rpl.get("role") == "user":
                                    rtxt = "\n".join(str(c.get("text") or "") for c in (rpl.get("content") or []) if isinstance(c, dict))
                                    if _is_synthetic_ping(rtxt):
                                        saw_daemon_prompt = True
                                        continue
                                    cu, _ = clean_codex_user_text(rtxt)
                                    if cu and not _is_synthetic_ping(cu):
                                        real_user_title = _summarize_codex_title(cu)
                                        break
                except Exception:
                    pass
                if real_user_title:
                    human_title = idx_title if (idx_title and not _is_synthetic_ping(idx_title)) else real_user_title
                elif saw_daemon_prompt:
                    continue
            if not human_title:
                human_title = f"Codex 对话 {cid[:8]}"
            preview = _summarize_codex_title(str(raw_title or "")) or human_title
            ts_ms = max(_epoch_to_ms(updated_at), int(_safe_mtime(rpath) * 1000))
            ws_clean = _clean_win_path(str(cwd or ""))

            items.append(
                ConversationItem(
                    conversation_id=cid,
                    title=human_title,
                    preview=preview[:90],
                    store="codex",
                    source_label="Codex 电脑端",
                    step_count=0,
                    updated_ms=ts_ms,
                    updated_human=_format_relative_time(ts_ms),
                    workspace=ws_clean,
                    running=False,
                    archived=bool(archived),
                )
            )
            if len(items) >= limit:
                break
    except Exception as exc:
        logger.warning("Failed reading Codex threads db: %s", exc)

    return items


def list_local_conversations(
    limit: int = 500,
    ide_dir: Path | None = None,
    cli_dir: Path | None = None,
    codex_dir: Path | None = None,
) -> list[ConversationItem]:
    """Return merged, recency-sorted conversations across PC Antigravity IDE, PC Codex Desktop, and Remote CLI."""
    ide_root = ide_dir if ide_dir is not None else _default_ide_dir()
    cli_root = cli_dir if cli_dir is not None else _default_cli_dir()
    # When custom test directories are passed without codex_dir, isolate from real ~/.codex
    if codex_dir is not None:
        codex_root: Path | None = codex_dir
    elif ide_dir is None and cli_dir is None:
        codex_root = _default_codex_dir()
    else:
        codex_root = None

    merged: dict[str, ConversationItem] = {}

    for it in _query_antigravity_store(ide_root, cli_root, "ide", "Antigravity 电脑端", limit):
        merged[it.conversation_id] = it

    for it in _query_antigravity_store(cli_root, ide_root, "cli", "手机 / 远程", limit):
        existing = merged.get(it.conversation_id)
        if existing is None or it.updated_ms > existing.updated_ms:
            merged[it.conversation_id] = it

    if codex_root is not None:
        for it in _query_codex_store(codex_root, limit):
            merged[f"codex:{it.conversation_id}" if it.conversation_id in merged else it.conversation_id] = it

    ordered = sorted(merged.values(), key=lambda x: x.updated_ms, reverse=True)
    return ordered[:limit]


def _resolve_codex_rollout(codex_root: Path, cid: str) -> tuple[Path | None, str, str]:
    """Return (rollout_path, title, workspace) for a Codex thread ID."""
    index_titles = _load_codex_index_titles(codex_root)
    state_db = _find_codex_state_db(codex_root)
    if state_db is not None:
        try:
            con = sqlite3.connect(f"file:{state_db}?mode=ro", uri=True, timeout=2.0)
            row = con.execute(
                "SELECT rollout_path, title, cwd FROM threads WHERE id = ?",
                (cid,),
            ).fetchone()
            con.close()
            if row:
                rp = Path(_clean_win_path(str(row[0] or "")))
                t = index_titles.get(cid) or _summarize_codex_title(str(row[1] or ""))
                ws = _clean_win_path(str(row[2] or ""))
                if rp.is_file():
                    return (rp, t, ws)
        except Exception:
            pass

    for sub in ("sessions", "archived_sessions"):
        sdir = codex_root / sub
        if sdir.is_dir():
            matches = list(sdir.rglob(f"*{cid}.jsonl"))
            if matches:
                return (matches[0], index_titles.get(cid, ""), "")
    return (None, "", "")


def _load_codex_detail(
    cid: str,
    codex_root: Path,
    max_messages: int,
) -> ConversationDetail | None:
    rpath, title, workspace = _resolve_codex_rollout(codex_root, cid)
    if rpath is None or not rpath.is_file():
        return None

    parsed_msgs: list[ChatMessage] = []
    pending_commentary: list[str] = []
    pending_commentary_ts: int = 0
    pending_tool_imgs: list[Path] = []
    pending_steps: list[str] = []
    step_counter = 0

    def _add_step(label: str) -> None:
        s = (label or "").strip()
        if s and s not in pending_steps and len(pending_steps) < 16:
            pending_steps.append(s)

    def _add_unique_img(lst: list[Path], cand: Path) -> None:
        try:
            rp = cand.resolve()
            if rp.is_file() and rp not in lst:
                lst.append(rp)
        except OSError:
            pass

    def _extract_md_imgs(text: str) -> list[Path]:
        found: list[Path] = []
        for m in MD_LOCAL_IMG_RE.finditer(text or ""):
            raw_u = m.group(1).strip()
            if raw_u.startswith("/dl/"):
                continue
            _add_unique_img(found, _uri_to_local_path(raw_u))
        return found

    def _flush_commentary_if_needed() -> None:
        nonlocal pending_commentary, pending_commentary_ts, pending_tool_imgs, pending_steps, step_counter
        if pending_commentary or pending_tool_imgs:
            step_counter += 1
            txt = "\n\n".join(pending_commentary)
            imgs = list(pending_tool_imgs[-4:])
            for im in _extract_md_imgs(txt):
                _add_unique_img(imgs, im)
            parsed_msgs.append(
                ChatMessage(
                    role="assistant",
                    text=txt,
                    step_index=step_counter,
                    ts_ms=pending_commentary_ts,
                    image_paths=imgs,
                    steps=list(pending_steps),
                )
            )
            pending_commentary = []
            pending_commentary_ts = 0
            pending_tool_imgs = []
            pending_steps = []

    try:
        with rpath.open("r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    obj = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue

                otype = obj.get("type")
                ts_ms = _parse_iso_to_ms(str(obj.get("timestamp") or ""))

                if otype in {"session_meta", "turn_context"} and not workspace:
                    pl = obj.get("payload") or {}
                    if isinstance(pl, dict) and pl.get("cwd"):
                        workspace = _clean_win_path(str(pl["cwd"]))
                    continue

                if otype != "response_item":
                    continue
                pl = obj.get("payload") or {}
                if not isinstance(pl, dict):
                    continue

                ptype = pl.get("type")
                if ptype in {"custom_tool_call", "function_call"}:
                    raw_in = str(pl.get("input") or pl.get("arguments") or "")
                    _add_step(_humanize_tool_step(str(pl.get("name") or ptype), raw_in))
                    for vm in CODEX_VIEW_IMG_RE.finditer(raw_in):
                        _add_unique_img(pending_tool_imgs, _uri_to_local_path(vm.group(1)))
                    continue

                if ptype != "message":
                    continue

                role = pl.get("role")
                if role not in {"user", "assistant"}:
                    continue

                raw_parts: list[str] = []
                for c in pl.get("content") or []:
                    if isinstance(c, dict) and c.get("text"):
                        raw_parts.append(str(c["text"]))
                joined = "\n".join(raw_parts).strip()

                if role == "user":
                    clean_u, imgs = clean_codex_user_text(joined)
                    if not clean_u and not imgs:
                        continue
                    _flush_commentary_if_needed()
                    step_counter += 1
                    if not title:
                        title = _summarize_codex_title(clean_u)
                    parsed_msgs.append(
                        ChatMessage(
                            role="user",
                            text=clean_u,
                            step_index=step_counter,
                            ts_ms=ts_ms,
                            image_paths=imgs,
                        )
                    )
                else:
                    # Handle <heartbeat> automation envelopes cleanly
                    hb = CODEX_HEARTBEAT_RE.search(joined)
                    if hb:
                        if hb.group(1) == "DONT_NOTIFY":
                            continue
                        joined = (hb.group(2) or "").strip()
                    if not joined:
                        continue

                    phase = str(pl.get("phase") or "")
                    if phase == "commentary":
                        first_ln = next((ln.strip() for ln in joined.splitlines() if ln.strip()), "")
                        if first_ln:
                            _add_step(first_ln[:64])
                        if joined not in pending_commentary:
                            pending_commentary.append(joined)
                            pending_commentary_ts = ts_ms or pending_commentary_ts
                    else:
                        # Final answer supersedes intermediate commentary for this turn (preserved in `steps`)
                        pending_commentary = []
                        pending_commentary_ts = 0
                        md_imgs = _extract_md_imgs(joined)
                        turn_imgs = list(md_imgs) if md_imgs else list(pending_tool_imgs[-4:])
                        turn_steps = list(pending_steps)
                        pending_tool_imgs = []
                        pending_steps = []
                        step_counter += 1
                        if parsed_msgs and parsed_msgs[-1].role == "assistant":
                            prev = parsed_msgs[-1]
                            if joined != prev.text:
                                prev.text = f"{prev.text}\n\n{joined}".strip()
                            for im in turn_imgs:
                                _add_unique_img(prev.image_paths, im)
                            for st_lbl in turn_steps:
                                if st_lbl not in prev.steps and len(prev.steps) < 16:
                                    prev.steps.append(st_lbl)
                            if ts_ms > prev.ts_ms:
                                prev.ts_ms = ts_ms
                        else:
                            parsed_msgs.append(
                                ChatMessage(
                                    role="assistant",
                                    text=joined,
                                    step_index=step_counter,
                                    ts_ms=ts_ms,
                                    image_paths=turn_imgs,
                                    steps=turn_steps,
                                )
                            )

        _flush_commentary_if_needed()
    except OSError as exc:
        logger.warning("Failed reading Codex rollout %s: %s", rpath, exc)
        return None

    total = len(parsed_msgs)
    sliced = parsed_msgs[-max_messages:] if max_messages > 0 else parsed_msgs
    return ConversationDetail(
        conversation_id=cid,
        title=title or f"Codex 对话 {cid[:8]}",
        store="codex",
        workspace=workspace,
        running=False,
        messages=sliced,
        total_messages=total,
        has_more=total > len(sliced),
    )


def load_conversation_detail(
    conversation_id: str,
    store: str = "auto",
    max_messages: int = 200,
    ide_dir: Path | None = None,
    cli_dir: Path | None = None,
    codex_dir: Path | None = None,
) -> ConversationDetail | None:
    """Load clean human-readable chat history (user + assistant turns & images) for any local store."""
    cid = (conversation_id or "").strip().removeprefix("codex:")
    if not SAFE_CONV_ID_RE.match(cid):
        return None

    ide_root = ide_dir if ide_dir is not None else _default_ide_dir()
    cli_root = cli_dir if cli_dir is not None else _default_cli_dir()
    codex_root = codex_dir if codex_dir is not None else _default_codex_dir()

    if store == "codex":
        return _load_codex_detail(cid, codex_root, max_messages)

    # Check both stores with preference matching requested `store`, ALWAYS falling back to the other store
    # so cross-store IDs never return empty!
    if store == "cli":
        candidates: list[tuple[str, Path]] = [("cli", cli_root), ("ide", ide_root)]
    elif store == "ide":
        candidates = [("ide", ide_root), ("cli", cli_root)]
    else:
        candidates = [("ide", ide_root), ("cli", cli_root)]

    chosen_store = ""
    chosen_base: Path | None = None
    tfile: Path | None = None
    for sk, base in candidates:
        tf = base / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"
        if tf.is_file():
            chosen_store = sk
            chosen_base = base
            tfile = tf
            break

    if chosen_base is None and store == "auto":
        codex_det = _load_codex_detail(cid, codex_root, max_messages)
        if codex_det is not None:
            return codex_det

    if chosen_base is None:
        for sk, base in candidates:
            db = base / "conversation_summaries.db"
            if db.is_file():
                try:
                    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2.0)
                    row = con.execute(
                        "SELECT title, workspace_uris, status FROM conversation_summaries WHERE conversation_id = ?",
                        (cid,),
                    ).fetchone()
                    con.close()
                    if row:
                        return ConversationDetail(
                            conversation_id=cid,
                            title=_clean_display_title(str(row[0] or ""), 60) or f"对话 {cid[:8]}",
                            store=sk,
                            workspace=_parse_workspace_uris(str(row[1] or "")),
                            running="RUNNING" in str(row[2] or "").upper(),
                            messages=[],
                            total_messages=0,
                            has_more=False,
                        )
                except Exception:
                    pass
        return None

    title = ""
    workspace = ""
    running = False
    db_path = chosen_base / "conversation_summaries.db"
    if db_path.is_file():
        try:
            con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2.0)
            row = con.execute(
                "SELECT title, workspace_uris, status FROM conversation_summaries WHERE conversation_id = ?",
                (cid,),
            ).fetchone()
            con.close()
            if row:
                title = _clean_display_title(str(row[0] or ""), 60)
                workspace = _parse_workspace_uris(str(row[1] or ""))
                running = "RUNNING" in str(row[2] or "").upper()
        except Exception:
            pass

    assert tfile is not None
    full_tfile = tfile.with_name("transcript_full.jsonl")
    raw_entries: list[tuple[int, dict[str, Any]]] = []
    truncated_line_nums: set[int] = set()

    try:
        with tfile.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, raw_line in enumerate(fh):
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    obj = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                etype = obj.get("type")
                has_media = bool(obj.get("media"))
                has_saved_shot = etype == "GENERIC" and "Saved screenshot" in str(obj.get("content") or "")
                if etype not in {"USER_INPUT", "PLANNER_RESPONSE"} and not has_media and not has_saved_shot:
                    continue
                raw_entries.append((line_no, obj))
                trunc = obj.get("truncated_fields") or []
                if isinstance(trunc, list) and "content" in trunc and etype in {"USER_INPUT", "PLANNER_RESPONSE"}:
                    truncated_line_nums.add(line_no)
    except OSError as exc:
        logger.warning("Error reading transcript %s: %s", tfile, exc)
        return None

    # Upgrade truncated lines within our target slice
    slice_raw = raw_entries[-(max_messages * 5) :] if max_messages > 0 else raw_entries
    needed_full = {ln for ln, _ in slice_raw if ln in truncated_line_nums}
    full_lookup: dict[int, dict[str, Any]] = {}
    if needed_full and full_tfile.is_file():
        max_ln = max(needed_full)
        try:
            with full_tfile.open("r", encoding="utf-8", errors="replace") as ffull:
                for line_no, raw_line in enumerate(ffull):
                    if line_no in needed_full:
                        try:
                            full_lookup[line_no] = json.loads(raw_line)
                        except json.JSONDecodeError:
                            pass
                    if line_no >= max_ln:
                        break
        except OSError:
            pass

    def _parse_entry_slice(entries: list[tuple[int, dict[str, Any]]]) -> list[ChatMessage]:
        nonlocal title
        out_msgs: list[ChatMessage] = []
        skip_next_prewarm_reply = False
        pending_tool_imgs: list[Path] = []
        pending_steps: list[str] = []

        def _append_unique(dst: list[Path], src: list[Path]) -> None:
            for p in src:
                try:
                    rp = p.resolve()
                    if rp.is_file() and rp not in dst:
                        dst.append(rp)
                except OSError:
                    pass

        for line_no, obj in entries:
            if line_no in full_lookup:
                obj = full_lookup[line_no]

            etype = obj.get("type")
            step_idx = int(obj.get("step_index") or 0)
            ts_ms = _parse_iso_to_ms(str(obj.get("created_at") or ""))

            images: list[Path] = []
            for m_item in obj.get("media") or []:
                if isinstance(m_item, dict):
                    uri = str(m_item.get("uri") or "").strip()
                    mime = str(m_item.get("mime_type") or "").lower()
                    if uri and (
                        mime.startswith("image/")
                        or Path(uri).suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
                    ):
                        p = _uri_to_local_path(uri)
                        if p.is_file():
                            images.append(p)

            if etype not in {"USER_INPUT", "PLANNER_RESPONSE"}:
                for sm in SAVED_PATH_RE.finditer(str(obj.get("content") or "")):
                    sp = _uri_to_local_path(sm.group(1))
                    if sp.is_file():
                        images.append(sp)
                if images and not skip_next_prewarm_reply:
                    _append_unique(pending_tool_imgs, images)
                    if len(pending_tool_imgs) > 4:
                        pending_tool_imgs = pending_tool_imgs[-4:]
                continue

            if etype == "USER_INPUT":
                if obj.get("source") not in {"USER_EXPLICIT", None, ""}:
                    continue
                if pending_tool_imgs and out_msgs and out_msgs[-1].role == "assistant":
                    _append_unique(out_msgs[-1].image_paths, pending_tool_imgs[-4:])
                pending_tool_imgs = []
                pending_steps = []
                cleaned_u = clean_user_input_text(str(obj.get("content") or ""))
                if PREWARM_PROMPT_MARKER in cleaned_u:
                    skip_next_prewarm_reply = True
                    continue
                skip_next_prewarm_reply = False
                if not cleaned_u and not images:
                    continue
                if not title:
                    first_ln = next((ln.strip() for ln in cleaned_u.splitlines() if ln.strip()), "")
                    title = first_ln[:54]
                out_msgs.append(
                    ChatMessage(
                        role="user",
                        text=cleaned_u,
                        step_index=step_idx,
                        ts_ms=ts_ms,
                        image_paths=images,
                    )
                )
            elif etype == "PLANNER_RESPONSE":
                content = str(obj.get("content") or "").strip()
                if skip_next_prewarm_reply and content in {"就绪", "就绪。", "收到"}:
                    skip_next_prewarm_reply = False
                    pending_tool_imgs = []
                    pending_steps = []
                    continue
                for tc in obj.get("tool_calls") or []:
                    if isinstance(tc, dict):
                        lbl = _humanize_tool_step(str(tc.get("name") or ""), tc.get("args") or tc.get("arguments"))
                        if lbl and lbl not in pending_steps and len(pending_steps) < 16:
                            pending_steps.append(lbl)
                for md_m in MD_LOCAL_IMG_RE.finditer(content):
                    raw_u = md_m.group(1).strip()
                    if not raw_u.startswith("/dl/"):
                        p_md = _uri_to_local_path(raw_u)
                        if p_md.is_file():
                            images.append(p_md)
                combined_imgs: list[Path] = []
                _append_unique(combined_imgs, pending_tool_imgs[-4:])
                _append_unique(combined_imgs, images)
                if not content and not combined_imgs:
                    continue
                pending_tool_imgs = []
                cur_steps = list(pending_steps)
                pending_steps = []
                if out_msgs and out_msgs[-1].role == "assistant":
                    prev = out_msgs[-1]
                    if content and content != prev.text:
                        prev.text = f"{prev.text}\n\n{content}".strip() if prev.text else content
                    _append_unique(prev.image_paths, combined_imgs)
                    if len(prev.image_paths) > 4:
                        prev.image_paths = prev.image_paths[-4:]
                    for st_lbl in cur_steps:
                        if st_lbl not in prev.steps and len(prev.steps) < 16:
                            prev.steps.append(st_lbl)
                    if ts_ms > prev.ts_ms:
                        prev.ts_ms = ts_ms
                else:
                    out_msgs.append(
                        ChatMessage(
                            role="assistant",
                            text=content,
                            step_index=step_idx,
                            ts_ms=ts_ms,
                            image_paths=combined_imgs,
                            steps=cur_steps,
                        )
                    )
        if pending_tool_imgs:
            if out_msgs and out_msgs[-1].role == "assistant":
                _append_unique(out_msgs[-1].image_paths, pending_tool_imgs[-4:])
            else:
                out_msgs.append(
                    ChatMessage(
                        role="assistant",
                        text="",
                        step_index=0,
                        ts_ms=0,
                        image_paths=list(pending_tool_imgs[-4:]),
                    )
                )
        return out_msgs

    parsed_msgs = _parse_entry_slice(slice_raw)
    approx_older = len(raw_entries) > len(slice_raw)
    total_est = len(parsed_msgs) + (max(1, (len(raw_entries) - len(slice_raw)) // 2) if approx_older else 0)
    final_msgs = parsed_msgs[-max_messages:] if max_messages > 0 else parsed_msgs
    has_more = approx_older or (len(parsed_msgs) > len(final_msgs))
    total_count = max(total_est, len(parsed_msgs))

    if not title:
        title = next((_clean_display_title(m.text, 60) for m in parsed_msgs if m.role == "user" and m.text), "")

    return ConversationDetail(
        conversation_id=cid,
        title=title or f"对话 {cid[:8]}",
        store=chosen_store,
        workspace=workspace,
        running=running,
        messages=final_msgs,
        total_messages=total_count,
        has_more=has_more,
    )


def build_ide_handoff_context(detail: ConversationDetail, max_chars: int = 5500) -> str:
    """Build a compact context block so continuing a PC Antigravity/Codex chat on mobile preserves history."""
    origin_name = "Codex 电脑端" if detail.store == "codex" else "Antigravity 电脑端"
    lines: list[str] = [
        f"来源：{origin_name}",
        f"对话标题：{detail.title}",
        f"原对话 ID：{detail.conversation_id}",
    ]
    if detail.workspace:
        lines.append(f"原工作目录：{detail.workspace}")
    lines.append("以下是该电脑端对话最近的聊天记录（请无缝接着往下处理，无需重复总结前文）：")

    recent_snippets: list[str] = []
    used = 0
    for msg in reversed(detail.messages[-16:]):
        role_tag = "主人" if msg.role == "user" else "助理"
        snippet = msg.text.strip()
        if len(snippet) > 800:
            snippet = snippet[:800] + "..."
        entry = f"{role_tag}：{snippet}"
        if used + len(entry) > max_chars:
            break
        recent_snippets.append(entry)
        used += len(entry)

    recent_snippets.reverse()
    lines.extend(recent_snippets)
    return "\n".join(lines)


def list_recent_workspaces(
    default_workspace: Path,
    ide_dir: Path | None = None,
    cli_dir: Path | None = None,
    codex_dir: Path | None = None,
    limit: int = 12,
) -> list[str]:
    """Collect recent existing workspace directories across Antigravity + Codex for quick project selection."""
    seen: list[str] = []

    def _add(p_str: str) -> None:
        if not p_str:
            return
        try:
            rp = str(Path(_clean_win_path(p_str)).resolve())
            if Path(rp).is_dir() and rp not in seen:
                seen.append(rp)
        except OSError:
            pass

    _add(str(default_workspace))
    for item in list_local_conversations(limit=80, ide_dir=ide_dir, cli_dir=cli_dir, codex_dir=codex_dir):
        if item.workspace:
            _add(item.workspace)

    scratch_dir = (ide_dir if ide_dir is not None else _default_ide_dir()) / "scratch"
    if scratch_dir.is_dir():
        for child in sorted(scratch_dir.iterdir(), key=_safe_mtime, reverse=True)[:8]:
            if child.is_dir():
                _add(str(child))

    return seen[:limit]


def get_transcript_signature(
    conversation_id: str,
    store: str = "ide",
    ide_dir: Path | None = None,
    cli_dir: Path | None = None,
    codex_dir: Path | None = None,
) -> tuple[int, int]:
    """Return lightweight (mtime_ns, size_bytes) signature for detecting live PC transcript updates."""
    cid = (conversation_id or "").strip().removeprefix("codex:")
    if not SAFE_CONV_ID_RE.match(cid):
        return (0, 0)

    if store == "codex":
        codex_root = codex_dir if codex_dir is not None else _default_codex_dir()
        rp, _, _ = _resolve_codex_rollout(codex_root, cid)
        if rp is None:
            return (0, 0)
        try:
            st = rp.stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return (0, 0)

    base = (
        (cli_dir if cli_dir is not None else _default_cli_dir())
        if store == "cli"
        else (ide_dir if ide_dir is not None else _default_ide_dir())
    )
    tfile = base / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"
    try:
        st = tfile.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return (0, 0)
