"""Dedicated Mobile-First Progressive Web App (PWA) server for Stayy."""

from __future__ import annotations

import asyncio
import base64
import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse, urlsplit

import websockets
from websockets.asyncio.server import ServerConnection
from websockets.datastructures import Headers
from websockets.http11 import Request, Response

from .agy_session import AgySession, SessionManager, TurnResult, _kill_process_tree_win32
from .approvals import ApprovalReadonlyTracker, deny_auto_invoke, inspect_ide_actions_readonly
from .auth import (
    AuthManager,
    atomic_write_env_token,
    cleanup_admin_state,
    write_admin_state,
)
from .config import BridgeConfig, resolve_agy_executable
from .conversations import (
    SAVED_PATH_RE,
    ConversationDetail,
    _default_cli_dir,
    _default_ide_dir,
    _uri_to_local_path,
    build_ide_handoff_context,
    get_transcript_signature,
    list_local_conversations,
    list_recent_workspaces,
    load_conversation_detail,
)
from .desktop_tools import (
    ALLOWED_IMAGE_EXTS,
    CREATE_NO_WINDOW,
    MODEL_ALIASES,
    PROJECT_INBOX_DIR,
    SEND_FILE_RE,
    SEND_IMAGE_RE,
    THOUGHT_TAG_RE,
    _resolve_inside_workspace,
    cancel_antigravity_ide_window_turn,
    capture_desktop_fast_jpeg_sync,
    create_and_send_antigravity_ide_new_chat,
    find_codex_cli_executable,
    get_desktop_cursor_ratio,
    get_pc_clipboard_text,
    get_workspace_file_diff,
    inspect_pc_system_and_ports,
    inspect_workspace_git,
    is_safe_outbound_file,
    list_workspace_directory,
    open_new_antigravity_ide_chat_window,
    perform_desktop_remote_input,
    prune_inbox,
    read_workspace_file_preview,
    sanitize_filename,
    send_prompt_to_antigravity_ide_window,
    set_pc_clipboard_text,
)
from .maintenance import discover_default_cache_targets, run_safe_cache_cleanup
from .notifier import BarkNotifier

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = Path(__file__).resolve().parent / "static"
ASSETS_DIR = PROJECT_ROOT / "assets"
CONTINUATION_MAP_FILE = PROJECT_ROOT / ".continuation_map.json"

DEFAULT_SLOT_KEY = "default-chat"
MAX_UPLOAD_BYTES = 100 * 1024 * 1024

# Match Markdown images pointing to local paths or file:// URIs (including Codex `<F:/path/img.png>` syntax)
MD_IMAGE_LOCAL_RE = re.compile(
    r"!\[([^\]]*)\]\(\s*<?((?:file:///)?[A-Za-z]:[\\/][^)\r\n>]+)>?\s*\)",
    re.IGNORECASE,
)
# Match Markdown links pointing directly to local image files `[截图](<F:/.../shot.png>)` or `file:///...png`
MD_LINK_LOCAL_IMG_RE = re.compile(
    r"(?<!!)\[([^\]]+)\]\(\s*<?((?:file:///)?[A-Za-z]:[\\/][^)\r\n>]+?\.(?:png|jpg|jpeg|webp|gif|bmp))>?\s*\)",
    re.IGNORECASE,
)

SERVICE_WORKER_JS = """\
self.addEventListener('install', (e) => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  const u = new URL(e.request.url);
  if (u.origin !== self.location.origin || u.pathname === '/ping' || u.pathname.startsWith('/dl/')) return;
  e.respondWith(
    fetch(e.request, { cache: 'no-store' }).catch(() => caches.match(e.request))
  );
});
"""


def _local_uri_or_path_to_path(raw: str) -> Path:
    s = (raw or "").strip().strip("<>\"'")
    if s.startswith("file://"):
        p = unquote(urlparse(s).path)
        if len(p) >= 3 and p[0] == "/" and p[2] == ":":
            p = p[1:]
        return Path(p)
    return Path(s).expanduser()


def get_lan_ipv4() -> str:
    """Detect primary LAN IPv4 address for instant Wi-Fi access."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("223.5.5.5", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith(("127.", "169.254.", "198.18.")):
                return ip
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith(("127.", "169.254.", "198.18.")):
                return ip
    except OSError:
        pass
    return "127.0.0.1"


def ensure_web_access_token(env_path: Path, current_token: str) -> str:
    """Ensure a strong cryptographic WEB_ACCESS_TOKEN exists, atomically persisting to .env if missing."""
    tok = current_token.strip()
    if len(tok) >= 16 and tok != "change-me":
        return tok
    new_tok = secrets.token_urlsafe(24)
    try:
        atomic_write_env_token(env_path, new_tok)
    except OSError as exc:
        logger.warning("Could not persist generated WEB_ACCESS_TOKEN to %s: %s", env_path, exc)
    return new_tok


def extract_pwa_media_and_text(text: str) -> tuple[str, list[Path], list[Path]]:
    """Strip <thought> tags and extract [SEND_IMAGE], [SEND_FILE], and local Markdown image/file tags."""
    cleaned = THOUGHT_TAG_RE.sub("", text or "")
    images: list[Path] = []
    files: list[Path] = []

    def _add_img(p: Path) -> bool:
        if is_safe_outbound_file(p, image_only=True):
            rp = p.resolve()
            if rp not in images:
                images.append(rp)
            return True
        return False

    def _on_send_img(m: re.Match[str]) -> str:
        raw = m.group(1).strip()
        if raw:
            _add_img(_local_uri_or_path_to_path(raw))
        return ""

    def _on_send_file(m: re.Match[str]) -> str:
        raw = m.group(1).strip()
        if raw:
            p = _local_uri_or_path_to_path(raw)
            if is_safe_outbound_file(p, image_only=False):
                rp = p.resolve()
                if rp not in files:
                    files.append(rp)
        return ""

    def _on_md_img(m: re.Match[str]) -> str:
        raw_target = m.group(2).strip()
        p = _local_uri_or_path_to_path(raw_target)
        if _add_img(p):
            return ""
        return m.group(0)

    def _on_md_link_img(m: re.Match[str]) -> str:
        label, raw_target = m.group(1).strip(), m.group(2).strip()
        p = _local_uri_or_path_to_path(raw_target)
        if _add_img(p):
            return label
        return m.group(0)

    cleaned = SEND_IMAGE_RE.sub(_on_send_img, cleaned)
    cleaned = SEND_FILE_RE.sub(_on_send_file, cleaned)
    cleaned = MD_IMAGE_LOCAL_RE.sub(_on_md_img, cleaned)
    cleaned = MD_LINK_LOCAL_IMG_RE.sub(_on_md_link_img, cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip(), images, files


def harvest_recent_cli_turn_images(
    cli_store_root: Path,
    conversation_id: str,
    since_epoch_sec: float,
) -> list[Path]:
    """Find screenshots saved by MCP / browser tools in `~/.gemini/antigravity-cli/brain/<cid>/.../media/`."""
    cid = (conversation_id or "").strip()
    if not cid:
        return []
    media_dir = cli_store_root / "brain" / cid / ".system_generated" / "logs" / "media"
    if not media_dir.is_dir():
        return []
    found: list[tuple[float, Path]] = []
    try:
        for f in media_dir.iterdir():
            if not f.is_file() or f.suffix.lower() not in ALLOWED_IMAGE_EXTS:
                continue
            st = f.stat()
            if st.st_mtime >= (since_epoch_sec - 1.5) and is_safe_outbound_file(f, image_only=True):
                found.append((st.st_mtime, f.resolve()))
    except OSError:
        return []
    found.sort(key=lambda t: t[0])
    return [p for _, p in found[-4:]]


def read_ide_live_turn_snapshot(
    ide_store_root: Path,
    conversation_id: str,
    baseline_lines: int,
) -> dict[str, Any]:
    """Read live progress of an active PC Antigravity IDE turn starting at `baseline_lines`."""
    cid = (conversation_id or "").strip()
    db_path = ide_store_root / "conversation_summaries.db"
    has_db_row = False
    db_running = False
    if db_path.is_file():
        try:
            con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1.5)
            try:
                row = con.execute(
                    "SELECT status FROM conversation_summaries WHERE conversation_id = ?",
                    (cid,),
                ).fetchone()
            finally:
                con.close()
            if row is not None:
                has_db_row = True
                db_running = "RUNNING" in str(row[0] or "").upper()
        except Exception:
            pass

    tfile = ide_store_root / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"
    if not tfile.is_file():
        return {
            "total_lines": 0,
            "mtime_ns": 0,
            "size": 0,
            "has_db_row": has_db_row,
            "db_running": db_running,
            "saw_user_input": False,
            "user_input_line_nos": [],
            "saw_activity_after_user": False,
            "last_planner_had_tools": False,
            "latest_tool_name": "",
            "text": "",
            "images": [],
        }

    try:
        st = tfile.stat()
        mtime_ns, size = st.st_mtime_ns, st.st_size
    except OSError:
        mtime_ns, size = 0, 0

    tail_entries: list[tuple[int, dict[str, Any]]] = []
    trunc_lines: set[int] = set()
    total_lines = 0
    try:
        with tfile.open("r", encoding="utf-8", errors="replace") as fh:
            for ln_no, raw in enumerate(fh):
                total_lines = ln_no + 1
                if ln_no < baseline_lines:
                    continue
                s = raw.strip()
                if not s:
                    continue
                try:
                    obj = json.loads(s)
                except json.JSONDecodeError:
                    continue
                tail_entries.append((ln_no, obj))
                trunc = obj.get("truncated_fields") or []
                if isinstance(trunc, list) and "content" in trunc and obj.get("type") == "PLANNER_RESPONSE":
                    trunc_lines.add(ln_no)
    except OSError:
        pass

    full_tfile = tfile.with_name("transcript_full.jsonl")
    if trunc_lines and full_tfile.is_file():
        max_ln = max(trunc_lines)
        full_map: dict[int, dict[str, Any]] = {}
        try:
            with full_tfile.open("r", encoding="utf-8", errors="replace") as ffull:
                for ln_no, raw in enumerate(ffull):
                    if ln_no in trunc_lines:
                        try:
                            full_map[ln_no] = json.loads(raw)
                        except json.JSONDecodeError:
                            pass
                    if ln_no >= max_ln:
                        break
        except OSError:
            pass
        if full_map:
            tail_entries = [(ln_no, full_map.get(ln_no, obj)) for ln_no, obj in tail_entries]

    user_positions: list[tuple[int, int]] = []
    for idx, (ln_no, obj) in enumerate(tail_entries):
        if obj.get("type") == "USER_INPUT" and obj.get("source") in {"USER_EXPLICIT", None, ""}:
            user_positions.append((idx, ln_no))

    saw_user_input = len(user_positions) > 0
    user_input_line_nos = [ln_no for _, ln_no in user_positions]
    saw_activity_after_user = False
    last_planner_had_tools = False
    latest_tool_name = ""
    planner_blocks: list[str] = []
    turn_images: list[Path] = []

    def _add_img(p: Path) -> None:
        try:
            rp = p.resolve()
            if rp.is_file() and rp not in turn_images:
                turn_images.append(rp)
        except OSError:
            pass

    if saw_user_input:
        first_u_idx = user_positions[0][0]
        second_u_idx = user_positions[1][0] if len(user_positions) > 1 else len(tail_entries)
        for _, obj in tail_entries[first_u_idx + 1 : second_u_idx]:
            etype = obj.get("type")
            if etype in {"PLANNER_RESPONSE", "GENERIC"}:
                saw_activity_after_user = True

            for m_item in obj.get("media") or []:
                if isinstance(m_item, dict):
                    uri = str(m_item.get("uri") or "").strip()
                    mime = str(m_item.get("mime_type") or "").lower()
                    if uri and (mime.startswith("image/") or Path(uri).suffix.lower() in ALLOWED_IMAGE_EXTS):
                        _add_img(_uri_to_local_path(uri))

            if etype == "GENERIC":
                for sm in SAVED_PATH_RE.finditer(str(obj.get("content") or "")):
                    _add_img(_uri_to_local_path(sm.group(1)))
            elif etype == "PLANNER_RESPONSE":
                tcalls = [tc for tc in (obj.get("tool_calls") or []) if isinstance(tc, dict)]
                last_planner_had_tools = len(tcalls) > 0
                if tcalls:
                    latest_tool_name = str(tcalls[-1].get("name") or "")
                content = str(obj.get("content") or "").strip()
                if content:
                    if not planner_blocks or planner_blocks[-1] != content:
                        planner_blocks.append(content)
                    if not tcalls:
                        latest_tool_name = ""

    return {
        "total_lines": total_lines,
        "mtime_ns": mtime_ns,
        "size": size,
        "has_db_row": has_db_row,
        "db_running": db_running,
        "saw_user_input": saw_user_input,
        "user_input_line_nos": user_input_line_nos,
        "saw_activity_after_user": saw_activity_after_user,
        "last_planner_had_tools": last_planner_had_tools,
        "latest_tool_name": latest_tool_name,
        "text": "\n\n".join(planner_blocks).strip(),
        "images": turn_images[-4:],
    }


def _extend_deduplicated_turns(base_hist: list[dict[str, Any]], extra_turns: list[dict[str, Any]]) -> None:
    """Append `extra_turns` that are not already present in the recent tail of `base_hist`."""
    recent_keys = {
        (str(m.get("role") or ""), str(m.get("text") or "").strip())
        for m in base_hist[-40:]
        if isinstance(m, dict)
    }
    for item in extra_turns:
        key = (str(item.get("role") or ""), str(item.get("text") or "").strip())
        if key[1] and key in recent_keys:
            continue
        base_hist.append(item)
        if key[1]:
            recent_keys.add(key)


class _UploadState:
    def __init__(self, path: Path, name: str, expected_size: int) -> None:
        self.path = path
        self.temp_path = path.with_name(path.name + ".part")
        self.name = name
        self.expected_size = max(0, int(expected_size))
        self.written = 0
        self._closed = False
        self.fh = self.temp_path.open("wb")

    def write(self, data: bytes) -> None:
        if self.written + len(data) > MAX_UPLOAD_BYTES:
            raise ValueError("上传文件超过 100MB 上限")
        if self.expected_size > 0 and self.written + len(data) > self.expected_size:
            raise ValueError("上传分片超出声明文件大小")
        self.fh.write(data)
        self.written += len(data)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self.fh.close()
            except Exception:
                pass

    def finalize(self) -> Path:
        try:
            if not self._closed:
                self.fh.flush()
                self.fh.close()
                self._closed = True
            if self.expected_size > 0 and self.written != self.expected_size:
                raise ValueError("上传文件不完整，请重试")
            self.temp_path.replace(self.path)
            return self.path
        except Exception:
            self.abort()
            raise

    def abort(self) -> None:
        self.close()
        try:
            self.temp_path.unlink(missing_ok=True)
        except OSError:
            pass


class WebPwaServer:
    """Hardened HTTP + WebSocket server + isolated loopback admin control plane for Stayy."""

    def __init__(
        self,
        config: BridgeConfig,
        session_manager: SessionManager,
        access_token: str,
        *,
        env_path: Path | None = None,
        runtime_dir: Path | None = None,
        admin_secret: str | None = None,
        bark_notifier: BarkNotifier | None = None,
        on_ws_pre_register: Callable[[ServerConnection], Awaitable[None]] | None = None,
        ide_store_dir: Path | None = None,
        cli_store_dir: Path | None = None,
        codex_store_dir: Path | None = None,
        continuation_map_path: Path | None = None,
        pc_window_sender: Callable[[str, str, str], tuple[bool, str]] | None = None,
        pc_window_new_opener: Callable[[], tuple[bool, str]] | None = None,
        pc_window_new_sender: Callable[[str], tuple[bool, str, str]] | None = None,
        pc_window_canceller: Callable[[str], bool] | None = None,
        ide_actions_inspector: Callable[[str], list[dict[str, Any]]] | None = None,
        ide_action_invoker: Callable[[str], tuple[bool, str]] | None = None,
        desktop_input_handler: Callable[[str, float, float, str], tuple[bool, str]] | None = None,
        pc_clipboard_getter: Callable[[], dict[str, Any]] | None = None,
        pc_clipboard_setter: Callable[[str], tuple[bool, str]] | None = None,
        pc_system_inspector: Callable[[Path | None], dict[str, Any]] | None = None,
        codex_cli_path: Path | None = None,
    ) -> None:
        self.config = config
        self.sessions = session_manager
        self.env_path = env_path
        self.runtime_dir = runtime_dir or (PROJECT_ROOT / ".runtime")
        self.auth = AuthManager(access_token, runtime_dir=self.runtime_dir, env_path=env_path)
        self.admin_secret = (admin_secret or "").strip() or secrets.token_urlsafe(24)
        self.admin_port: int = 0
        self._admin_state_file: Path | None = None
        self._on_ws_pre_register = on_ws_pre_register

        self.ide_store_dir = ide_store_dir
        self.cli_store_dir = cli_store_dir
        self.codex_store_dir = codex_store_dir
        self._pc_window_sender: Callable[[str, str, str], tuple[bool, str]] | None = (
            pc_window_sender
            if pc_window_sender is not None
            else (send_prompt_to_antigravity_ide_window if ide_store_dir is None else None)
        )
        self._pc_window_new_opener: Callable[[], tuple[bool, str]] | None = (
            pc_window_new_opener
            if pc_window_new_opener is not None
            else (open_new_antigravity_ide_chat_window if ide_store_dir is None else None)
        )
        self._pc_window_new_sender: Callable[[str], tuple[bool, str, str]] | None = (
            pc_window_new_sender
            if pc_window_new_sender is not None
            else (
                (lambda prompt: create_and_send_antigravity_ide_new_chat(prompt, ide_store_dir))
                if ide_store_dir is None
                else None
            )
        )
        self._pc_window_canceller: Callable[[str], bool] | None = (
            pc_window_canceller
            if pc_window_canceller is not None
            else (cancel_antigravity_ide_window_turn if ide_store_dir is None else None)
        )
        self._approval_tracker = ApprovalReadonlyTracker()
        self._ide_actions_inspector: Callable[[str], list[dict[str, Any]]] = (
            ide_actions_inspector
            if ide_actions_inspector is not None
            else (
                (lambda cid="": inspect_ide_actions_readonly(cid, tracker=self._approval_tracker))
                if ide_store_dir is None
                else (lambda _cid="": [])
            )
        )
        self._ide_action_invoker = ide_action_invoker
        self._custom_desktop_input = desktop_input_handler is not None
        self._desktop_input_handler: Callable[..., tuple[bool, str]] = (
            desktop_input_handler
            if desktop_input_handler is not None
            else (
                perform_desktop_remote_input
                if ide_store_dir is None
                else (lambda act, xr, yr, kn, _txt="": (False, "测试环境未启用远程桌面输入"))
            )
        )
        self._pc_clipboard_getter: Callable[[], dict[str, Any]] = (
            pc_clipboard_getter if pc_clipboard_getter is not None else get_pc_clipboard_text
        )
        self._pc_clipboard_setter: Callable[[str], tuple[bool, str]] = (
            pc_clipboard_setter if pc_clipboard_setter is not None else set_pc_clipboard_text
        )
        self._pc_system_inspector: Callable[[Path | None], dict[str, Any]] = (
            pc_system_inspector if pc_system_inspector is not None else inspect_pc_system_and_ports
        )
        self._codex_cli_override = codex_cli_path
        self.bark_notifier = (
            bark_notifier
            if bark_notifier is not None
            else BarkNotifier(config.bark_push_url, allow_private_host=config.bark_allow_private_host)
        )
        self._cont_map_path = continuation_map_path or (
            (cli_store_dir / "continuation_map.json") if cli_store_dir is not None else CONTINUATION_MAP_FILE
        )
        self._continuation_map: dict[str, str] = self._load_continuation_map()

        self._clients: set[ServerConnection] = set()
        self._client_epochs: dict[ServerConnection, int] = {}
        self._clients_lock = asyncio.Lock()
        self._media_registry: OrderedDict[str, Path] = OrderedDict()
        self._tasks: set[asyncio.Task[None]] = set()

        # Shared single-producer live-screen coordinator with bounded 1-frame subscriber queues
        self._screen_subs: dict[ServerConnection, asyncio.Queue[dict[str, Any]]] = {}
        self._screen_sender_tasks: dict[ServerConnection, asyncio.Task[None]] = {}
        self._screen_producer_task: asyncio.Task[None] | None = None
        self._screen_interval: float = 0.75
        self._screen_lock = asyncio.Lock()
        self._screen_capturer: Callable[..., Path] = (
            lambda dir_p, w=1440, q=76: capture_desktop_fast_jpeg_sync(dir_p, w, q)
        )
        self._cursor_reader: Callable[[], dict[str, float | int]] = get_desktop_cursor_ratio

        # Active slot currently displayed on mobile clients + per-slot isolated state
        self._active_slot: str = DEFAULT_SLOT_KEY
        self._slot_history: dict[str, list[dict[str, Any]]] = {DEFAULT_SLOT_KEY: []}
        self._slot_local_turns: dict[str, list[dict[str, Any]]] = {}
        self._slot_inflight: dict[str, dict[str, Any]] = {}
        self._slot_followup_queue: dict[str, list[dict[str, Any]]] = {}
        self._slot_codex_procs: dict[str, asyncio.subprocess.Process] = {}
        self._slot_meta: dict[str, dict[str, Any]] = {
            DEFAULT_SLOT_KEY: {
                "conversation_id": "",
                "title": "",
                "store": "ide" if self._pc_window_new_sender is not None else "",
            }
        }
        self._unread_slots: dict[str, dict[str, Any]] = {}
        self._processed_client_ids: OrderedDict[str, float] = OrderedDict()
        self._cancelled_reply_ids: set[str] = set()
        self._nav_seq: int = 0
        self._watch_gen: int = 0
        self._ide_watch_sig: tuple[str, str, int, int] = ("", "", 0, 0)
        self.pc_ide_poll_interval: float = 0.55
        self.pc_ide_accept_timeout: float = 10.0

    @property
    def access_token(self) -> str:
        return self.auth.access_token

    @access_token.setter
    def access_token(self, value: str) -> None:
        self.auth.access_token = (value or "").strip()

    def _load_continuation_map(self) -> dict[str, str]:
        if self._cont_map_path.is_file():
            try:
                raw = json.loads(self._cont_map_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    return {str(k): str(v) for k, v in raw.items() if k and v}
            except Exception:
                pass
        return {}

    def _save_continuation_map(self) -> None:
        try:
            self._cont_map_path.parent.mkdir(parents=True, exist_ok=True)
            self._cont_map_path.write_text(
                json.dumps(self._continuation_map, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass

    def _session_for_slot(self, slot_key: str) -> AgySession:
        s = self.sessions.get(f"pwa:{slot_key}")
        s._ide_continuation_map = (
            {} if (self._pc_window_sender is not None and slot_key.startswith("ide:")) else self._continuation_map
        )
        return s

    @property
    def _history(self) -> list[dict[str, Any]]:
        return self._slot_history.setdefault(self._active_slot, [])

    def _append_slot_history(
        self, slot_key: str, item: dict[str, Any], *, persist_local: bool = True
    ) -> None:
        arr = self._slot_history.setdefault(slot_key, [])
        arr.append(item)
        if len(arr) > 300:
            self._slot_history[slot_key] = arr[-300:]
        if persist_local:
            loc = self._slot_local_turns.setdefault(slot_key, [])
            loc.append(item)
            if len(loc) > 100:
                self._slot_local_turns[slot_key] = loc[-100:]

    def _insert_slot_history_before(
        self, slot_key: str, item: dict[str, Any], before_id: str, *, persist_local: bool = True
    ) -> None:
        arr = self._slot_history.setdefault(slot_key, [])
        if before_id:
            for idx, existing in enumerate(arr):
                if existing.get("id") == before_id:
                    arr.insert(idx, item)
                    break
            else:
                arr.append(item)
        else:
            arr.append(item)
        if len(arr) > 300:
            self._slot_history[slot_key] = arr[-300:]
        if persist_local:
            loc = self._slot_local_turns.setdefault(slot_key, [])
            loc.append(item)
            if len(loc) > 100:
                self._slot_local_turns[slot_key] = loc[-100:]

    def _remove_slot_local_turn(self, slot_key: str, item_id: str) -> None:
        loc = self._slot_local_turns.get(slot_key)
        if loc:
            self._slot_local_turns[slot_key] = [x for x in loc if x.get("id") != item_id]

    def _public_inflight(self, slot_key: str) -> dict[str, Any] | None:
        inf = self._slot_inflight.get(slot_key)
        if not inf:
            return None
        return {
            "msg_id": str(inf.get("msg_id") or ""),
            "slot": str(inf.get("slot") or slot_key),
            "model": str(inf.get("model") or ""),
            "text": str(inf.get("text") or ""),
            "status": str(inf.get("status") or ""),
            "steps": list(inf.get("steps") or []),
            "started_ms": int(inf.get("started_ms") or 0),
        }

    def _build_slots_overview(self) -> dict[str, Any]:
        running_items: list[dict[str, Any]] = []
        for s_key, inf in list(self._slot_inflight.items()):
            meta = self._slot_meta.get(s_key, {})
            running_items.append(
                {
                    "slot": s_key,
                    "conversation_id": str(meta.get("conversation_id") or ""),
                    "store": str(meta.get("store") or ""),
                    "title": str(meta.get("title") or "会话执行中"),
                    "status": str(inf.get("status") or "正在生成..."),
                }
            )
        unread_items = list(self._unread_slots.values())[-15:]
        return {"running": running_items, "unread": unread_items}

    async def _broadcast_slots_overview(self) -> None:
        await self._broadcast({"type": "slots_overview", **self._build_slots_overview()})

    def _client_ip(self, connection: ServerConnection, headers: Headers | None = None) -> str:
        peer_ip = "unknown"
        peer = connection.remote_address
        if isinstance(peer, tuple) and peer:
            peer_ip = str(peer[0])
        # Only trust proxy headers when socket originates from local loopback AND tunnel proxy trust is explicitly enabled
        if (
            self.config.trust_cf_proxy_headers
            and headers is not None
            and peer_ip in {"127.0.0.1", "::1", "::ffff:127.0.0.1"}
        ):
            cf_ip = headers.get("CF-Connecting-IP", "").strip()
            if cf_ip:
                return cf_ip[:64]
        return peer_ip

    def _is_ip_locked(self, ip: str) -> bool:
        return self.auth.is_ip_locked(ip)

    def _record_auth_failure(self, ip: str) -> None:
        self.auth.record_auth_failure(ip)

    def _allowed_origin_set(self, host_hdr: str) -> set[str]:
        allowed: set[str] = set()
        if host_hdr:
            allowed.add(host_hdr.strip().lower())
        for orig in self.config.allowed_origins:
            p = urlsplit(orig.strip())
            if p.netloc:
                allowed.add(p.netloc.strip().lower())
        if self.config.public_base_url:
            p_pub = urlsplit(self.config.public_base_url)
            if p_pub.netloc:
                allowed.add(p_pub.netloc.strip().lower())
        return allowed

    def _is_allowed_origin(self, origin_hdr: str, host_hdr: str) -> bool:
        if not origin_hdr:
            return True
        p = urlsplit(origin_hdr.strip())
        if p.scheme.lower() not in {"http", "https"} or not p.netloc:
            return False
        return p.netloc.strip().lower() in self._allowed_origin_set(host_hdr)

    def _cors_headers(self, headers: Headers | None) -> dict[str, str]:
        if headers is None:
            return {}
        origin_hdr = (headers.get("Origin") or "").strip()
        host_hdr = (headers.get("Host") or "").strip()
        if origin_hdr and self._is_allowed_origin(origin_hdr, host_hdr):
            p = urlsplit(origin_hdr)
            # Only reflect CORS header when cross-origin (origin netloc != host)
            if p.netloc.strip().lower() != host_hdr.strip().lower():
                return {"Access-Control-Allow-Origin": origin_hdr, "Vary": "Origin"}
        return {}

    def _extract_credential_and_ticket(self, query: str, headers: Headers | None) -> tuple[str, str]:
        qs = parse_qs(query or "")
        q_tok = (qs.get("token") or [""])[0].strip()
        ticket = (qs.get("ticket") or [""])[0].strip()
        if q_tok:
            return q_tok, ticket
        if headers is not None:
            auth_hdr = (headers.get("Authorization") or "").strip()
            if auth_hdr.lower().startswith("bearer "):
                bearer = auth_hdr[7:].strip()
                if bearer:
                    return bearer, ticket
            raw_cookie = headers.get("Cookie", "")
            if raw_cookie:
                try:
                    jar = SimpleCookie()
                    jar.load(raw_cookie)
                    morsel = jar.get("stayy_session")
                    if morsel and morsel.value:
                        return morsel.value.strip(), ticket
                except Exception:
                    pass
        return "", ticket

    def _verify_token(self, token: str, ip: str, *, record_failure: bool = True) -> bool:
        ok, _ = self.auth.verify_credential(token, ip, record_failure=record_failure)
        return ok

    def register_media(self, path: Path) -> str:
        resolved = path.resolve()
        for existing_id, existing_path in self._media_registry.items():
            if existing_path == resolved:
                self._media_registry.move_to_end(existing_id)
                return existing_id
        media_id = uuid.uuid4().hex
        self._media_registry[media_id] = resolved
        while len(self._media_registry) > 400:
            self._media_registry.popitem(last=False)
        return media_id

    def _media_ref(self, path: Path, **extra: Any) -> dict[str, Any]:
        mid = self.register_media(path)
        item: dict[str, Any] = {
            "media_id": mid,
            "media_ticket": self.auth.issue_media_ticket(mid),
        }
        item.update(extra)
        return item

    async def revoke_all_tokens(self) -> tuple[bool, int, int]:
        """Atomically rotate master token, increment epoch, clear caches, and disconnect stale WS clients."""
        ok, _result_or_err, new_epoch = self.auth.revoke_and_rotate(self.env_path)
        if not ok:
            return False, 0, new_epoch

        stale_ws: list[ServerConnection] = []
        async with self._clients_lock:
            self._media_registry.clear()
            self._approval_tracker.clear()
            for cli in list(self._clients):
                ep = self._client_epochs.get(cli, 0)
                if not self.auth.is_epoch_active(ep):
                    stale_ws.append(cli)
                    self._clients.discard(cli)
                    self._client_epochs.pop(cli, None)

        for sws in stale_ws:
            await self._unsubscribe_live_screen(sws)

        if stale_ws:
            await asyncio.gather(
                *(
                    asyncio.wait_for(sws.close(code=4001, reason="Revoked"), timeout=0.6)
                    for sws in stale_ws
                ),
                return_exceptions=True,
            )
        return True, len(stale_ws), new_epoch

    async def _safe_send(self, ws: ServerConnection, raw_or_dict: str | dict[str, Any], timeout: float = 4.0) -> bool:
        raw = raw_or_dict if isinstance(raw_or_dict, str) else json.dumps(raw_or_dict, ensure_ascii=False)
        try:
            await asyncio.wait_for(ws.send(raw), timeout=timeout)
            return True
        except Exception:
            async with self._clients_lock:
                self._clients.discard(ws)
                self._client_epochs.pop(ws, None)
            try:
                await ws.close()
            except Exception:
                pass
            return False

    async def _broadcast(self, payload: dict[str, Any]) -> None:
        async with self._clients_lock:
            clients_snapshot = [
                c
                for c in self._clients
                if self.auth.is_epoch_active(self._client_epochs.get(c, 0))
            ]
        if not clients_snapshot:
            return
        raw = json.dumps(payload, ensure_ascii=False)
        if len(clients_snapshot) == 1:
            await self._safe_send(clients_snapshot[0], raw, timeout=3.5)
            return
        await asyncio.gather(
            *(self._safe_send(c, raw, timeout=3.5) for c in clients_snapshot),
            return_exceptions=True,
        )

    def _http_response(
        self,
        status: int,
        reason: str,
        body: bytes,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
    ) -> Response:
        hdrs = Headers(
            [
                ("Content-Type", content_type),
                ("Content-Length", str(len(body))),
                ("X-Content-Type-Options", "nosniff"),
            ]
        )
        if extra_headers:
            for k, v in extra_headers.items():
                hdrs[k] = v
        return Response(status, reason, hdrs, body)

    async def _process_request(
        self, connection: ServerConnection, request: Request
    ) -> Response | None:
        parsed = urlsplit(request.path)
        path = parsed.path

        if path == "/ws":
            return None

        # Never expose control-plane admin routes on the public/business listener!
        if path.startswith("/admin"):
            return self._http_response(404, "Not Found", b"Not Found", "text/plain")

        req_method = str(getattr(request, "method", "GET") or "GET").upper()
        if req_method not in {"GET", "HEAD"}:
            return self._http_response(405, "Method Not Allowed", b"Method Not Allowed", "text/plain")

        if path in {"/", "/index.html"}:
            html_file = STATIC_DIR / "index.html"
            if not html_file.is_file():
                return self._http_response(404, "Not Found", b"Missing index.html", "text/plain")
            body = await asyncio.to_thread(html_file.read_bytes)
            extra_hdrs: dict[str, str] = {"Cache-Control": "no-cache"}
            ip = self._client_ip(connection, request.headers)
            qs = parse_qs(parsed.query)
            pair_code = (qs.get("pair") or [""])[0].strip()
            cand_tok = (qs.get("token") or [""])[0].strip()

            xf_proto = (
                request.headers.get("X-Forwarded-Proto", "").strip().lower()
                if self.config.trust_cf_proxy_headers
                else ""
            )
            is_https = (xf_proto == "https") or self.config.public_base_url.startswith("https://")
            sec_attr = "; Secure" if is_https else ""

            sess_tok = ""
            if pair_code:
                ok_pair, issued_sess, _ = self.auth.exchange_pairing_code(pair_code, ip)
                if ok_pair:
                    sess_tok = issued_sess
            elif cand_tok:
                ok_tok, _ = self.auth.verify_credential(cand_tok, ip, record_failure=True)
                if ok_tok:
                    sess_tok = self.auth.issue_session_token()

            if sess_tok:
                extra_hdrs["Set-Cookie"] = (
                    f"stayy_session={sess_tok}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax{sec_attr}"
                )

            return self._http_response(
                200,
                "OK",
                body,
                "text/html; charset=utf-8",
                extra_hdrs,
            )

        if path == "/manifest.json":
            manifest = {
                "name": "Stayy",
                "short_name": "Stayy",
                "description": "Local-first AI Coding & Precision PC Remote Hub",
                "start_url": "./",
                "display": "standalone",
                "background_color": "#000000",
                "theme_color": "#000000",
                "orientation": "portrait-primary",
                "icons": [
                    {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
                    {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"},
                ],
            }
            body = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
            return self._http_response(
                200,
                "OK",
                body,
                "application/manifest+json",
                {"Cache-Control": "private, no-cache"},
            )

        if path == "/sw.js":
            return self._http_response(
                200,
                "OK",
                SERVICE_WORKER_JS.encode("utf-8"),
                "application/javascript; charset=utf-8",
                {"Cache-Control": "no-cache"},
            )

        if path == "/ping":
            body = json.dumps(
                {
                    "ok": True,
                    "service": "stayy",
                    "host_id": self.auth.host_id,
                    "ts": int(time.time() * 1000),
                }
            ).encode("utf-8")
            hdrs_ping = {"Cache-Control": "no-store", **self._cors_headers(request.headers)}
            return self._http_response(
                200,
                "OK",
                body,
                "application/json; charset=utf-8",
                hdrs_ping,
            )

        if path in {"/apple-touch-icon.png", "/icon-192.png", "/icon-512.png"}:
            icon_file = ASSETS_DIR / path.lstrip("/")
            if not icon_file.is_file() and path == "/apple-touch-icon.png":
                icon_file = ASSETS_DIR / "icon-192.png"
            if icon_file.is_file():
                body = await asyncio.to_thread(icon_file.read_bytes)
                return self._http_response(
                    200,
                    "OK",
                    body,
                    "image/png",
                    {"Cache-Control": "max-age=86400", **self._cors_headers(request.headers)},
                )

        if path == "/favicon.ico":
            ico_file = ASSETS_DIR / "app.ico"
            if ico_file.is_file():
                body = await asyncio.to_thread(ico_file.read_bytes)
                return self._http_response(200, "OK", body, "image/x-icon", {"Cache-Control": "max-age=86400"})

        if path.startswith("/dl/"):
            cors = self._cors_headers(request.headers)
            ip = self._client_ip(connection, request.headers)
            cred, ticket = self._extract_credential_and_ticket(parsed.query, request.headers)
            media_id = path.removeprefix("/dl/").strip("/")

            ok_cred = bool(cred) and self.auth.verify_credential(cred, ip, record_failure=True)[0]
            ok_ticket = bool(ticket) and self.auth.verify_media_ticket(ticket, media_id)
            if not (ok_cred or ok_ticket):
                if not cred:
                    self.auth.record_auth_failure(ip)
                return self._http_response(
                    401,
                    "Unauthorized",
                    b"",
                    "application/octet-stream",
                    {"Cache-Control": "no-store", **cors},
                )

            target = self._media_registry.get(media_id)
            if target is None or not is_safe_outbound_file(target, image_only=False):
                return self._http_response(
                    404,
                    "Not Found",
                    b"",
                    "text/plain",
                    {"Cache-Control": "no-store", **cors},
                )

            body = await asyncio.to_thread(target.read_bytes)
            mime, _ = mimetypes.guess_type(str(target))
            mime = mime or "application/octet-stream"
            disp_type = "inline" if mime.startswith("image/") else "attachment"
            encoded_name = quote(target.name)
            return self._http_response(
                200,
                "OK",
                body,
                mime,
                {
                    "Content-Disposition": f"{disp_type}; filename*=UTF-8''{encoded_name}",
                    "Cache-Control": "private, no-store",
                    **cors,
                },
            )

        return self._http_response(404, "Not Found", b"Not Found", "text/plain")

    def _effective_slot_identity(self, slot: str, session: AgySession) -> tuple[str, str]:
        """Return `(active_conversation_id, active_store)` without leaking background CLI IDs onto empty Home slots."""
        meta = self._slot_meta.get(slot, {})
        meta_cid = str(meta.get("conversation_id") or "")
        meta_store = str(meta.get("store") or "")
        has_slot_activity = bool(self._slot_history.get(slot)) or (slot in self._slot_inflight)

        if meta_cid:
            return meta_cid, (meta_store or session.linked_store or "ide")
        if meta_store in {"ide", "codex"}:
            return (str(session.linked_ide_id or "") if has_slot_activity else ""), meta_store
        if meta_store == "cli":
            return (str(session.conversation_id or "") if has_slot_activity else ""), "cli"
        if not has_slot_activity:
            default_store = "ide" if self._pc_window_new_sender is not None else ""
            return "", default_store
        active_cid = str(session.linked_ide_id or session.conversation_id or "")
        active_store = str(
            session.linked_store if session.linked_ide_id else ("cli" if session.conversation_id else "")
        )
        return active_cid, active_store

    def _build_backend_status(self) -> dict[str, bool]:
        local_app_data = os.getenv("LOCALAPPDATA", "")
        ide_exe = (
            Path(local_app_data) / "Programs" / "Antigravity" / "Antigravity.exe"
            if local_app_data
            else Path("__missing__")
        )
        ide_root = self.ide_store_dir if self.ide_store_dir is not None else _default_ide_dir()
        ide_avail = bool(
            self._pc_window_sender is not None
            or ide_exe.is_file()
            or (ide_root / "brain").is_dir()
        )
        codex_cli = self._codex_cli_override or find_codex_cli_executable()
        codex_avail = bool(codex_cli is not None)
        agy_exe = resolve_agy_executable(self.config.agy_executable)
        cli_avail = bool(shutil.which(agy_exe) or Path(agy_exe).is_file())
        return {
            "ide_available": ide_avail,
            "codex_available": codex_avail,
            "cli_available": cli_avail,
        }

    def _build_capabilities(self) -> dict[str, Any]:
        bstat = self._build_backend_status()
        remote_enabled = (sys.platform == "win32") or self._custom_desktop_input
        return {
            "ide": {
                "chat": bstat["ide_available"] or self._pc_window_sender is not None,
                "approvals_readonly": sys.platform == "win32",
                "approvals_auto_invoke": False,
                "cancel": self._pc_window_canceller is not None,
            },
            "codex": {
                "chat": bstat["codex_available"],
                "approvals_readonly": False,
                "approvals_auto_invoke": False,
                "cancel": True,
            },
            "cli": {
                "chat": bstat["cli_available"],
                "approvals_readonly": False,
                "approvals_auto_invoke": False,
                "cancel": True,
            },
            "remote_desktop": {
                "enabled": remote_enabled,
                "loupe": True,
                "trackpad": True,
            },
        }

    async def _screen_client_sender(self, ws: ServerConnection, q: asyncio.Queue[dict[str, Any]]) -> None:
        try:
            while True:
                frame = await q.get()
                ep = self._client_epochs.get(ws, 0)
                if not self.auth.is_epoch_active(ep):
                    break
                try:
                    await asyncio.wait_for(ws.send(json.dumps(frame, ensure_ascii=False)), timeout=2.5)
                except Exception:
                    break
        except asyncio.CancelledError:
            raise
        finally:
            await self._unsubscribe_live_screen(ws)

    async def _screen_producer_loop(self) -> None:
        try:
            while True:
                async with self._screen_lock:
                    has_subs = bool(self._screen_subs)
                    interval = self._screen_interval
                if not has_subs:
                    break

                try:
                    shot, cur_info = await asyncio.gather(
                        asyncio.to_thread(self._screen_capturer, PROJECT_INBOX_DIR, 1440, 76),
                        asyncio.to_thread(self._cursor_reader),
                    )
                    frame = {
                        "type": "desktop_frame",
                        **self._media_ref(shot),
                        "ts": int(time.time() * 1000),
                        "cursor": cur_info,
                    }
                    async with self._screen_lock:
                        subs = list(self._screen_subs.items())
                    for ws_cli, q in subs:
                        ep = self._client_epochs.get(ws_cli, 0)
                        if not self.auth.is_epoch_active(ep):
                            continue
                        if q.full():
                            try:
                                q.get_nowait()
                            except asyncio.QueueEmpty:
                                pass
                        try:
                            q.put_nowait(frame)
                        except asyncio.QueueFull:
                            pass
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.debug("Shared live screen producer error: %s", exc)

                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            raise

    async def _subscribe_live_screen(self, ws: ServerConnection, interval: float) -> None:
        clamped = max(0.6, min(5.0, float(interval)))
        async with self._screen_lock:
            self._screen_interval = clamped
            if ws not in self._screen_subs:
                q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1)
                self._screen_subs[ws] = q
                stask = asyncio.create_task(self._screen_client_sender(ws, q))
                self._screen_sender_tasks[ws] = stask
            if self._screen_producer_task is None or self._screen_producer_task.done():
                self._screen_producer_task = asyncio.create_task(self._screen_producer_loop())

    async def _unsubscribe_live_screen(self, ws: ServerConnection) -> None:
        sender_task: asyncio.Task[None] | None = None
        prod_task: asyncio.Task[None] | None = None
        cur_task = asyncio.current_task()
        async with self._screen_lock:
            self._screen_subs.pop(ws, None)
            sender_task = self._screen_sender_tasks.pop(ws, None)
            if not self._screen_subs and self._screen_producer_task is not None:
                prod_task = self._screen_producer_task
                self._screen_producer_task = None

        if sender_task is not None and sender_task is not cur_task:
            sender_task.cancel()
            try:
                await sender_task
            except BaseException:
                pass
        if prod_task is not None and prod_task is not cur_task:
            prod_task.cancel()
            try:
                await prod_task
            except BaseException:
                pass

    async def _handle_ws(self, ws: ServerConnection) -> None:
        req = ws.request
        ip = self._client_ip(ws, req.headers if req else None)
        parsed = urlsplit(req.path if req else "")
        qs = parse_qs(parsed.query)
        q_tok = (qs.get("token") or [""])[0].strip()
        q_pair = (qs.get("pair") or [""])[0].strip()
        cred, _ = self._extract_credential_and_ticket(parsed.query, req.headers if req else None)

        if req is not None:
            origin_hdr = (req.headers.get("Origin") or "").strip()
            host_hdr = (req.headers.get("Host") or "").strip()
            if origin_hdr and not self._is_allowed_origin(origin_hdr, host_hdr):
                logger.warning("Blocked cross-origin WS handshake from Origin=%s (%s)", origin_hdr, ip)
                await ws.close(code=4003, reason="Forbidden Origin")
                return

        conn_epoch = 0
        ok_auth = False
        if q_pair:
            ok_pair, _sess_tok, ep = self.auth.exchange_pairing_code(q_pair, ip)
            if ok_pair:
                ok_auth = True
                conn_epoch = ep
        else:
            tok = q_tok or cred
            ok_auth, conn_epoch = self.auth.verify_credential(tok, ip, record_failure=True)

        if not ok_auth or not self.auth.is_epoch_active(conn_epoch):
            logger.warning("Rejected unauthorized Stayy WS connection from %s", ip)
            await ws.close(code=4001, reason="Unauthorized")
            return

        if self._on_ws_pre_register is not None:
            try:
                await self._on_ws_pre_register(ws)
            except Exception:
                pass

        # CRITICAL RACE CLOSURE: re-check active epoch inside _clients_lock right before registering `ws`!
        async with self._clients_lock:
            if not self.auth.is_epoch_active(conn_epoch):
                await ws.close(code=4001, reason="Revoked")
                return
            self._clients.add(ws)
            self._client_epochs[ws] = conn_epoch

        uploads: dict[str, _UploadState] = {}
        logger.info("Stayy 客户端已连接 (%s, epoch=%d)", ip, conn_epoch)
        try:
            slot = self._active_slot
            session = self._session_for_slot(slot)
            meta = self._slot_meta.get(slot, {})
            active_cid, active_store = self._effective_slot_identity(slot, session)
            pub_inflight = self._public_inflight(slot)
            hello_model = (
                "Antigravity 电脑端"
                if active_store == "ide"
                else ("Codex 电脑端" if active_store == "codex" else (session.model or "default"))
            )
            await self._safe_send(
                ws,
                {
                    "type": "hello",
                    "host_id": self.auth.host_id,
                    "auth_epoch": conn_epoch,
                    "nav_seq": self._nav_seq,
                    "capabilities": self._build_capabilities(),
                    "backend_status": self._build_backend_status(),
                    "slot": slot,
                    "model": hello_model,
                    "workspace": str(session.workspace),
                    "active_conversation_id": active_cid,
                    "active_title": meta.get("title") or session.active_title or "",
                    "active_store": active_store,
                    "busy": pub_inflight is not None,
                    "inflight": pub_inflight,
                    "slots_overview": self._build_slots_overview(),
                    "cooldowns": session.failover_pool.cooldown_summary(),
                    "history": self._slot_history.get(slot, []),
                },
            )

            async for raw in ws:
                if not self.auth.is_epoch_active(conn_epoch):
                    await ws.close(code=4001, reason="Revoked")
                    break
                if not isinstance(raw, str):
                    continue
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(msg, dict):
                    continue

                if not self.auth.is_epoch_active(conn_epoch):
                    await ws.close(code=4001, reason="Revoked")
                    break

                mtype = msg.get("type")

                if mtype == "ping":
                    await self._safe_send(ws, {"type": "pong", "ts": msg.get("ts")})

                elif mtype == "desktop_frame":
                    if not self._build_capabilities()["remote_desktop"]["enabled"]:
                        await self._safe_send(
                            ws,
                            {"type": "toast", "level": "err", "text": "当前主机不支持远程桌面抓取", "code": "capabilities_denied"},
                        )
                        continue
                    try:
                        shot, cur_info = await asyncio.gather(
                            asyncio.to_thread(self._screen_capturer, PROJECT_INBOX_DIR, 1440, 80),
                            asyncio.to_thread(self._cursor_reader),
                        )
                        await self._safe_send(
                            ws,
                            {
                                "type": "desktop_frame",
                                **self._media_ref(shot),
                                "ts": int(time.time() * 1000),
                                "cursor": cur_info,
                            },
                        )
                    except Exception as exc:
                        await self._safe_send(ws, {"type": "toast", "level": "err", "text": f"截屏失败：{exc}"})

                elif mtype == "live_screen":
                    enable = bool(msg.get("enable"))
                    if enable:
                        if not self._build_capabilities()["remote_desktop"]["enabled"]:
                            await self._safe_send(
                                ws,
                                {"type": "toast", "level": "err", "text": "当前主机未启用远程桌面画面流", "code": "capabilities_denied"},
                            )
                            continue
                        interval = float(msg.get("interval_ms") or 750) / 1000.0
                        await self._subscribe_live_screen(ws, interval)
                    else:
                        await self._unsubscribe_live_screen(ws)

                elif mtype == "upload_init":
                    if len(uploads) >= 8:
                        await self._safe_send(ws, {"type": "toast", "level": "err", "text": "同时上传文件过多，请稍候"})
                        continue
                    uid = str(msg.get("upload_id") or uuid.uuid4().hex)
                    if uid in uploads:
                        uploads.pop(uid).abort()
                    safe_name = sanitize_filename(str(msg.get("name") or "upload.bin"))
                    size = int(msg.get("size") or 0)
                    if size < 0 or size > MAX_UPLOAD_BYTES:
                        await self._safe_send(ws, {"type": "toast", "level": "err", "text": "文件超过 100MB 上限"})
                        continue
                    PROJECT_INBOX_DIR.mkdir(parents=True, exist_ok=True)
                    dest = PROJECT_INBOX_DIR / f"pwa_{int(time.time())}_{uuid.uuid4().hex[:5]}_{safe_name}"
                    uploads[uid] = _UploadState(dest, safe_name, size)
                    await self._safe_send(ws, {"type": "upload_ack", "upload_id": uid})

                elif mtype == "upload_chunk":
                    uid = str(msg.get("upload_id") or "")
                    state = uploads.get(uid)
                    if state is None:
                        continue
                    try:
                        chunk_bytes = base64.b64decode(str(msg.get("data") or ""))
                        await asyncio.to_thread(state.write, chunk_bytes)
                        await self._safe_send(
                            ws,
                            {
                                "type": "upload_progress",
                                "upload_id": uid,
                                "written": state.written,
                                "total": state.expected_size,
                            },
                        )
                    except Exception as exc:
                        state.abort()
                        uploads.pop(uid, None)
                        await self._safe_send(ws, {"type": "toast", "level": "err", "text": f"上传出错：{exc}"})

                elif mtype == "upload_complete":
                    uid = str(msg.get("upload_id") or "")
                    state = uploads.pop(uid, None)
                    if state is None:
                        continue
                    try:
                        final_path = await asyncio.to_thread(state.finalize)
                    except Exception as exc:
                        await self._safe_send(ws, {"type": "toast", "level": "err", "text": f"上传校验未通过：{exc}"})
                        continue
                    prune_inbox(PROJECT_INBOX_DIR, keep=40, prefix_only="pwa_")
                    is_img = final_path.suffix.lower() in ALLOWED_IMAGE_EXTS
                    await self._safe_send(
                        ws,
                        {
                            "type": "upload_done",
                            "upload_id": uid,
                            **self._media_ref(final_path),
                            "name": state.name,
                            "path": str(final_path),
                            "is_image": is_img,
                        },
                    )

                elif mtype == "cancel":
                    cur_slot = str(msg.get("slot") or self._active_slot)
                    req_mid = str(msg.get("msg_id") or "")
                    inf = self._slot_inflight.get(cur_slot)
                    if req_mid and inf and str(inf.get("msg_id") or "") != req_mid:
                        await self._safe_send(
                            ws, {"type": "toast", "level": "info", "text": "该轮生成已结束。"}
                        )
                        continue
                    killed = False
                    if inf and inf.get("msg_id"):
                        self._cancelled_reply_ids.add(str(inf["msg_id"]))
                    if inf and inf.get("pc_ide_cid") and self._pc_window_canceller is not None:
                        killed = await asyncio.to_thread(self._pc_window_canceller, str(inf["pc_ide_cid"])) or True
                    proc_cdx = self._slot_codex_procs.get(cur_slot)
                    if proc_cdx is not None and proc_cdx.returncode is None:
                        try:
                            if sys.platform == "win32" and proc_cdx.pid:
                                await asyncio.to_thread(_kill_process_tree_win32, proc_cdx.pid)
                            else:
                                proc_cdx.terminate()
                            killed = True
                        except Exception:
                            pass
                    killed = (await self._session_for_slot(cur_slot).cancel_current()) or killed
                    note = "已停止当前生成。" if killed else "当前没有运行中的任务。"
                    await self._safe_send(ws, {"type": "toast", "level": "info", "text": note})

                elif mtype == "list_conversations":
                    await self._handle_list_conversations(ws)

                elif mtype == "select_conversation":
                    max_m = int(msg.get("max_messages") or 200)
                    t = asyncio.create_task(
                        self._handle_select_conversation(
                            ws,
                            str(msg.get("conversation_id") or ""),
                            str(msg.get("store") or "auto"),
                            only_refresh=bool(msg.get("only_refresh", False)),
                            max_messages=max(50, min(3000, max_m)),
                        )
                    )
                    self._tasks.add(t)
                    t.add_done_callback(self._tasks.discard)

                elif mtype == "refresh_conversation":
                    cur_slot = self._active_slot
                    if cur_slot in self._slot_inflight:
                        continue
                    meta_cur = self._slot_meta.get(cur_slot, {})
                    target_cid = str(msg.get("conversation_id") or meta_cur.get("conversation_id") or "")
                    target_store = str(msg.get("store") or meta_cur.get("store") or "auto")
                    if target_cid:
                        t = asyncio.create_task(
                            self._handle_select_conversation(
                                ws, target_cid, target_store, only_refresh=True, max_messages=200
                            )
                        )
                        self._tasks.add(t)
                        t.add_done_callback(self._tasks.discard)

                elif mtype == "new_conversation":
                    t = asyncio.create_task(
                        self._handle_new_conversation(
                            ws,
                            str(msg.get("workspace") or ""),
                            str(msg.get("target") or "ide"),
                            str(msg.get("req_id") or ""),
                            open_pc_window=bool(msg.get("open_pc_window", True)),
                            silent_keep_view=bool(msg.get("silent_keep_view", False)),
                        )
                    )
                    self._tasks.add(t)
                    t.add_done_callback(self._tasks.discard)

                elif mtype == "workspace_inspect":
                    await self._handle_workspace_inspect(ws, str(msg.get("rel_dir") or ""))

                elif mtype == "workspace_diff":
                    await self._handle_workspace_diff(ws, str(msg.get("path") or ""))

                elif mtype == "workspace_file":
                    await self._handle_workspace_file(ws, str(msg.get("path") or ""))

                elif mtype == "ide_actions_inspect":
                    req_cid = str(msg.get("conversation_id") or "")
                    actions = await asyncio.to_thread(self._ide_actions_inspector, req_cid)
                    if self.bark_notifier.enabled and actions:
                        ekeys = [str(a.get("event_key") or "") for a in actions if isinstance(a, dict) and a.get("event_key")]
                        if ekeys:
                            await asyncio.to_thread(self.bark_notifier.notify_for_events, ekeys)
                    await self._safe_send(
                        ws,
                        {
                            "type": "ide_actions",
                            "mode": "manual_screen_only",
                            "actions": actions,
                        },
                    )

                elif mtype == "ide_action_invoke":
                    # Branch B hard enforcement: NEVER perform blind remote button click; zero desktop input!
                    ok, code, note = deny_auto_invoke()
                    await self._safe_send(
                        ws,
                        {"type": "ide_action_result", "ok": ok, "code": code, "note": note},
                    )

                elif mtype == "desktop_input":
                    if not self._build_capabilities()["remote_desktop"]["enabled"]:
                        await self._safe_send(
                            ws,
                            {"type": "toast", "level": "err", "text": "当前主机未启用远程桌面输入", "code": "capabilities_denied"},
                        )
                        continue
                    act_kind = str(msg.get("action") or "")
                    kname = str(msg.get("key") or "")
                    txt_payload = str(msg.get("text") or "")
                    try:
                        xr = 0.5 if act_kind in {"key", "hotkey", "type_text"} else float(msg.get("x_ratio") if msg.get("x_ratio") is not None else 0.5)
                        yr = 0.5 if act_kind in {"key", "hotkey", "type_text"} else float(msg.get("y_ratio") if msg.get("y_ratio") is not None else 0.5)
                    except (TypeError, ValueError):
                        await self._safe_send(ws, {"type": "toast", "level": "err", "text": "触控坐标参数无效"})
                        continue

                    if not self.auth.is_epoch_active(conn_epoch):
                        await ws.close(code=4001, reason="Revoked")
                        break

                    def _invoke_desk_handler() -> tuple[bool, str]:
                        if not self.auth.is_epoch_active(conn_epoch):
                            return (False, "配对已撤销，动作已取消")
                        try:
                            return self._desktop_input_handler(act_kind, xr, yr, kname, txt_payload)
                        except TypeError:
                            return self._desktop_input_handler(act_kind, xr, yr, kname)

                    ok, note = await asyncio.to_thread(_invoke_desk_handler)
                    quiet_act = bool(msg.get("quiet")) or act_kind in {"move", "scroll_up", "scroll_down"}
                    if not ok or (not quiet_act and act_kind in {"hotkey", "type_text", "right_click", "double_click"}):
                        await self._safe_send(
                            ws,
                            {"type": "toast", "level": "info" if ok else "err", "text": note},
                        )
                    async with self._screen_lock:
                        has_live = ws in self._screen_subs
                    if ok and not has_live:
                        await asyncio.sleep(0.06 if act_kind == "move" else 0.16)
                        try:
                            shot, cur_info = await asyncio.gather(
                                asyncio.to_thread(self._screen_capturer, PROJECT_INBOX_DIR, 1440, 80),
                                asyncio.to_thread(self._cursor_reader),
                            )
                            await self._safe_send(
                                ws,
                                {
                                    "type": "desktop_frame",
                                    **self._media_ref(shot),
                                    "ts": int(time.time() * 1000),
                                    "cursor": cur_info,
                                },
                            )
                        except Exception:
                            pass

                elif mtype == "pc_system_inspect":
                    session_cur = self._session_for_slot(self._active_slot)
                    sys_info, clip_info = await asyncio.gather(
                        asyncio.to_thread(self._pc_system_inspector, session_cur.workspace),
                        asyncio.to_thread(self._pc_clipboard_getter),
                    )
                    await self._safe_send(
                        ws,
                        {"type": "pc_system_state", "system": sys_info, "clipboard": clip_info},
                    )

                elif mtype == "pc_clipboard_get":
                    clip_info = await asyncio.to_thread(self._pc_clipboard_getter)
                    await self._safe_send(ws, {"type": "pc_clipboard", **clip_info})

                elif mtype == "pc_clipboard_set":
                    ok, note = await asyncio.to_thread(self._pc_clipboard_setter, str(msg.get("text") or ""))
                    await self._safe_send(
                        ws,
                        {"type": "toast", "level": "info" if ok else "err", "text": note},
                    )

                elif mtype == "chat":
                    req_slot = str(msg.get("slot") or self._active_slot)
                    t = asyncio.create_task(self._handle_chat(ws, msg, req_slot))
                    self._tasks.add(t)
                    t.add_done_callback(self._tasks.discard)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self._unsubscribe_live_screen(ws)
            for st in uploads.values():
                st.abort()
            async with self._clients_lock:
                self._clients.discard(ws)
                self._client_epochs.pop(ws, None)
            logger.info("Stayy 客户端已断开 (%s)", ip)

    def _safe_file_size(self, path: Path) -> int:
        try:
            return path.stat().st_size
        except OSError:
            return 0

    async def _handle_workspace_inspect(self, ws: ServerConnection, rel_dir: str) -> None:
        session = self._session_for_slot(self._active_slot)
        git_info, dir_info = await asyncio.gather(
            asyncio.to_thread(inspect_workspace_git, session.workspace),
            asyncio.to_thread(list_workspace_directory, session.workspace, rel_dir),
        )
        await self._safe_send(
            ws,
            {
                "type": "workspace_state",
                "workspace": str(session.workspace),
                "git": git_info,
                "dir": dir_info,
            },
        )

    async def _handle_workspace_diff(self, ws: ServerConnection, rel_path: str) -> None:
        session = self._session_for_slot(self._active_slot)
        diff_res = await asyncio.to_thread(get_workspace_file_diff, session.workspace, rel_path)
        await self._safe_send(ws, {"type": "workspace_diff", **diff_res})

    async def _handle_workspace_file(self, ws: ServerConnection, rel_path: str) -> None:
        session = self._session_for_slot(self._active_slot)
        prev = await asyncio.to_thread(read_workspace_file_preview, session.workspace, rel_path)
        if prev.get("ok"):
            resolved = _resolve_inside_workspace(session.workspace, rel_path)
            if resolved is not None and is_safe_outbound_file(resolved, image_only=False):
                prev.update(self._media_ref(resolved))
        await self._safe_send(ws, {"type": "workspace_file", **prev})

    def _convert_detail_to_pwa_history(self, detail: ConversationDetail, model_label: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        origin_tag = (
            "Antigravity 电脑端"
            if detail.store == "ide"
            else ("Codex 电脑端" if detail.store == "codex" else model_label)
        )
        for idx, m in enumerate(detail.messages):
            if m.role == "user":
                atts = []
                for p in m.image_paths:
                    if is_safe_outbound_file(p, image_only=True):
                        atts.append(self._media_ref(p, name=p.name, is_image=True))
                out.append(
                    {
                        "role": "user",
                        "id": f"hist-u-{detail.conversation_id[:8]}-{m.step_index}-{idx}",
                        "text": m.text,
                        "attachments": atts,
                        "ts": m.ts_ms,
                    }
                )
            else:
                clean_txt, extra_imgs, extra_files = extract_pwa_media_and_text(m.text)
                imgs = []
                seen_paths: set[Path] = set()
                for p in [*m.image_paths, *extra_imgs]:
                    if is_safe_outbound_file(p, image_only=True):
                        rp = p.resolve()
                        if rp not in seen_paths:
                            seen_paths.add(rp)
                            imgs.append(self._media_ref(rp, name=rp.name))
                fls = [
                    self._media_ref(p, name=p.name, size=self._safe_file_size(p))
                    for p in extra_files
                ]
                out.append(
                    {
                        "role": "assistant",
                        "id": f"hist-a-{detail.conversation_id[:8]}-{m.step_index}-{idx}",
                        "text": clean_txt,
                        "images": imgs,
                        "files": fls,
                        "steps": list(m.steps),
                        "model": origin_tag,
                        "ts": m.ts_ms,
                    }
                )
        return out

    async def _handle_list_conversations(self, ws: ServerConnection) -> None:
        session = self._session_for_slot(self._active_slot)
        meta = self._slot_meta.get(self._active_slot, {})
        items = await asyncio.to_thread(
            list_local_conversations,
            500,
            self.ide_store_dir,
            self.cli_store_dir,
            self.codex_store_dir,
        )
        # Hide internal CLI continuation child conversations that are already merged into their parent PC chat
        hidden_cont_ids = set(self._continuation_map.values())
        visible_items = []
        for it in items:
            if it.store == "cli" and it.conversation_id in hidden_cont_ids:
                continue
            slot_candidate = f"{it.store}:{it.conversation_id}"
            d = it.to_dict()
            if slot_candidate in self._slot_inflight:
                d["running"] = True
            visible_items.append(d)

        workspaces = await asyncio.to_thread(
            list_recent_workspaces,
            session.workspace,
            self.ide_store_dir,
            self.cli_store_dir,
            self.codex_store_dir,
        )
        active_cid_for_list, _ = self._effective_slot_identity(self._active_slot, session)
        await self._safe_send(
            ws,
            {
                "type": "conversations_list",
                "active_id": active_cid_for_list,
                "current_workspace": str(session.workspace),
                "items": visible_items,
                "workspaces": workspaces,
            },
        )

    async def _handle_select_conversation(
        self,
        ws: ServerConnection,
        conversation_id: str,
        store: str,
        *,
        only_refresh: bool = False,
        max_messages: int = 200,
    ) -> None:
        nav_token = 0
        if not only_refresh:
            self._nav_seq += 1
            nav_token = self._nav_seq

        detail = await asyncio.to_thread(
            load_conversation_detail,
            conversation_id,
            store,
            max_messages,
            self.ide_store_dir,
            self.cli_store_dir,
            self.codex_store_dir,
        )
        if not only_refresh and nav_token != self._nav_seq:
            return
        if detail is None:
            await self._safe_send(ws, {"type": "toast", "level": "err", "text": "未找到该对话记录"})
            return

        slot_key = f"{detail.store}:{detail.conversation_id}"
        if only_refresh and self._active_slot != slot_key:
            return
        session = self._session_for_slot(slot_key)
        slot_is_running = slot_key in self._slot_inflight

        if not only_refresh:
            self._active_slot = slot_key
            self._unread_slots.pop(slot_key, None)
            self._slot_meta[slot_key] = {
                "conversation_id": detail.conversation_id,
                "title": detail.title,
                "store": detail.store,
            }
            # Only initialize/attach the slot's AgySession if it is NOT currently executing a turn!
            if not slot_is_running:
                if detail.store == "cli":
                    if session.conversation_id != detail.conversation_id:
                        await session.attach_cli_conversation(
                            detail.conversation_id, workspace=detail.workspace, title=detail.title
                        )
                    self._ide_watch_sig = ("", "", 0, 0)
                else:
                    handoff = build_ide_handoff_context(detail)
                    if session.linked_ide_id != detail.conversation_id:
                        await session.attach_ide_conversation(
                            detail.conversation_id,
                            handoff_context=handoff,
                            workspace=detail.workspace,
                            title=detail.title,
                            store=detail.store,
                        )
                    elif not session.conversation_id:
                        session._pending_handoff_context = handoff
                    sig = await asyncio.to_thread(
                        get_transcript_signature,
                        detail.conversation_id,
                        detail.store,
                        self.ide_store_dir,
                        self.cli_store_dir,
                        self.codex_store_dir,
                    )
                    if nav_token != self._nav_seq:
                        return
                    self._ide_watch_sig = (detail.store, detail.conversation_id, sig[0], sig[1])

        # If this slot already has an in-memory turn running, keep its live history intact!
        if slot_is_running and self._slot_history.get(slot_key):
            loaded_history = self._slot_history[slot_key]
        else:
            loaded_history = self._convert_detail_to_pwa_history(detail, session.model or "default")
            # Only merge standalone CLI continuation turns when running without a live PC window sender
            # (never append forked headless CLI turns on top of live PC IDE chats!)
            allow_cont_merge = (detail.store == "codex") or (detail.store == "ide" and self._pc_window_sender is None)
            if allow_cont_merge:
                cont_cid = (
                    self._continuation_map.get(f"{detail.store}:{detail.conversation_id}")
                    or self._continuation_map.get(detail.conversation_id)
                    or session.conversation_id
                )
                if cont_cid:
                    cont_detail = await asyncio.to_thread(
                        load_conversation_detail,
                        cont_cid,
                        "cli",
                        100,
                        self.ide_store_dir,
                        self.cli_store_dir,
                        self.codex_store_dir,
                    )
                    if not only_refresh and nav_token != self._nav_seq:
                        return
                    if cont_detail and cont_detail.messages:
                        cont_hist = self._convert_detail_to_pwa_history(cont_detail, session.model or "default")
                        _extend_deduplicated_turns(loaded_history, cont_hist)
                        if any(int(x.get("ts") or 0) > 0 for x in loaded_history) and len(loaded_history) > 1:
                            # Preserve monotone order even if individual items lack `ts` by carrying forward previous timestamp
                            running_ts = 0
                            keyed: list[tuple[int, int, dict[str, Any]]] = []
                            for idx_item, item in enumerate(loaded_history):
                                raw_ts = int(item.get("ts") or 0)
                                if raw_ts > 0:
                                    running_ts = raw_ts
                                keyed.append((running_ts, idx_item, item))
                            loaded_history = [it for _, _, it in sorted(keyed, key=lambda t: (t[0], t[1]))]
                    if self._slot_local_turns.get(slot_key):
                        _extend_deduplicated_turns(loaded_history, self._slot_local_turns[slot_key])
                elif self._slot_local_turns.get(slot_key):
                    _extend_deduplicated_turns(loaded_history, self._slot_local_turns[slot_key])
            elif self._slot_local_turns.get(slot_key) and detail.store != "ide":
                _extend_deduplicated_turns(loaded_history, self._slot_local_turns[slot_key])
            self._slot_history[slot_key] = loaded_history

        if (not only_refresh and nav_token != self._nav_seq) or (only_refresh and self._active_slot != slot_key):
            return

        await self._broadcast(
            {
                "type": "conversation_loaded",
                "nav_seq": self._nav_seq,
                "slot": slot_key,
                "conversation_id": detail.conversation_id,
                "title": detail.title,
                "store": detail.store,
                "running": detail.running or slot_is_running,
                "busy": slot_is_running,
                "inflight": self._public_inflight(slot_key),
                "workspace": str(session.workspace),
                "silent": only_refresh,
                "has_more": detail.has_more,
                "total_messages": detail.total_messages,
                "slots_overview": self._build_slots_overview(),
                "history": loaded_history,
            }
        )

    async def _handle_new_conversation(
        self,
        ws: ServerConnection,
        workspace: str,
        target: str = "ide",
        req_id: str = "",
        *,
        open_pc_window: bool = True,
        silent_keep_view: bool = False,
    ) -> None:
        self._nav_seq += 1
        nav_token = self._nav_seq
        new_slot = f"new:{uuid.uuid4().hex[:8]}"
        session = self._session_for_slot(new_slot)
        try:
            await session.start_new_conversation(workspace=workspace)
        except FileNotFoundError as exc:
            await self._safe_send(ws, {"type": "toast", "level": "err", "text": str(exc), "req_id": req_id})
            return

        if nav_token != self._nav_seq:
            return

        req_target = (target or "ide").strip().lower()
        store_mode = ""
        title_label = "Stayy"
        toast_note = ""

        if req_target == "ide" and not open_pc_window:
            store_mode = "ide" if self._pc_window_new_sender is not None else ""
            title_label = "Stayy"
        elif req_target == "ide" and self._pc_window_new_opener is not None:
            opened, open_note = await asyncio.to_thread(self._pc_window_new_opener)
            if nav_token != self._nav_seq:
                return
            if opened:
                store_mode = "ide"
                title_label = "新建电脑对话"
                toast_note = "已在电脑端打开新对话窗口"
            else:
                store_mode = "ide" if self._pc_window_new_sender is not None else ""
                toast_note = f"提示：{open_note}，发消息时将自动尝试连接"
        elif req_target == "codex":
            store_mode = "codex"
            title_label = "新建 Codex 对话"
            toast_note = "已准备新建 Codex 电脑会话"
        elif req_target == "cli":
            store_mode = "cli"
            title_label = "新建远程会话"

        self._active_slot = new_slot
        self._slot_history[new_slot] = []
        self._slot_meta[new_slot] = {"conversation_id": "", "title": title_label, "store": store_mode}
        self._ide_watch_sig = ("", "", 0, 0)

        await self._broadcast(
            {
                "type": "clear_history",
                "nav_seq": self._nav_seq,
                "slot": new_slot,
                "req_id": req_id,
                "keep_view": silent_keep_view,
            }
        )
        await self._broadcast_slots_overview()
        await self._broadcast(
            {
                "type": "meta_update",
                "slot": new_slot,
                "model": (
                    "Antigravity 电脑端"
                    if store_mode == "ide"
                    else ("Codex 电脑端" if store_mode == "codex" else (session.model or "default"))
                ),
                "workspace": str(session.workspace),
                "active_conversation_id": "",
                "active_title": title_label,
                "active_store": store_mode,
                "busy": False,
            }
        )
        if toast_note and not silent_keep_view:
            await self._safe_send(ws, {"type": "toast", "level": "info", "text": toast_note})

    async def _stream_pc_ide_transcript_until_idle(
        self,
        *,
        chat_slot: str = "",
        ide_root: Path,
        ide_cid: str,
        baseline_lines: int,
        base_snap: dict[str, Any],
        reply_id: str,
        inflight_state: dict[str, Any],
        turn_start_sec: float,
        on_delta: Callable[[str], Any],
        on_reset: Callable[[], Any],
        on_tool: Callable[[str], Any],
    ) -> tuple[TurnResult, list[Path]] | None:
        inflight_state["pc_ide_cid"] = ide_cid
        poll_sec = max(0.08, float(self.pc_ide_poll_interval))
        accept_deadline = time.monotonic() + max(0.5, float(self.pc_ide_accept_timeout))
        overall_deadline = time.monotonic() + max(30.0, float(self.config.agy_timeout_seconds))
        last_sig: tuple[int, int, int, bool] = (
            baseline_lines,
            int(base_snap.get("mtime_ns") or 0),
            int(base_snap.get("size") or 0),
            bool(base_snap.get("db_running")),
        )
        last_change_mono = time.monotonic()
        emitted_text = ""
        last_tool = ""
        final_snap = base_snap

        while time.monotonic() < overall_deadline:
            cur_reply_id = str(inflight_state.get("msg_id") or reply_id)
            if cur_reply_id in self._cancelled_reply_ids:
                final_snap = await asyncio.to_thread(
                    read_ide_live_turn_snapshot, ide_root, ide_cid, baseline_lines
                )
                return (
                    TurnResult(
                        status="CANCELLED",
                        response=str(final_snap.get("text") or emitted_text),
                        conversation_id=ide_cid,
                        active_model="Antigravity 电脑端",
                    ),
                    list(final_snap.get("images") or []),
                )

            await asyncio.sleep(poll_sec)
            snap = await asyncio.to_thread(read_ide_live_turn_snapshot, ide_root, ide_cid, baseline_lines)
            final_snap = snap

            cur_sig = (
                int(snap.get("total_lines") or 0),
                int(snap.get("mtime_ns") or 0),
                int(snap.get("size") or 0),
                bool(snap.get("db_running")),
            )
            if cur_sig != last_sig:
                last_sig = cur_sig
                last_change_mono = time.monotonic()

            saw_u = bool(snap.get("saw_user_input"))
            u_line_nos = list(snap.get("user_input_line_nos") or [])
            db_run = bool(snap.get("db_running"))
            pending_steers = int(inflight_state.get("pending_steers") or 0)
            steered_q: list[dict[str, Any]] = inflight_state.setdefault("steered_ack_queue", [])
            last_steer_mono = float(inflight_state.get("last_steer_mono") or 0.0)
            if last_steer_mono > 0:
                overall_deadline = max(
                    overall_deadline,
                    last_steer_mono + max(30.0, float(self.config.agy_timeout_seconds)),
                )

            if not saw_u and not db_run and pending_steers == 0 and time.monotonic() >= accept_deadline:
                logger.warning("PC IDE window did not record USER_INPUT within %.1fs after Enter", self.pc_ide_accept_timeout)
                return (
                    TurnResult(
                        status="TIMEOUT",
                        response="",
                        conversation_id=ide_cid,
                        active_model="Antigravity 电脑端",
                        error="已向电脑端 Antigravity 窗口送出按键，但暂未检测到会话记录新增（为避免重复提交与模型分叉，未启动后台重跑，请点右上角同步或查看电脑画面确认）。",
                    ),
                    [],
                )

            if saw_u:
                raw_txt = str(snap.get("text") or "")
                clean_so_far = THOUGHT_TAG_RE.sub("", raw_txt).strip()
                if clean_so_far != emitted_text:
                    if clean_so_far.startswith(emitted_text):
                        await on_delta(clean_so_far[len(emitted_text) :])
                    else:
                        await on_reset()
                        if clean_so_far:
                            await on_delta(clean_so_far)
                    emitted_text = clean_so_far

                tname = str(snap.get("latest_tool_name") or "")
                if tname and tname != last_tool:
                    last_tool = tname
                    await on_tool(tname)

                # Exact transcript-anchored pivot when a mid-turn steering USER_INPUT line (`u_line_nos[1]`) lands!
                if len(u_line_nos) >= 2 and chat_slot:
                    steer_cid = ""
                    if steered_q:
                        st_item = steered_q.pop(0)
                        steer_cid = str(st_item.get("client_id") or "")

                    seg_imgs = [p for p in (snap.get("images") or []) if is_safe_outbound_file(p, image_only=True)]
                    prev_steps = list(inflight_state.get("steps") or [])
                    if emitted_text or seg_imgs:
                        seg_clean, md_imgs, md_files = extract_pwa_media_and_text(emitted_text)
                        for p_im in seg_imgs:
                            if p_im not in md_imgs:
                                md_imgs.append(p_im)
                        seg_entry = {
                            "role": "assistant",
                            "id": cur_reply_id,
                            "text": seg_clean,
                            "images": [self._media_ref(p, name=p.name) for p in md_imgs],
                            "files": [
                                self._media_ref(p, name=p.name, size=self._safe_file_size(p))
                                for p in md_files
                            ],
                            "steps": prev_steps,
                            "duration_sec": max(1, int(round(time.time() - turn_start_sec))),
                            "model": "Antigravity 电脑端",
                            "ts": int(time.time() * 1000),
                        }
                        self._insert_slot_history_before(chat_slot, seg_entry, steer_cid, persist_local=False)
                        if self._active_slot == chat_slot:
                            await self._broadcast(
                                {
                                    "type": "stream_end",
                                    "slot": chat_slot,
                                    "item": seg_entry,
                                    "keep_busy": True,
                                    "slots_overview": self._build_slots_overview(),
                                }
                            )
                        carried_steps: list[str] = []
                    else:
                        if self._active_slot == chat_slot:
                            await self._broadcast(
                                {"type": "stream_abandon", "slot": chat_slot, "msg_id": cur_reply_id}
                            )
                        carried_steps = prev_steps

                    if steer_cid:
                        await self._broadcast(
                            {
                                "type": "chat_ack",
                                "client_id": steer_cid,
                                "slot": chat_slot,
                                "stage": "processing_pc",
                                "label": "⚡ 电脑端正在处理此引导指令",
                            }
                        )

                    next_reply_id = f"a-{uuid.uuid4().hex[:10]}"
                    inflight_state["msg_id"] = next_reply_id
                    inflight_state["text"] = ""
                    inflight_state["status"] = "正在结合引导指令继续执行..."
                    inflight_state["steps"] = carried_steps
                    baseline_lines = int(u_line_nos[1])
                    emitted_text = ""
                    last_tool = ""
                    turn_start_sec = time.time()
                    accept_deadline = time.monotonic() + max(0.5, float(self.pc_ide_accept_timeout))
                    last_change_mono = time.monotonic()
                    if self._active_slot == chat_slot:
                        await self._broadcast(
                            {
                                "type": "stream_start",
                                "slot": chat_slot,
                                "msg_id": next_reply_id,
                                "model": "Antigravity 电脑端",
                                "slots_overview": self._build_slots_overview(),
                            }
                        )
                        if carried_steps:
                            await self._broadcast(
                                {
                                    "type": "stream_status",
                                    "slot": chat_slot,
                                    "msg_id": next_reply_id,
                                    "status": "正在结合引导指令继续执行...",
                                    "steps": carried_steps,
                                }
                            )
                    continue

                # Wait while a mid-turn steering delivery is in flight or queued waiting for IDE pickup
                if pending_steers > 0 or (
                    steered_q and (db_run or (time.monotonic() - last_steer_mono) < max(0.8, float(self.pc_ide_accept_timeout)))
                ):
                    continue

                saw_act = bool(snap.get("saw_activity_after_user"))
                has_db = bool(snap.get("has_db_row"))
                quiet_elapsed = time.monotonic() - last_change_mono

                if has_db:
                    if saw_act and not db_run and quiet_elapsed >= min(1.0, poll_sec * 1.8):
                        break
                else:
                    if saw_act and not bool(snap.get("last_planner_had_tools")) and quiet_elapsed >= min(1.4, poll_sec * 2.4):
                        break
        else:
            return (
                TurnResult(
                    status="TIMEOUT",
                    response=str(final_snap.get("text") or emitted_text),
                    conversation_id=ide_cid,
                    active_model="Antigravity 电脑端",
                    error="电脑端会话执行超时，请查看电脑屏幕确认状态。",
                ),
                list(final_snap.get("images") or []),
            )

        final_snap = await asyncio.to_thread(read_ide_live_turn_snapshot, ide_root, ide_cid, baseline_lines)
        ide_media = await asyncio.to_thread(harvest_recent_cli_turn_images, ide_root, ide_cid, turn_start_sec)
        merged_imgs: list[Path] = list(final_snap.get("images") or [])
        for mp in ide_media:
            if mp not in merged_imgs:
                merged_imgs.append(mp)

        self._ide_watch_sig = (
            "ide",
            ide_cid,
            int(final_snap.get("mtime_ns") or 0),
            int(final_snap.get("size") or 0),
        )
        return (
            TurnResult(
                status="SUCCESS",
                response=str(final_snap.get("text") or emitted_text),
                conversation_id=ide_cid,
                active_model="Antigravity 电脑端",
            ),
            merged_imgs,
        )

    async def _try_run_pc_ide_window_turn(
        self,
        *,
        chat_slot: str,
        ide_cid: str,
        title: str,
        prompt_text: str,
        reply_id: str,
        inflight_state: dict[str, Any],
        turn_start_sec: float,
        on_delta: Callable[[str], Any],
        on_reset: Callable[[], Any],
        on_tool: Callable[[str], Any],
        on_status: Callable[[str], Any],
        already_delivered: bool = False,
        preset_baseline_lines: int | None = None,
    ) -> tuple[TurnResult, list[Path]] | None:
        """Deliver `prompt_text` directly into the open PC Antigravity IDE window (including mid-turn steering!) and stream its live transcript."""
        if self._pc_window_sender is None or not ide_cid:
            return None

        ide_root = self.ide_store_dir if self.ide_store_dir is not None else _default_ide_dir()
        base_snap = await asyncio.to_thread(read_ide_live_turn_snapshot, ide_root, ide_cid, 10**9)
        was_pc_running = bool(base_snap.get("db_running"))
        baseline_lines = (
            int(preset_baseline_lines)
            if preset_baseline_lines is not None
            else int(base_snap.get("total_lines") or 0)
        )

        if not already_delivered:
            await on_status(
                "正在向运行中的电脑窗口注入引导指令..." if was_pc_running else "正在向电脑端窗口发送指令..."
            )
            delivered, note = await asyncio.to_thread(self._pc_window_sender, ide_cid, title, prompt_text)
            if not delivered:
                logger.warning("PC IDE window delivery rejected (%s): %s", ide_cid[:8], note)
                return (
                    TurnResult(
                        status="ERROR",
                        response="",
                        conversation_id=ide_cid,
                        active_model="Antigravity 电脑端",
                        error=f"未能投递到电脑端 Antigravity 聊天窗口：{note}\n（已阻止切换后台独立模型分叉双写，请确认电脑屏幕未锁屏且 Antigravity 窗口已打开后，点气泡下方「重填」重试。）",
                    ),
                    [],
                )

        await on_status(
            "⚡ 已送达引导指令，等待当前步骤衔接..." if was_pc_running else "电脑端窗口已接收，正在执行..."
        )
        return await self._stream_pc_ide_transcript_until_idle(
            chat_slot=chat_slot,
            ide_root=ide_root,
            ide_cid=ide_cid,
            baseline_lines=baseline_lines,
            base_snap=base_snap,
            reply_id=reply_id,
            inflight_state=inflight_state,
            turn_start_sec=turn_start_sec,
            on_delta=on_delta,
            on_reset=on_reset,
            on_tool=on_tool,
        )

    async def _try_run_pc_ide_new_chat_turn(
        self,
        *,
        chat_slot: str,
        session: AgySession,
        raw_title_seed: str,
        prompt_text: str,
        reply_id: str,
        inflight_state: dict[str, Any],
        turn_start_sec: float,
        on_delta: Callable[[str], Any],
        on_reset: Callable[[], Any],
        on_tool: Callable[[str], Any],
        on_status: Callable[[str], Any],
    ) -> tuple[TurnResult, list[Path]] | None:
        """Create a brand-new conversation inside the open PC Antigravity window and stream its reply."""
        if self._pc_window_new_sender is None:
            return None

        await on_status("正在电脑端新建 Antigravity 对话并发送...")
        ok, new_cid, note = await asyncio.to_thread(self._pc_window_new_sender, prompt_text)
        if not ok or not new_cid:
            logger.warning("PC IDE new-chat creation failed: %s", note)
            if slot_store_req := (self._slot_meta.get(chat_slot, {}).get("store") or ""):
                if slot_store_req == "ide":
                    return (
                        TurnResult(
                            status="ERROR",
                            response="",
                            conversation_id="",
                            active_model="Antigravity 电脑端",
                            error=f"未能在电脑端 Antigravity 窗口新建会话：{note}\n（若希望使用纯远程后台会话，可在新建面板切换为「远程后台」。）",
                        ),
                        [],
                    )
            return None

        new_title = (raw_title_seed or "").strip()[:38] or "电脑端新对话"
        meta_cur = self._slot_meta.setdefault(chat_slot, {})
        meta_cur["conversation_id"] = new_cid
        meta_cur["store"] = "ide"
        meta_cur["title"] = new_title
        session.linked_ide_id = new_cid
        session.linked_store = "ide"
        session.active_title = new_title

        if self._active_slot == chat_slot:
            await self._broadcast(
                {
                    "type": "meta_update",
                    "slot": chat_slot,
                    "model": "Antigravity 电脑端",
                    "workspace": str(session.workspace),
                    "active_conversation_id": new_cid,
                    "active_title": new_title,
                    "active_store": "ide",
                    "busy": True,
                }
            )

        await on_status("电脑端新对话已创建，正在执行...")
        ide_root = self.ide_store_dir if self.ide_store_dir is not None else _default_ide_dir()
        empty_snap = {
            "total_lines": 0,
            "mtime_ns": 0,
            "size": 0,
            "db_running": True,
        }
        return await self._stream_pc_ide_transcript_until_idle(
            chat_slot=chat_slot,
            ide_root=ide_root,
            ide_cid=new_cid,
            baseline_lines=0,
            base_snap=empty_snap,
            reply_id=reply_id,
            inflight_state=inflight_state,
            turn_start_sec=turn_start_sec,
            on_delta=on_delta,
            on_reset=on_reset,
            on_tool=on_tool,
        )

    async def _try_run_codex_cli_turn(
        self,
        *,
        chat_slot: str,
        codex_cid: str,
        workspace: Path,
        prompt_text: str,
        reply_id: str,
        on_delta: Callable[[str], Any],
        on_tool: Callable[[str], Any],
        on_status: Callable[[str], Any],
    ) -> TurnResult | None:
        """Start a new (`codex_cid == ""`) or resume an existing OpenAI Codex PC thread via `codex.exe exec`."""
        codex_exe = self._codex_cli_override
        if codex_exe is None and self.codex_store_dir is None:
            codex_exe = await asyncio.to_thread(find_codex_cli_executable)
        if codex_exe is None or not codex_exe.is_file():
            return None

        PROJECT_INBOX_DIR.mkdir(parents=True, exist_ok=True)
        last_msg_file = PROJECT_INBOX_DIR / f"codex_last_{uuid.uuid4().hex[:8]}.txt"
        extra_kwargs: dict[str, Any] = {"creationflags": CREATE_NO_WINDOW} if sys.platform == "win32" else {}

        is_new_thread = not bool(codex_cid)
        await on_status("正在电脑端创建 Codex 新会话..." if is_new_thread else "正在唤醒电脑端 Codex 会话...")
        cmd_args = (
            [str(codex_exe), "exec", "--skip-git-repo-check", "--json", "-o", str(last_msg_file), "-"]
            if is_new_thread
            else [
                str(codex_exe),
                "exec",
                "resume",
                "--all",
                "--skip-git-repo-check",
                "--json",
                "-o",
                str(last_msg_file),
                codex_cid,
                "-",
            ]
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(workspace) if workspace.is_dir() else None,
                **extra_kwargs,
            )
        except Exception as exc:
            logger.info("Failed starting codex.exe (%s): %s", codex_cid[:8] or "new", exc)
            return None

        self._slot_codex_procs[chat_slot] = proc
        emitted_blocks: list[str] = []
        stderr_tail: list[str] = []
        resolved_cid = codex_cid
        turn_accepted = False
        overall_deadline = time.monotonic() + max(15.0, float(self.config.agy_timeout_seconds))

        async def _drain_cdx_stderr() -> None:
            if proc.stderr is None:
                return
            try:
                while True:
                    sline = await proc.stderr.readline()
                    if not sline:
                        break
                    txt_err = sline.decode("utf-8", errors="replace").strip()
                    if txt_err:
                        stderr_tail.append(txt_err)
                        if len(stderr_tail) > 25:
                            del stderr_tail[:-25]
            except Exception:
                pass

        stderr_task = asyncio.create_task(_drain_cdx_stderr())

        try:
            if reply_id in self._cancelled_reply_ids:
                return TurnResult(
                    status="CANCELLED",
                    response="",
                    conversation_id=resolved_cid,
                    active_model="Codex 电脑端",
                )
            if proc.stdin is not None:
                proc.stdin.write(prompt_text.encode("utf-8"))
                await asyncio.wait_for(
                    proc.stdin.drain(),
                    timeout=max(1.0, overall_deadline - time.monotonic()),
                )
                proc.stdin.close()

            assert proc.stdout is not None
            while True:
                remaining = overall_deadline - time.monotonic()
                if remaining <= 0:
                    raise asyncio.TimeoutError("Codex 执行超时")
                raw_line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
                if not raw_line:
                    break
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ev_type = str(ev.get("type") or "")
                if ev_type == "thread.started":
                    turn_accepted = True
                    if ev.get("thread_id"):
                        resolved_cid = str(ev["thread_id"])
                elif ev_type.startswith("item.") or ev_type.startswith("turn."):
                    turn_accepted = True
                item = ev.get("item") if isinstance(ev.get("item"), dict) else {}
                itype = str(item.get("type") or "")
                if ev_type in {"item.started", "item.updated"} and itype in {"command_execution", "mcp_tool_call"}:
                    await on_tool(itype)
                elif ev_type == "item.completed" and itype == "agent_message":
                    txt = str(item.get("text") or "").strip()
                    if txt:
                        prefix = "\n\n" if emitted_blocks else ""
                        emitted_blocks.append(txt)
                        await on_delta(prefix + txt)

            rc = await asyncio.wait_for(proc.wait(), timeout=15.0)
            if reply_id in self._cancelled_reply_ids:
                return TurnResult(
                    status="CANCELLED",
                    response="\n\n".join(emitted_blocks),
                    conversation_id=resolved_cid,
                    active_model="Codex 电脑端",
                )

            final_txt = "\n\n".join(emitted_blocks).strip()
            if last_msg_file.is_file():
                file_txt = (await asyncio.to_thread(last_msg_file.read_text, "utf-8", "replace")).strip()
                if file_txt:
                    final_txt = file_txt

            if rc != 0 and not final_txt:
                if turn_accepted:
                    err_hint = stderr_tail[-1] if stderr_tail else f"Codex 进程异常退出 (exit={rc})"
                    return TurnResult(
                        status="ERROR",
                        response="",
                        conversation_id=resolved_cid,
                        active_model="Codex 电脑端",
                        error=err_hint,
                    )
                return None

            if resolved_cid:
                sig = await asyncio.to_thread(
                    get_transcript_signature,
                    resolved_cid,
                    "codex",
                    self.ide_store_dir,
                    self.cli_store_dir,
                    self.codex_store_dir,
                )
                self._ide_watch_sig = ("codex", resolved_cid, sig[0], sig[1])
            return TurnResult(
                status="SUCCESS",
                response=final_txt,
                conversation_id=resolved_cid,
                active_model="Codex 电脑端",
            )
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            if turn_accepted or emitted_blocks:
                return TurnResult(
                    status="TIMEOUT",
                    response="\n\n".join(emitted_blocks),
                    conversation_id=resolved_cid,
                    active_model="Codex 电脑端",
                    error="电脑端 Codex 会话执行超时，已安全中断（未重复重投）。",
                )
            return None
        except Exception as exc:
            logger.info("Codex CLI turn error (%s): %s", codex_cid[:8], exc)
            if turn_accepted or emitted_blocks:
                return TurnResult(
                    status="ERROR",
                    response="\n\n".join(emitted_blocks),
                    conversation_id=resolved_cid,
                    active_model="Codex 电脑端",
                    error=f"Codex 会话中断：{exc}",
                )
            return None
        finally:
            if self._slot_codex_procs.get(chat_slot) is proc:
                self._slot_codex_procs.pop(chat_slot, None)
            if proc.returncode is None:
                try:
                    if sys.platform == "win32" and proc.pid:
                        await asyncio.to_thread(_kill_process_tree_win32, proc.pid)
                    else:
                        proc.kill()
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                except Exception:
                    pass
            stderr_task.cancel()
            try:
                await stderr_task
            except BaseException:
                pass
            try:
                if last_msg_file.is_file():
                    last_msg_file.unlink()
            except OSError:
                pass

    async def _handle_chat(self, ws: ServerConnection, msg: dict[str, Any], chat_slot: str) -> None:
        raw_text = str(msg.get("text") or "").strip()
        explicit_client_id = str(msg.get("client_id") or "").strip()
        client_id = explicit_client_id or f"u-{uuid.uuid4().hex[:10]}"
        attachments = msg.get("attachments") or []
        if not raw_text and not attachments:
            return

        now_mono = time.monotonic()
        while self._processed_client_ids:
            oldest_cid, oldest_ts = next(iter(self._processed_client_ids.items()))
            if now_mono - oldest_ts > 900.0 or len(self._processed_client_ids) > 300:
                self._processed_client_ids.pop(oldest_cid, None)
            else:
                break

        if explicit_client_id and explicit_client_id in self._processed_client_ids:
            await self._safe_send(
                ws,
                {
                    "type": "chat_ack",
                    "client_id": client_id,
                    "slot": chat_slot,
                    "stage": "duplicate_ignored",
                    "label": "✓ 已接收（防重去重）",
                },
            )
            return

        session = self._session_for_slot(chat_slot)
        slot_meta = self._slot_meta.get(chat_slot, {})
        slot_store = str(slot_meta.get("store") or (session.linked_store if session.linked_ide_id else ""))
        slot_cid = str(slot_meta.get("conversation_id") or session.linked_ide_id or "")
        if (not slot_store or not slot_cid) and ":" in chat_slot:
            pfx, rest_cid = chat_slot.split(":", 1)
            if pfx in {"ide", "codex", "cli"} and rest_cid:
                slot_store = slot_store or pfx
                slot_cid = slot_cid or rest_cid
                self._slot_meta.setdefault(
                    chat_slot,
                    {"conversation_id": slot_cid, "title": session.active_title or "", "store": slot_store},
                )
        slot_title = str(slot_meta.get("title") or session.active_title or "")

        user_entry = {
            "role": "user",
            "id": client_id,
            "text": raw_text,
            "attachments": [
                {
                    "media_id": a.get("media_id"),
                    "name": a.get("name"),
                    "is_image": bool(a.get("is_image")),
                }
                for a in attachments
                if isinstance(a, dict)
            ],
            "ts": int(time.time() * 1000),
        }

        is_quick_slash = raw_text.startswith("/") and not attachments and raw_text.split()[0].lower() in {
            "/screen",
            "/shot",
            "/status",
            "/clean",
        }
        if is_quick_slash:
            if explicit_client_id:
                self._processed_client_ids[explicit_client_id] = now_mono
            self._append_slot_history(chat_slot, user_entry)
            if self._active_slot == chat_slot:
                await self._broadcast({"type": "user_msg", "slot": chat_slot, "item": user_entry})
            handled = await self._handle_slash_command(chat_slot, session, raw_text)
            if handled:
                return

        prompt_parts: list[str] = []
        if raw_text:
            prompt_parts.append(raw_text)
        for att in attachments:
            if not isinstance(att, dict):
                continue
            mid = str(att.get("media_id") or "")
            local_p = self._media_registry.get(mid)
            if local_p and local_p.is_file():
                kind = "图片" if att.get("is_image") else "文件"
                prompt_parts.append(f"[用户上传了{kind} {local_p.name}，已保存在本地，可直接读取或处理: {local_p}]")
        prompt_text = "\n".join(prompt_parts).strip()
        if not prompt_text:
            return

        already_delivered_pc = False
        preset_baseline: int | None = None
        already_persisted_user = False

        # Mid-turn Steering & Follow-Up Queueing when `chat_slot` already has an active turn!
        active_inf = self._slot_inflight.get(chat_slot)
        if active_inf is not None:
            fq = self._slot_followup_queue.setdefault(chat_slot, [])
            cur_steers = int(active_inf.get("pending_steers") or 0) + len(active_inf.get("steered_ack_queue") or [])
            if len(fq) + cur_steers >= 5:
                await self._safe_send(
                    ws,
                    {
                        "type": "chat_ack",
                        "client_id": client_id,
                        "slot": chat_slot,
                        "stage": "rejected_full",
                        "label": "⚠ 引导排队已满（最多 5 条），请稍候再发",
                    },
                )
                await self._safe_send(
                    ws,
                    {"type": "toast", "level": "err", "text": "当前引导指令排队已满，请等上一步消化后再发"},
                )
                return

            if explicit_client_id:
                self._processed_client_ids[explicit_client_id] = now_mono

            # Branch A: Live mid-turn steering directly into PC Antigravity IDE window (`slot_store == 'ide'`)
            if slot_store == "ide" and slot_cid and self._pc_window_sender is not None:
                self._append_slot_history(chat_slot, user_entry)
                if self._active_slot == chat_slot:
                    await self._broadcast({"type": "user_msg", "slot": chat_slot, "item": user_entry})
                await self._broadcast(
                    {
                        "type": "chat_ack",
                        "client_id": client_id,
                        "slot": chat_slot,
                        "stage": "gateway_accepted",
                        "label": "⚡ 正在向电脑窗口注入引导指令...",
                    }
                )
                ide_root_st = self.ide_store_dir if self.ide_store_dir is not None else _default_ide_dir()
                pre_snap_st = await asyncio.to_thread(read_ide_live_turn_snapshot, ide_root_st, slot_cid, 10**9)
                active_inf["pending_steers"] = int(active_inf.get("pending_steers") or 0) + 1
                try:
                    delivered_st, note_st = await asyncio.to_thread(
                        self._pc_window_sender, slot_cid, slot_title, prompt_text
                    )
                finally:
                    active_inf["pending_steers"] = max(0, int(active_inf.get("pending_steers") or 1) - 1)

                if not delivered_st:
                    self._remove_slot_local_turn(chat_slot, client_id)
                    await self._broadcast(
                        {
                            "type": "chat_ack",
                            "client_id": client_id,
                            "slot": chat_slot,
                            "stage": "steer_failed",
                            "label": "⚠ 未送达电脑窗口（可点重填）",
                        }
                    )
                    await self._safe_send(
                        ws, {"type": "toast", "level": "err", "text": f"引导指令未能送达电脑窗口：{note_st}"}
                    )
                    return

                self._remove_slot_local_turn(chat_slot, client_id)
                if self._slot_inflight.get(chat_slot) is active_inf:
                    active_inf.setdefault("steered_ack_queue", []).append(
                        {"client_id": client_id, "sent_mono": time.monotonic()}
                    )
                    active_inf["last_steer_mono"] = time.monotonic()
                    await self._broadcast(
                        {
                            "type": "chat_ack",
                            "client_id": client_id,
                            "slot": chat_slot,
                            "stage": "delivered_pc",
                            "label": "⚡ 已送达电脑端，本步完成后无缝继续",
                        }
                    )
                    await self._safe_send(
                        ws,
                        {"type": "toast", "level": "info", "text": "⚡ 引导指令已送达电脑窗口，无需中断直接继续"},
                    )
                    return

                # Previous turn finished right while we were pasting `prompt_text` into IDE -> seamlessly track the new turn!
                if chat_slot not in self._slot_inflight:
                    already_delivered_pc = True
                    already_persisted_user = True
                    preset_baseline = int(pre_snap_st.get("total_lines") or 0)
                else:
                    return
            else:
                # Branch B: Codex / CLI subprocess (`stdin` closed) -> FIFO queue for automatic immediate continuation!
                self._append_slot_history(chat_slot, user_entry)
                if self._active_slot == chat_slot:
                    await self._broadcast({"type": "user_msg", "slot": chat_slot, "item": user_entry})
                fq.append(
                    {
                        "raw_text": raw_text,
                        "attachments": attachments,
                        "prompt_text": prompt_text,
                        "user_entry": user_entry,
                        "client_id": client_id,
                    }
                )
                await self._broadcast(
                    {
                        "type": "chat_ack",
                        "client_id": client_id,
                        "slot": chat_slot,
                        "stage": "queued_followup",
                        "label": "⏳ 已排队，当前轮结束后自动继续",
                    }
                )
                await self._safe_send(
                    ws,
                    {"type": "toast", "level": "info", "text": "⏳ 当前对话正在执行中，已将引导指令排入队列自动续跑"},
                )
                return

        if explicit_client_id and explicit_client_id not in self._processed_client_ids:
            self._processed_client_ids[explicit_client_id] = now_mono

        if not already_persisted_user and raw_text.startswith("/") and not attachments:
            self._append_slot_history(chat_slot, user_entry)
            if self._active_slot == chat_slot:
                await self._broadcast({"type": "user_msg", "slot": chat_slot, "item": user_entry})
            handled = await self._handle_slash_command(chat_slot, session, raw_text)
            if handled:
                return

        was_brand_new = not bool(slot_cid)
        while True:
            # Atomically claim `self._slot_inflight[chat_slot]` BEFORE the first `await` so concurrent sends cannot slip in!
            slot_meta = self._slot_meta.get(chat_slot, {})
            slot_store = str(slot_meta.get("store") or (session.linked_store if session.linked_ide_id else ""))
            slot_cid = str(slot_meta.get("conversation_id") or session.linked_ide_id or "")
            slot_title = str(slot_meta.get("title") or session.active_title or "")

            reply_id = f"a-{uuid.uuid4().hex[:10]}"
            initial_model_label = (
                "Antigravity 电脑端"
                if slot_store == "ide"
                else ("Codex 电脑端" if slot_store == "codex" else (session.model or "default"))
            )
            inflight_state: dict[str, Any] = {
                "msg_id": reply_id,
                "slot": chat_slot,
                "model": initial_model_label,
                "text": "",
                "status": "正在思考...",
                "steps": [],
                "started_ms": int(time.time() * 1000),
            }
            self._slot_inflight[chat_slot] = inflight_state
            if not already_persisted_user and not (raw_text.startswith("/") and not attachments):
                self._append_slot_history(chat_slot, user_entry)

            turn_start_sec = time.time()
            partial_before_finish = ""
            pc_direct_persisted = False
            extra_pc_images: list[Path] = []
            result: TurnResult | None = None

            async def _on_delta(delta: str) -> None:
                cur_mid = str(inflight_state.get("msg_id") or reply_id)
                inflight_state["text"] = str(inflight_state.get("text") or "") + delta
                inflight_state["status"] = ""
                if self._active_slot == chat_slot:
                    await self._broadcast(
                        {"type": "stream_delta", "slot": chat_slot, "msg_id": cur_mid, "delta": delta}
                    )

            async def _on_reset() -> None:
                cur_mid = str(inflight_state.get("msg_id") or reply_id)
                inflight_state["text"] = ""
                if self._active_slot == chat_slot:
                    await self._broadcast({"type": "stream_reset", "slot": chat_slot, "msg_id": cur_mid})

            async def _on_status(status_txt: str) -> None:
                cur_mid = str(inflight_state.get("msg_id") or reply_id)
                inflight_state["status"] = status_txt
                clean_st = status_txt.strip().rstrip(".")
                if clean_st and clean_st != "正在思考":
                    steps_arr: list[str] = inflight_state.setdefault("steps", [])
                    if not steps_arr or steps_arr[-1] != clean_st:
                        if len(steps_arr) < 16:
                            steps_arr.append(clean_st)
                if self._active_slot == chat_slot:
                    await self._broadcast(
                        {
                            "type": "stream_status",
                            "slot": chat_slot,
                            "msg_id": cur_mid,
                            "status": status_txt,
                            "steps": list(inflight_state.get("steps") or []),
                        }
                    )

            async def _on_tool(tool_name: str) -> None:
                tlow = tool_name.lower()
                if "screenshot" in tlow or "snapshot" in tlow:
                    hint = "电脑端正在截取画面..."
                elif "edit" in tlow or "write" in tlow:
                    hint = "电脑端正在修改代码..."
                elif "mcp" in tlow or "command" in tlow:
                    hint = "电脑端正在执行命令..."
                else:
                    hint = "电脑端正在检索与处理..."
                await _on_status(hint)

            try:
                if not already_persisted_user:
                    await self._broadcast(
                        {
                            "type": "chat_ack",
                            "client_id": client_id,
                            "slot": chat_slot,
                            "stage": "gateway_accepted",
                            "label": "✓ 网关已接收",
                        }
                    )
                else:
                    await self._broadcast(
                        {
                            "type": "chat_ack",
                            "client_id": client_id,
                            "slot": chat_slot,
                            "stage": "processing_followup",
                            "label": "⚡ 正在自动执行此引导指令",
                        }
                    )
                if self._active_slot == chat_slot:
                    if not already_persisted_user and not (raw_text.startswith("/") and not attachments):
                        await self._broadcast({"type": "user_msg", "slot": chat_slot, "item": user_entry})
                    await self._broadcast(
                        {
                            "type": "stream_start",
                            "slot": chat_slot,
                            "msg_id": reply_id,
                            "model": initial_model_label,
                            "slots_overview": self._build_slots_overview(),
                        }
                    )
                else:
                    await self._broadcast_slots_overview()

                # 1. Existing PC Antigravity IDE conversation -> deliver into live PC IDE window
                if slot_store == "ide" and slot_cid:
                    pc_ide_out = await self._try_run_pc_ide_window_turn(
                        chat_slot=chat_slot,
                        ide_cid=slot_cid,
                        title=slot_title,
                        prompt_text=prompt_text,
                        reply_id=reply_id,
                        inflight_state=inflight_state,
                        turn_start_sec=turn_start_sec,
                        on_delta=_on_delta,
                        on_reset=_on_reset,
                        on_tool=_on_tool,
                        on_status=_on_status,
                        already_delivered=already_delivered_pc,
                        preset_baseline_lines=preset_baseline,
                    )
                    if pc_ide_out is not None:
                        result, extra_pc_images = pc_ide_out
                        pc_direct_persisted = True
                        await self._broadcast(
                            {
                                "type": "chat_ack",
                                "client_id": client_id,
                                "slot": chat_slot,
                                "stage": "delivered_pc",
                                "label": "✓ 已投递至电脑窗口",
                            }
                        )

                # 2. Brand-new PC Antigravity IDE conversation (tapped `+` or sent from default home screen)
                elif not slot_cid and slot_store in {"", "ide"} and self._pc_window_new_sender is not None:
                    pc_new_out = await self._try_run_pc_ide_new_chat_turn(
                        chat_slot=chat_slot,
                        session=session,
                        raw_title_seed=raw_text,
                        prompt_text=prompt_text,
                        reply_id=reply_id,
                        inflight_state=inflight_state,
                        turn_start_sec=turn_start_sec,
                        on_delta=_on_delta,
                        on_reset=_on_reset,
                        on_tool=_on_tool,
                        on_status=_on_status,
                    )
                    if pc_new_out is not None:
                        result, extra_pc_images = pc_new_out
                        pc_direct_persisted = True
                        await self._broadcast(
                            {
                                "type": "chat_ack",
                                "client_id": client_id,
                                "slot": chat_slot,
                                "stage": "delivered_pc",
                                "label": "✓ 已在电脑端新建并投递",
                            }
                        )

                # 3. Existing OR brand-new PC OpenAI Codex conversation (`slot_store == "codex"`)
                elif slot_store == "codex":
                    cdx_out = await self._try_run_codex_cli_turn(
                        chat_slot=chat_slot,
                        codex_cid=slot_cid,
                        workspace=session.workspace,
                        prompt_text=prompt_text,
                        reply_id=reply_id,
                        on_delta=_on_delta,
                        on_tool=_on_tool,
                        on_status=_on_status,
                    )
                    if cdx_out is not None:
                        result = cdx_out
                        pc_direct_persisted = True
                        await self._broadcast(
                            {
                                "type": "chat_ack",
                                "client_id": client_id,
                                "slot": chat_slot,
                                "stage": "delivered_pc",
                                "label": "✓ 已交由电脑 Codex 执行",
                            }
                        )
                        if not slot_cid and cdx_out.conversation_id:
                            new_title = raw_text[:38] or "Codex 新对话"
                            meta_cur = self._slot_meta.setdefault(chat_slot, {})
                            meta_cur["conversation_id"] = cdx_out.conversation_id
                            meta_cur["store"] = "codex"
                            meta_cur["title"] = new_title
                            session.linked_ide_id = cdx_out.conversation_id
                            session.linked_store = "codex"
                            session.active_title = new_title
                            if self._active_slot == chat_slot:
                                await self._broadcast(
                                    {
                                        "type": "meta_update",
                                        "slot": chat_slot,
                                        "model": "Codex 电脑端",
                                        "workspace": str(session.workspace),
                                        "active_conversation_id": cdx_out.conversation_id,
                                        "active_title": new_title,
                                        "active_store": "codex",
                                        "busy": True,
                                    }
                                )

                # 4. Fallback to standalone `agy.exe` session when in a mobile/CLI chat or when PC desktop app is closed
                if result is None:
                    final_mid_chk = str(inflight_state.get("msg_id") or reply_id)
                    if final_mid_chk in self._cancelled_reply_ids or reply_id in self._cancelled_reply_ids:
                        result = TurnResult(
                            status="CANCELLED",
                            response=str(inflight_state.get("text") or ""),
                            active_model=initial_model_label,
                        )
                    else:
                        if slot_store in {"ide", "codex"} and (self._pc_window_sender is not None or slot_store == "codex"):
                            await _on_status("桌面窗口未就绪，已切换后台引擎接力处理...")
                        result = await session.ask(
                            prompt_text,
                            on_delay_notice=None,
                            on_stream_delta=_on_delta,
                            on_stream_reset=_on_reset,
                            on_tool_start=_on_tool,
                        )
            except asyncio.CancelledError:
                final_mid_chk = str(inflight_state.get("msg_id") or reply_id)
                if final_mid_chk not in self._cancelled_reply_ids and reply_id not in self._cancelled_reply_ids:
                    if self._slot_inflight.get(chat_slot) is inflight_state:
                        self._slot_inflight.pop(chat_slot, None)
                    raise
                result = TurnResult(
                    status="CANCELLED",
                    response=str(inflight_state.get("text") or ""),
                    active_model=initial_model_label,
                )
            finally:
                partial_before_finish = str(inflight_state.get("text") or "")
                if (
                    not pc_direct_persisted
                    and self._pc_window_sender is None
                    and session.linked_ide_id
                    and session.conversation_id
                ):
                    map_key = f"{session.linked_store}:{session.linked_ide_id}" if session.linked_store else session.linked_ide_id
                    self._continuation_map[map_key] = session.conversation_id
                    self._continuation_map[session.linked_ide_id] = session.conversation_id
                    await asyncio.to_thread(self._save_continuation_map)

            final_reply_id = str(inflight_state.get("msg_id") or reply_id)
            was_user_cancelled = final_reply_id in self._cancelled_reply_ids or reply_id in self._cancelled_reply_ids
            self._cancelled_reply_ids.discard(final_reply_id)
            self._cancelled_reply_ids.discard(reply_id)

            if result.status == "SUCCESS":
                clean_text, img_paths, file_paths = extract_pwa_media_and_text(result.response or "")
                if result.switched_from_model and result.active_model:
                    note = f"（注：{result.switched_from_model} 额度已满，已自动切到 {result.active_model}）"
                    clean_text = f"{clean_text}\n\n{note}" if clean_text else note
            elif was_user_cancelled or result.status == "CANCELLED":
                clean_resp, img_paths, file_paths = extract_pwa_media_and_text(result.response or partial_before_finish)
                clean_text = f"{clean_resp}\n\n⏹ 已停止生成。".strip() if clean_resp else "⏹ 已停止生成。"
            else:
                clean_resp, img_paths, file_paths = extract_pwa_media_and_text(result.response or partial_before_finish)
                err = result.error or f"执行未成功 ({result.status})"
                clean_text = f"{clean_resp}\n\n刚才这步出了点状况：\n{err}".strip()

            for ep in extra_pc_images:
                if ep not in img_paths and is_safe_outbound_file(ep, image_only=True):
                    img_paths.append(ep)

            if not pc_direct_persisted:
                cli_root = self.cli_store_dir if self.cli_store_dir is not None else _default_cli_dir()
                harvested = await asyncio.to_thread(
                    harvest_recent_cli_turn_images,
                    cli_root,
                    result.conversation_id or session.conversation_id,
                    turn_start_sec,
                )
                for hp in harvested:
                    if hp not in img_paths:
                        img_paths.append(hp)
            else:
                # Turn was written directly into the PC IDE / Codex transcript — avoid duplicating in `_slot_local_turns`!
                self._remove_slot_local_turn(chat_slot, client_id)

            if result.status == "SUCCESS" and not clean_text and not img_paths and not file_paths:
                clean_text = "已完成。"

            # Update slot metadata if this was a brand-new conversation that just received a CLI ID
            if chat_slot.startswith("new:") or chat_slot == DEFAULT_SLOT_KEY:
                if session.conversation_id:
                    meta_cur = self._slot_meta.setdefault(chat_slot, {})
                    if not meta_cur.get("conversation_id"):
                        meta_cur["conversation_id"] = session.conversation_id
                        meta_cur["store"] = "cli"
                        meta_cur["title"] = raw_text[:36] or "新对话"

            img_items = [self._media_ref(p, name=p.name) for p in img_paths]
            file_items = [
                self._media_ref(p, name=p.name, size=self._safe_file_size(p))
                for p in file_paths
            ]

            assistant_entry = {
                "role": "assistant",
                "id": final_reply_id,
                "text": clean_text,
                "images": img_items,
                "files": file_items,
                "steps": list(inflight_state.get("steps") or []),
                "duration_sec": max(1, int(round(time.time() - turn_start_sec))),
                "model": result.active_model or session.model or "default",
                "ts": int(time.time() * 1000),
            }
            self._append_slot_history(chat_slot, assistant_entry, persist_local=not pc_direct_persisted)

            # Atomically check FIFO follow-up queue BEFORE releasing `self._slot_inflight[chat_slot]`!
            fq_after = self._slot_followup_queue.get(chat_slot)
            has_next_queued = bool(fq_after)
            if not has_next_queued and self._slot_inflight.get(chat_slot) is inflight_state:
                self._slot_inflight.pop(chat_slot, None)

            if self._active_slot == chat_slot:
                await self._broadcast(
                    {
                        "type": "stream_end",
                        "slot": chat_slot,
                        "item": assistant_entry,
                        "keep_busy": has_next_queued,
                        "slots_overview": self._build_slots_overview(),
                    }
                )
            else:
                meta_done = self._slot_meta.get(chat_slot, {})
                done_title = meta_done.get("title") or "后台会话"
                self._unread_slots[chat_slot] = {
                    "slot": chat_slot,
                    "conversation_id": str(meta_done.get("conversation_id") or result.conversation_id or ""),
                    "store": str(meta_done.get("store") or "cli"),
                    "title": done_title,
                    "preview": clean_text[:60],
                    "ts": int(time.time() * 1000),
                }
                await self._broadcast_slots_overview()
                await self._broadcast(
                    {
                        "type": "toast",
                        "level": "info",
                        "text": f"✓ 「{done_title[:18]}」已完成回复",
                    }
                )

            if has_next_queued and fq_after:
                nxt = fq_after.pop(0)
                raw_text = str(nxt["raw_text"])
                attachments = nxt["attachments"]
                prompt_text = str(nxt["prompt_text"])
                user_entry = nxt["user_entry"]
                client_id = str(nxt["client_id"])
                already_persisted_user = True
                already_delivered_pc = False
                preset_baseline = None
                continue
            break

        # Refresh conversation sidebar list whenever a brand-new conversation finished its first turn
        if was_brand_new and self._clients:
            for cli_ws in list(self._clients):
                try:
                    await self._handle_list_conversations(cli_ws)
                except Exception:
                    pass

    async def _send_sys_reply(
        self, slot_key: str, text: str, model: str = "", images: list[dict] | None = None
    ) -> None:
        entry = {
            "role": "assistant",
            "id": f"s-{uuid.uuid4().hex[:10]}",
            "text": text,
            "images": images or [],
            "files": [],
            "model": model,
            "ts": int(time.time() * 1000),
        }
        self._append_slot_history(slot_key, entry)
        if self._active_slot == slot_key:
            await self._broadcast({"type": "stream_end", "slot": slot_key, "item": entry})

    async def _handle_slash_command(self, slot_key: str, session: AgySession, raw_text: str) -> bool:
        parts = raw_text.strip().split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd in {"/screen", "/shot"}:
            shot = await asyncio.to_thread(capture_desktop_fast_jpeg_sync, PROJECT_INBOX_DIR)
            await self._send_sys_reply(
                slot_key,
                "当前电脑桌面截图：",
                session.model,
                images=[self._media_ref(shot, name=shot.name)],
            )
            return True

        if cmd in {"/new", "/reset"}:
            prev_store = str(self._slot_meta.get(slot_key, {}).get("store") or "")
            if not prev_store and self._pc_window_new_sender is not None:
                prev_store = "ide"
            self._nav_seq += 1
            new_slot = f"new:{uuid.uuid4().hex[:8]}"
            new_sess = self._session_for_slot(new_slot)
            await new_sess.start_new_conversation(workspace=str(session.workspace))
            self._active_slot = new_slot
            self._slot_history[new_slot] = []
            self._slot_meta[new_slot] = {"conversation_id": "", "title": "Stayy", "store": prev_store}
            self._ide_watch_sig = ("", "", 0, 0)
            await self._broadcast({"type": "clear_history", "nav_seq": self._nav_seq, "slot": new_slot})
            await self._broadcast_slots_overview()
            await self._broadcast(
                {
                    "type": "meta_update",
                    "slot": new_slot,
                    "model": (
                        "Antigravity 电脑端"
                        if prev_store == "ide"
                        else ("Codex 电脑端" if prev_store == "codex" else (new_sess.model or "default"))
                    ),
                    "workspace": str(new_sess.workspace),
                    "active_conversation_id": "",
                    "active_title": "Stayy",
                    "active_store": prev_store,
                    "busy": False,
                }
            )
            return True

        if cmd == "/model":
            if not arg:
                chain = " -> ".join(session.failover_pool.models[:5])
                await self._send_sys_reply(
                    slot_key,
                    f"当前模型：`{session.model or '默认'}`\n容灾链：{chain}\n\n"
                    "可点击顶栏标题切换模型，或输入：`/model fast | balanced | smart | gemini`",
                    session.model,
                )
                return True
            target = MODEL_ALIASES.get(arg.lower(), arg)
            await session.set_model(target)
            await self._broadcast(
                {"type": "meta_update", "slot": slot_key, "model": session.model, "workspace": str(session.workspace)}
            )
            await self._send_sys_reply(slot_key, f"已切换到 `{target}`，上下文继续保留。", session.model)
            return True

        if cmd == "/clean":
            targets = discover_default_cache_targets(PROJECT_ROOT)
            rep = await asyncio.to_thread(
                run_safe_cache_cleanup, targets, force_all_expired_zero=(arg.lower() == "all")
            )
            await self._send_sys_reply(slot_key, rep.format_human(), session.model)
            return True

        if cmd == "/status":
            cooling = session.failover_pool.cooldown_summary()
            cool_str = ", ".join(f"{m}({mins}m)" for m, mins in cooling) if cooling else "全部正常可用"
            await self._send_sys_reply(
                slot_key,
                f"**Stayy 状态**\n"
                f"- 当前模型：`{session.model or '默认'}`\n"
                f"- 额度池：{cool_str}\n"
                f"- 会话轮次：{session.num_turns}\n"
                f"- 工作目录：`{session.workspace}`",
                session.model,
            )
            return True

        if cmd == "/cd" and arg:
            target_dir = Path(arg.strip("\"'"))
            if not target_dir.is_absolute():
                target_dir = session.workspace / target_dir
            try:
                await session.set_workspace(target_dir)
                await self._broadcast(
                    {
                        "type": "meta_update",
                        "slot": slot_key,
                        "model": session.model,
                        "workspace": str(session.workspace),
                    }
                )
                await self._send_sys_reply(slot_key, f"已切换工作目录：\n`{session.workspace}`", session.model)
            except FileNotFoundError as exc:
                await self._send_sys_reply(slot_key, str(exc), session.model)
            return True

        return False

    async def _poll_ide_watch_once(self) -> None:
        """Single watch tick: sync active PC transcript safely (zero-await before commit) and trigger optional Bark reminder."""
        cur_slot = self._active_slot
        meta_cur = self._slot_meta.get(cur_slot, {})
        ide_cid = str(meta_cur.get("conversation_id") or "")
        watch_store = str(meta_cur.get("store") or "")
        session = self._session_for_slot(cur_slot)
        if not ide_cid:
            ide_cid = str(session.linked_ide_id or "")
        if not watch_store:
            watch_store = str(session.linked_store or "ide")

        # Low-power optional Bark check ONLY when configured AND (active task running or viewing live IDE window)
        if self.bark_notifier.enabled and (cur_slot in self._slot_inflight or (watch_store == "ide" and ide_cid)):
            try:
                ro_actions = await asyncio.to_thread(self._ide_actions_inspector, ide_cid)
                event_keys = [
                    str(a.get("event_key") or "")
                    for a in (ro_actions or [])
                    if isinstance(a, dict) and a.get("event_key")
                ]
                await asyncio.to_thread(self.bark_notifier.notify_for_events, event_keys)
            except Exception as exc:
                logger.debug("Optional Bark watcher skipped: %s", exc)

        async with self._clients_lock:
            has_clients = bool(self._clients)
        if not has_clients:
            return
        if cur_slot in self._slot_inflight:
            return
        if not ide_cid or watch_store not in {"ide", "codex"}:
            return

        snap_nav = self._nav_seq
        self._watch_gen += 1
        snap_gen = self._watch_gen
        snap = (snap_nav, cur_slot, ide_cid, watch_store)

        sig = await asyncio.to_thread(
            get_transcript_signature,
            ide_cid,
            watch_store,
            self.ide_store_dir,
            self.cli_store_dir,
            self.codex_store_dir,
        )
        if sig == (0, 0) or (watch_store, ide_cid, sig[0], sig[1]) == self._ide_watch_sig:
            return

        detail = await asyncio.to_thread(
            load_conversation_detail,
            ide_cid,
            watch_store,
            200,
            self.ide_store_dir,
            self.cli_store_dir,
            self.codex_store_dir,
        )
        if detail is None:
            return

        cont_detail: ConversationDetail | None = None
        allow_cont_merge = (detail.store == "codex") or (detail.store == "ide" and self._pc_window_sender is None)
        if allow_cont_merge:
            cont_cid = (
                self._continuation_map.get(f"{detail.store}:{detail.conversation_id}")
                or self._continuation_map.get(detail.conversation_id)
                or session.conversation_id
            )
            if cont_cid:
                cont_detail = await asyncio.to_thread(
                    load_conversation_detail,
                    cont_cid,
                    "cli",
                    100,
                    self.ide_store_dir,
                    self.cli_store_dir,
                    self.codex_store_dir,
                )

        # CRITICAL CONCURRENCY GUARD: re-verify full snapshot identity & perform state commit with ZERO awaits in between!
        meta_now = self._slot_meta.get(cur_slot, {})
        now_cid = str(meta_now.get("conversation_id") or session.linked_ide_id or "")
        now_store = str(meta_now.get("store") or session.linked_store or "ide")
        if (
            self._nav_seq != snap[0]
            or self._watch_gen != snap_gen
            or self._active_slot != snap[1]
            or now_cid != snap[2]
            or now_store != snap[3]
            or cur_slot in self._slot_inflight
        ):
            return

        self._ide_watch_sig = (watch_store, ide_cid, sig[0], sig[1])
        if not session.conversation_id:
            session._pending_handoff_context = build_ide_handoff_context(detail)

        loaded_history = self._convert_detail_to_pwa_history(detail, session.model or "default")
        if cont_detail and cont_detail.messages:
            cont_hist = self._convert_detail_to_pwa_history(cont_detail, session.model or "default")
            _extend_deduplicated_turns(loaded_history, cont_hist)
            if any(int(x.get("ts") or 0) > 0 for x in loaded_history) and len(loaded_history) > 1:
                running_ts = 0
                keyed: list[tuple[int, int, dict[str, Any]]] = []
                for idx_item, item in enumerate(loaded_history):
                    raw_ts = int(item.get("ts") or 0)
                    if raw_ts > 0:
                        running_ts = raw_ts
                    keyed.append((running_ts, idx_item, item))
                loaded_history = [it for _, _, it in sorted(keyed, key=lambda t: (t[0], t[1]))]
        if self._slot_local_turns.get(cur_slot) and detail.store != "ide":
            _extend_deduplicated_turns(loaded_history, self._slot_local_turns[cur_slot])

        self._slot_history[cur_slot] = loaded_history
        outbound = {
            "type": "conversation_loaded",
            "nav_seq": snap_nav,
            "slot": cur_slot,
            "conversation_id": detail.conversation_id,
            "title": detail.title,
            "store": detail.store,
            "running": detail.running,
            "busy": False,
            "workspace": str(session.workspace),
            "silent": True,
            "has_more": detail.has_more,
            "total_messages": detail.total_messages,
            "history": loaded_history,
        }
        await self._broadcast(outbound)

    async def _ide_watch_loop(self) -> None:
        """Auto-push live PC Antigravity / Codex transcript updates when viewing a PC chat."""
        while True:
            interval = getattr(self, "ide_watch_interval", 1.4)
            await asyncio.sleep(interval)
            try:
                await self._poll_ide_watch_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("PC transcript watch loop error: %s", exc)

    async def _cache_clean_loop(self) -> None:
        if self.config.cache_clean_interval_hours <= 0.0:
            return
        interval_sec = max(300.0, self.config.cache_clean_interval_hours * 3600.0)
        await asyncio.sleep(20.0)
        while True:
            try:
                targets = discover_default_cache_targets(PROJECT_ROOT)
                rep = await asyncio.to_thread(run_safe_cache_cleanup, targets)
                if rep.deleted_files > 0:
                    logger.info(
                        "Periodic cache cleanup removed %d expired files (%.2f MB)",
                        rep.deleted_files,
                        rep.freed_mb,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("Cache cleaner warning: %s", exc)
            await asyncio.sleep(interval_sec)

    async def _handle_admin_http(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Isolated loopback-only admin control plane (`GET /admin/health`, `POST /admin/pair`, `POST /admin/revoke`)."""
        try:
            req_line_raw = await asyncio.wait_for(reader.readline(), timeout=4.0)
            req_line = req_line_raw.decode("utf-8", errors="replace").strip()
            if not req_line:
                return
            parts = req_line.split()
            method = parts[0].upper() if len(parts) >= 1 else "GET"
            raw_path = urlsplit(parts[1]).path if len(parts) >= 2 else "/"

            hdrs: dict[str, str] = {}
            while True:
                hline = await asyncio.wait_for(reader.readline(), timeout=4.0)
                if not hline or hline in {b"\r\n", b"\n"}:
                    break
                dec = hline.decode("utf-8", errors="replace").strip()
                if ":" in dec:
                    k, v = dec.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()

            clen = int(hdrs.get("content-length") or "0")
            if 0 < clen <= 65536:
                await asyncio.wait_for(reader.readexactly(clen), timeout=4.0)

            provided = hdrs.get("x-admin-token", "")
            if not provided or not hmac.compare_digest(provided, self.admin_secret):
                status, reason, payload = 403, "Forbidden", {"ok": False, "error": "forbidden"}
            elif method == "GET" and raw_path == "/admin/health":
                async with self._clients_lock:
                    n_cli = len(self._clients)
                status, reason, payload = 200, "OK", {
                    "ok": True,
                    "service": "stayy",
                    "host_id": self.auth.host_id,
                    "auth_epoch": self.auth.current_epoch(),
                    "clients": n_cli,
                }
            elif method == "POST" and raw_path == "/admin/pair":
                code = self.auth.issue_pairing_code(ttl_sec=300.0)
                status, reason, payload = 200, "OK", {"ok": True, "code": code, "ttl_sec": 300}
            elif method == "POST" and raw_path == "/admin/revoke":
                ok_rev, closed_cnt, new_ep = await self.revoke_all_tokens()
                if ok_rev:
                    status, reason, payload = 200, "OK", {
                        "ok": True,
                        "auth_epoch": new_ep,
                        "closed_clients": closed_cnt,
                    }
                else:
                    status, reason, payload = 500, "Internal Server Error", {
                        "ok": False,
                        "auth_epoch": new_ep,
                        "error": "env_write_failed",
                    }
            else:
                status, reason, payload = 404, "Not Found", {"ok": False, "error": "not_found"}

            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            resp_hdr = (
                f"HTTP/1.1 {status} {reason}\r\n"
                "Content-Type: application/json; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Cache-Control: no-store\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            writer.write(resp_hdr + body)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def run(self, stop_event: asyncio.Event | None = None) -> None:
        logger.info(
            "Starting Stayy server at http://%s:%d (LAN: http://%s:%d)",
            self.config.web_pwa_host,
            self.config.web_pwa_port,
            get_lan_ipv4(),
            self.config.web_pwa_port,
        )
        if self.config.agy_prewarm:
            pw_task = asyncio.create_task(self._session_for_slot(DEFAULT_SLOT_KEY).prewarm())
            self._tasks.add(pw_task)
            pw_task.add_done_callback(self._tasks.discard)

        for coro in (self._ide_watch_loop(), self._cache_clean_loop()):
            bg_task = asyncio.create_task(coro)
            self._tasks.add(bg_task)
            bg_task.add_done_callback(self._tasks.discard)

        admin_srv = await asyncio.start_server(self._handle_admin_http, "127.0.0.1", 0)
        sock_addr = admin_srv.sockets[0].getsockname()
        self.admin_port = int(sock_addr[1])
        self._admin_state_file = write_admin_state(
            self.runtime_dir, self.admin_port, self.admin_secret, os.getpid()
        )
        logger.info("Stayy loopback admin control plane listening on 127.0.0.1:%d", self.admin_port)

        serve_kwargs: dict[str, Any] = {
            "process_request": self._process_request,
            "compression": None,
            "ping_interval": 20,
            "ping_timeout": 20,
            "max_size": 16 * 1024 * 1024,
        }
        if sys.platform == "win32":
            serve_kwargs["reuse_address"] = False

        try:
            async with websockets.serve(
                self._handle_ws,
                self.config.web_pwa_host,
                self.config.web_pwa_port,
                **serve_kwargs,
            ):
                if stop_event is not None:
                    await stop_event.wait()
                else:
                    await asyncio.Future()
        finally:
            admin_srv.close()
            try:
                await admin_srv.wait_closed()
            except Exception:
                pass
            cleanup_admin_state(self._admin_state_file)
            async with self._screen_lock:
                subs_ws = list(self._screen_subs.keys())
            for sws in subs_ws:
                await self._unsubscribe_live_screen(sws)
            for task in list(self._tasks):
                task.cancel()
            if self._tasks:
                await asyncio.gather(*self._tasks, return_exceptions=True)
