"""Base models, security path guards, and lifecycle helpers for Stayy AI agent adapters."""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import os
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


@dataclass
class AgentTurnCallbacks:
    """Async callbacks emitted by streaming CLI / API adapters during a single turn."""

    on_session: Callable[[str], Awaitable[None]] | None = None
    on_delta: Callable[[str], Awaitable[None]] | None = None
    on_thought: Callable[[str], Awaitable[None]] | None = None
    on_tool: Callable[[str, str], Awaitable[None]] | None = None
    on_demote_to_thought: Callable[[], Awaitable[None]] | None = None
    on_proc_started: Callable[[asyncio.subprocess.Process], Awaitable[None]] | None = None
    on_proc_finished: Callable[[asyncio.subprocess.Process], Awaitable[None]] | None = None


@dataclass
class AgentRunResult:
    ok: bool
    session_id: str = ""
    text: str = ""
    thought: str = ""
    error: str = ""
    aborted: bool = False


@dataclass
class AgentSpec:
    """Metadata and security capability descriptor for a registered AI agent or desktop app."""

    id: str
    name: str
    vendor: str
    kind: str  # "native_cli" | "openai_api" | "desktop_app"
    store: str
    description: str = ""
    accent: str = "#10b981"
    badge: str = ""
    installed: bool = False
    configured: bool = False
    running: bool = False
    read_only_enforced: bool = True
    capabilities: dict[str, bool] = field(default_factory=dict)
    internal_meta: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize strictly non-sensitive agent status & capabilities for mobile UI (`hello`)."""
        return {
            "id": self.id,
            "name": self.name,
            "vendor": self.vendor,
            "kind": self.kind,
            "store": self.store,
            "description": self.description,
            "accent": self.accent,
            "badge": self.badge,
            "installed": self.installed,
            "configured": self.configured,
            "running": self.running,
            "read_only_enforced": self.read_only_enforced,
            "capabilities": dict(self.capabilities),
        }


def is_process_elevated() -> bool:
    """Return True if the current Stayy process holds administrator/root privileges."""
    try:
        if sys.platform == "win32":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
    except Exception:
        return False
    return False


def is_path_safe_no_reparse(path: Path) -> bool:
    """Verify `path` and all non-root ancestor directories contain zero symlinks or reparse junctions."""
    try:
        raw_abs = Path(os.path.abspath(str(path)))
        if not raw_abs.exists():
            return False
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        parts_to_check = [raw_abs] + list(raw_abs.parents)
        anchor = Path(raw_abs.anchor) if raw_abs.anchor else Path("/")
        for p in parts_to_check:
            if p == anchor:
                continue
            try:
                if p.is_symlink():
                    return False
                st = os.lstat(p)
                if stat.S_ISLNK(st.st_mode):
                    return False
                attrs = getattr(st, "st_file_attributes", 0)
                if reparse_flag and (attrs & reparse_flag):
                    return False
            except OSError:
                return False
        return True
    except Exception:
        return False


def kill_pid_tree_sync(pid: int) -> None:
    """Terminate a spawned subprocess tree cleanly without leaking grandchildren."""
    if not pid or pid <= 0:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/PID", str(int(pid)), "/T", "/F"],
                capture_output=True,
                timeout=6,
                creationflags=CREATE_NO_WINDOW,
            )
        else:
            os.kill(int(pid), 9)
    except Exception:
        pass


def make_composite_slot_key(store: str, workspace: str, conv_id: str) -> str:
    """Build collision-free composite lock/slot identity across `(store, workspace, conv_id)`."""
    ws_norm = os.path.normcase(str(Path(workspace).resolve())) if workspace else ""
    ws_hash = hashlib.sha256(ws_norm.encode("utf-8")).hexdigest()[:10] if ws_norm else "global"
    return f"{(store or 'cli').strip()}::{ws_hash}::{(conv_id or '').strip()}"
