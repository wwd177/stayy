"""Read-only approval prompt inspector & Branch-B TOCTOU guard for Stayy.

Per M0 architectural ruling:
Antigravity IDE's local `ConversationService` does not expose an atomic request-instance ID approval
endpoint. To eliminate A -> B TOCTOU prompt-substitution risks (even for identically worded
sequential prompts), Stayy enforces Branch B:
1. Scans pending approval controls read-only and extracts bounded human-readable context summaries.
2. Enforces strict fail-closed validation (marks prompts without verified `conversation_id` or missing
   context as `unverified`).
3. Refuses all blind remote auto-click (`ide_action_invoke`) requests server-side with **zero desktop
   input**, directing users to inspect and click safely via the 3.2x optical loupe remote screen.
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from typing import Any

from .desktop_tools import inspect_antigravity_ide_actions

logger = logging.getLogger(__name__)


class ApprovalReadonlyTracker:
    """Tracks read-only approval detections and assigns distinct `event_key` per appearance."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active_keys: dict[tuple[int, str, str], int] = {}
        self._seq: int = 0

    def normalize_snapshot(self, raw_actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now_ms = int(time.time() * 1000)
        present_triples: set[tuple[int, str, str]] = set()
        normalized: list[dict[str, Any]] = []

        with self._lock:
            for item in raw_actions:
                if not isinstance(item, dict):
                    continue
                hwnd = int(item.get("hwnd") or 0)
                cid = str(item.get("conversation_id") or "").strip()
                label = str(item.get("label") or "").strip()
                summary = str(item.get("context_summary") or "").strip()
                truncated = bool(item.get("truncated"))
                verified = bool(cid) and bool(summary) and bool(item.get("verified", True))
                reason = str(item.get("reason") or "")
                if not cid:
                    verified = False
                    reason = reason or "unverified_window"
                elif not summary:
                    verified = False
                    reason = reason or "missing_context"

                triple = (hwnd, cid, label)
                present_triples.add(triple)
                if triple not in self._active_keys:
                    self._seq += 1
                    self._active_keys[triple] = self._seq
                occ_seq = self._active_keys[triple]
                event_key = f"{hwnd}:{cid}:{label}:{occ_seq}"

                normalized.append(
                    {
                        "hwnd": hwnd,
                        "conversation_id": cid,
                        "label": label,
                        "context_summary": summary,
                        "truncated": truncated,
                        "verified": verified,
                        "reason": reason,
                        "mode": "manual_screen_only",
                        "event_key": event_key,
                        "detected_ms": now_ms,
                    }
                )

            # Once a prompt disappears, forget its occurrence so a future identical prompt gets a new event_key!
            gone = [k for k in self._active_keys if k not in present_triples]
            for k in gone:
                self._active_keys.pop(k, None)

        return normalized

    def clear(self) -> None:
        with self._lock:
            self._active_keys.clear()


def deny_auto_invoke() -> tuple[bool, str, str]:
    """Enforce Branch B server-side rejection for blind approval auto-invocation (0 desktop inputs)."""
    return (
        False,
        "manual_screen_required",
        "为防连续同文审批弹窗替身误触，Stayy 已禁用盲点自动放行；请点击「🔍 放大镜看屏」亲自确认。",
    )


def inspect_ide_actions_readonly(
    conversation_id: str = "",
    *,
    tracker: ApprovalReadonlyTracker | None = None,
) -> list[dict[str, Any]]:
    """Scan open Antigravity windows read-only and never issue clickable tokens."""
    if sys.platform != "win32":
        return []
    raw = inspect_antigravity_ide_actions(conversation_id)
    if tracker is not None:
        return tracker.normalize_snapshot(raw)
    return ApprovalReadonlyTracker().normalize_snapshot(raw)
