"""Plugin-based multi-agent ecosystem core for Stayy."""

from .base import (
    AgentRunResult,
    AgentSpec,
    AgentTurnCallbacks,
    is_path_safe_no_reparse,
    is_process_elevated,
    kill_pid_tree_sync,
    make_composite_slot_key,
)
from .registry import AgentRegistry

__all__ = [
    "AgentRegistry",
    "AgentRunResult",
    "AgentSpec",
    "AgentTurnCallbacks",
    "is_path_safe_no_reparse",
    "is_process_elevated",
    "kill_pid_tree_sync",
    "make_composite_slot_key",
]
