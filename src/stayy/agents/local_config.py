"""Read-only loader for optional host-local custom agent definitions (`agents.local.json`).

Mobile WebSocket clients can NEVER inspect raw file paths, read API keys, or edit this file.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def load_local_agent_overrides(project_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """Load optional `<project_dir>/agents.local.json` cleanly with strict structural validation."""
    cfg_path = project_dir / "agents.local.json"
    out: dict[str, list[dict[str, Any]]] = {"custom_apis": [], "custom_desktop_apps": []}
    if not cfg_path.is_file():
        return out

    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return out
        raw_apis = data.get("custom_apis")
        if isinstance(raw_apis, list):
            for row in raw_apis[:20]:
                if isinstance(row, dict) and str(row.get("id") or "").strip():
                    out["custom_apis"].append(dict(row))
        raw_apps = data.get("custom_desktop_apps")
        if isinstance(raw_apps, list):
            for row in raw_apps[:20]:
                if isinstance(row, dict) and str(row.get("id") or "").strip():
                    out["custom_desktop_apps"].append(dict(row))
    except Exception as exc:
        logger.warning("Ignoring invalid agents.local.json: %s", exc)
    return out
