"""Central multi-agent registry combining native CLIs, OpenAI-compatible APIs, and desktop AI apps."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from ..config import BridgeConfig
from ..desktop_tools import find_codex_cli_executable
from .base import AgentSpec
from .cli_adapters import (
    discover_copilot_installation,
    discover_dsh_installation,
    discover_workbuddy_installation,
)
from .desktop_apps import discover_desktop_ai_apps, launch_desktop_ai_app
from .local_config import load_local_agent_overrides
from .openai_compat import validate_llm_endpoint_url


class AgentRegistry:
    """Discovers and tracks all local & API AI backends with sanitized capability serialization."""

    def __init__(
        self,
        config: BridgeConfig,
        *,
        project_dir: Path | None = None,
        runtime_dir: Path | None = None,
        ide_store_dir: Path | None = None,
        codex_cli_path: Path | None = None,
        local_app_data: Path | None = None,
        has_pc_ide_sender: bool = False,
    ) -> None:
        self.config = config
        self.project_dir = project_dir or Path(__file__).resolve().parents[3]
        self.runtime_dir = runtime_dir or (self.project_dir / ".runtime")
        self.ide_store_dir = ide_store_dir
        self.codex_cli_path = codex_cli_path
        self.local_app_data = local_app_data
        self.has_pc_ide_sender = has_pc_ide_sender
        self._specs: dict[str, AgentSpec] = {}
        self._desktop_apps: dict[str, dict[str, Any]] = {}
        self.refresh()

    def refresh(self) -> None:
        la = self.local_app_data or Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        overrides = load_local_agent_overrides(self.project_dir)
        allow_write = bool(self.config.stayy_allow_agent_write)

        specs: dict[str, AgentSpec] = {}

        # 1. Antigravity IDE (PC synced)
        ide_exe = la / "Programs" / "Antigravity" / "Antigravity.exe"
        ide_root = self.ide_store_dir or (Path.home() / ".gemini" / "antigravity")
        ide_avail = bool(self.has_pc_ide_sender or ide_exe.is_file() or (ide_root / "brain").is_dir())
        specs["ide"] = AgentSpec(
            id="ide",
            name="Antigravity 电脑端",
            vendor="Google DeepMind",
            kind="native_cli",
            store="ide",
            description="同步电脑端 Antigravity IDE 对话流与工作区",
            accent="#10b981",
            badge="AG",
            installed=ide_avail,
            configured=ide_avail,
            read_only_enforced=False,
            capabilities={"chat": ide_avail, "stream": True, "history": True, "resume": True, "cancel": False, "read_only_default": False},
        )

        # 2. OpenAI Codex Desktop / CLI
        codex_bin = self.codex_cli_path or find_codex_cli_executable()
        codex_avail = codex_bin is not None
        specs["codex"] = AgentSpec(
            id="codex",
            name="Codex 电脑端",
            vendor="OpenAI",
            kind="native_cli",
            store="codex",
            description="OpenAI Codex 本地任务会话（支持中途撤销取消）",
            accent="#6366f1",
            badge="CX",
            installed=codex_avail,
            configured=codex_avail,
            read_only_enforced=not self.config.agy_dangerously_skip_permissions,
            capabilities={"chat": codex_avail, "stream": True, "history": True, "resume": True, "cancel": True, "read_only_default": True},
        )

        # 3. Antigravity CLI (`agy`)
        cli_avail = bool(shutil.which(self.config.agy_executable) or Path(self.config.agy_executable).is_file())
        specs["cli"] = AgentSpec(
            id="cli",
            name="独立随身助手",
            vendor="Google Antigravity CLI",
            kind="native_cli",
            store="cli",
            description="独立后台 `agy` 流式引擎（额度池自动容灾）",
            accent="#34d399",
            badge="CLI",
            installed=cli_avail,
            configured=cli_avail,
            read_only_enforced=not self.config.agy_dangerously_skip_permissions,
            capabilities={"chat": cli_avail, "stream": True, "history": True, "resume": True, "cancel": True, "read_only_default": True},
        )

        # 4. DeepSeek Harness (`dsh`)
        dsh_info = discover_dsh_installation(la)
        dsh_ok = bool(dsh_info)
        specs["dsh"] = AgentSpec(
            id="dsh",
            name="DeepSeek Harness",
            vendor="DeepSeek",
            kind="native_cli",
            store="dsh",
            description="DeepSeek Harness 本地插件化引擎（默认只读沙箱，防静默改码）",
            accent="#2563eb",
            badge="DS",
            installed=dsh_ok,
            configured=dsh_ok,
            read_only_enforced=not allow_write,
            capabilities={"chat": dsh_ok, "stream": True, "history": True, "resume": True, "cancel": True, "read_only_default": True},
            internal_meta={"install": dsh_info},
        )

        # 5. Tencent WorkBuddy (`workbuddy`)
        wb_info = discover_workbuddy_installation(la)
        wb_ok = bool(wb_info)
        specs["workbuddy"] = AgentSpec(
            id="workbuddy",
            name="WorkBuddy",
            vendor="腾讯",
            kind="native_cli",
            store="workbuddy",
            description="腾讯 WorkBuddy 办公研发助手（默认只读工具，保留本地对话历史）",
            accent="#0ea5e9",
            badge="WB",
            installed=wb_ok,
            configured=wb_ok,
            read_only_enforced=not allow_write,
            capabilities={"chat": wb_ok, "stream": True, "history": True, "resume": True, "cancel": True, "read_only_default": True},
            internal_meta={"install": wb_info},
        )

        # 6. GitHub Copilot CLI (`copilot`)
        cop_info = discover_copilot_installation(la)
        cop_ok = bool(cop_info)
        specs["copilot"] = AgentSpec(
            id="copilot",
            name="GitHub Copilot CLI",
            vendor="GitHub",
            kind="native_cli",
            store="copilot",
            description="GitHub Copilot 命令行引擎（默认禁用写工具与任意 Shell）",
            accent="#a855f7",
            badge="CP",
            installed=cop_ok,
            configured=cop_ok,
            read_only_enforced=not allow_write,
            capabilities={"chat": cop_ok, "stream": True, "history": True, "resume": True, "cancel": True, "read_only_default": True},
            internal_meta={"install": cop_info},
        )

        # 7. Built-in OpenAI-compatible API agents (Doubao Ark, DeepSeek API, Ollama)
        api_presets = [
            {
                "id": "doubao_api",
                "name": "豆包 (火山方舟 Ark)",
                "vendor": "字节跳动",
                "accent": "#38bdf8",
                "badge": "DB",
                "base_url": self.config.doubao_ark_base_url,
                "api_key": self.config.doubao_ark_api_key,
                "model": self.config.doubao_ark_model,
                "description": "配置 DOUBAO_ARK_API_KEY + MODEL 即开启云端流式对话；未配置可用下方豆包桌面直控",
            },
            {
                "id": "deepseek_api",
                "name": "DeepSeek API",
                "vendor": "DeepSeek",
                "accent": "#0284c7",
                "badge": "R1",
                "base_url": self.config.deepseek_base_url,
                "api_key": self.config.deepseek_api_key,
                "model": self.config.deepseek_model,
                "description": "DeepSeek 官方云端直连 API（支持思考推理折叠输出）",
            },
            {
                "id": "ollama",
                "name": "本机 Ollama",
                "vendor": "Ollama",
                "accent": "#a3e635",
                "badge": "OL",
                "base_url": self.config.ollama_base_url,
                "api_key": "",
                "model": self.config.ollama_model,
                "description": "仅通过本机白名单回环端口连接本地 Ollama 模型",
            },
        ]
        for row in overrides.get("custom_apis", []):
            raw_id = str(row.get("id") or "").strip().lower()
            if not raw_id or raw_id in specs:
                continue
            store_id = raw_id if raw_id.startswith("api:") else f"api:{raw_id}"
            api_presets.append(
                {
                    "id": store_id,
                    "name": str(row.get("name") or raw_id),
                    "vendor": str(row.get("vendor") or "自定义 API"),
                    "accent": str(row.get("accent") or "#f59e0b"),
                    "badge": str(row.get("badge") or "API"),
                    "base_url": str(row.get("base_url") or "").strip().rstrip("/"),
                    "api_key": str(row.get("api_key") or "").strip(),
                    "model": str(row.get("model") or "").strip(),
                    "description": str(row.get("description") or "本地 agents.local.json 自定义模型端点"),
                }
            )

        for ap in api_presets:
            aid = ap["id"]
            burl = ap["base_url"]
            key = ap["api_key"]
            mod = ap["model"]
            is_local = aid == "ollama" or burl.startswith("http://127.0.0.1") or burl.startswith("http://localhost")
            ok_url, _, _, _ = (
                validate_llm_endpoint_url(burl, allow_local_ports=self.config.stayy_allow_local_llm_ports)
                if burl
                else (False, "", [], False)
            )
            cfg_ready = bool(ok_url and mod and (is_local or key))
            specs[aid] = AgentSpec(
                id=aid,
                name=ap["name"],
                vendor=ap["vendor"],
                kind="openai_api",
                store=aid,
                description=ap["description"],
                accent=ap["accent"],
                badge=ap["badge"],
                installed=True,
                configured=cfg_ready,
                read_only_enforced=True,
                capabilities={"chat": cfg_ready, "stream": True, "history": True, "resume": True, "cancel": True, "read_only_default": True},
                internal_meta={"base_url": burl, "api_key": key, "model": mod},
            )

        # 8. Desktop AI Clients (Doubao Desktop, TRAE CN, Gemini Desktop, Grok Bot, WorkBuddy, etc.)
        self._desktop_apps = discover_desktop_ai_apps(overrides.get("custom_desktop_apps"))
        for app_id, app_info in self._desktop_apps.items():
            specs[f"app:{app_id}"] = AgentSpec(
                id=app_id,
                name=app_info["name"],
                vendor=app_info["vendor"],
                kind="desktop_app",
                store=f"app:{app_id}",
                description=app_info["description"],
                accent=app_info["accent"],
                badge=app_info["badge"],
                installed=True,
                configured=True,
                running=bool(app_info["running"]),
                read_only_enforced=True,
                capabilities={"desktop_launch": True, "loupe_control": True},
                internal_meta={"desktop_entry": app_info},
            )

        self._specs = specs

    def get_agent(self, store_or_id: str) -> AgentSpec | None:
        return self._specs.get(store_or_id)

    def native_chat_stores(self) -> set[str]:
        return {
            s.store
            for s in self._specs.values()
            if s.kind in {"native_cli", "openai_api"} and (s.configured or s.store in {"ide", "codex", "cli"})
        }

    def all_known_chat_stores(self) -> set[str]:
        return {s.store for s in self._specs.values() if s.kind in {"native_cli", "openai_api"}}

    def desktop_app_entry(self, app_id: str) -> dict[str, Any] | None:
        return self._desktop_apps.get((app_id or "").strip().lower())

    def launch_desktop_app(self, app_id: str) -> tuple[bool, bool, str]:
        entry = self.desktop_app_entry(app_id)
        ok, focused, note = launch_desktop_ai_app(app_id, entry)
        if ok:
            self.refresh()
        return ok, focused, note

    def public_catalog(self) -> list[dict[str, Any]]:
        """Return strictly sanitized agent list for mobile clients (ZERO API keys or local exe paths)."""
        return [spec.to_public_dict() for spec in self._specs.values()]
