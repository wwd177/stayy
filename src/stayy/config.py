from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from dotenv import dotenv_values, load_dotenv


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _parse_int(value: str | None, default: int) -> int:
    if value is None or value.strip() == "":
        return default
    return int(value.strip())


def _parse_float(value: str | None, default: float) -> float:
    if value is None or value.strip() == "":
        return default
    return float(value.strip())


def _parse_csv(value: str | None) -> tuple[str, ...]:
    if not value or not value.strip():
        return ()
    return tuple(part.strip() for part in value.split(",") if part.strip())


def resolve_agy_executable(configured: str) -> str:
    """Resolve agy binary path, checking common install locations on Windows / macOS / Linux."""
    configured = configured.strip() or "agy"
    found = shutil.which(configured)
    if found:
        return found

    direct = Path(configured)
    if direct.is_file():
        return str(direct)

    home = Path.home()
    local_app_data = os.getenv("LOCALAPPDATA")
    candidates = [
        home / ".gemini" / "bin" / "agy.exe",
        home / ".gemini" / "bin" / "agy",
        home / ".local" / "bin" / "agy.exe",
        home / ".local" / "bin" / "agy",
        Path("/Applications/Antigravity.app/Contents/Resources/app/bin/agy"),
        Path("/opt/homebrew/bin/agy"),
        Path("/usr/local/bin/agy"),
    ]
    if local_app_data:
        candidates.insert(0, Path(local_app_data) / "Programs" / "Antigravity" / "bin" / "agy.exe")
        candidates.insert(0, Path(local_app_data) / "agy" / "bin" / "agy.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    return configured


@dataclass(frozen=True)
class BridgeConfig:
    agy_executable: str
    agy_workspace: Path
    agy_model: str = ""
    agy_effort: str = ""
    # Security default: MUST default to False everywhere so CLI permissions are never bypassed silently.
    agy_dangerously_skip_permissions: bool = False
    agy_timeout_seconds: int = 300
    progress_notice_delay_seconds: int = 0
    log_level: str = "INFO"
    agy_system_prompt: str = ""
    user_memory_file: Path | None = None
    agy_prewarm: bool = False
    agy_fallback_models: tuple[str, ...] = ()
    quota_cooldown_minutes: int = 60
    cache_clean_interval_hours: float = 6.0
    web_pwa_enabled: bool = True
    web_pwa_host: str = "0.0.0.0"
    web_pwa_port: int = 8766
    web_access_token: str = ""
    # Stayy security, multi-user beacon isolation, proxy trust & notification config
    remote_desktop_enabled: bool = False
    remote_clipboard_enabled: bool = False
    beacon_enabled: bool = False
    beacon_git_remote: str = ""
    beacon_branch: str = "gh-pages"
    public_base_url: str = ""
    allowed_origins: tuple[str, ...] = ()
    trust_cf_proxy_headers: bool = False
    bark_push_url: str = ""
    bark_allow_private_host: bool = False
    # Multi-Agent ecosystem security & optional API provider configuration
    stayy_allow_agent_write: bool = False
    stayy_allow_local_llm_ports: tuple[int, ...] = (11434, 1234)
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com/v1"
    deepseek_model: str = "deepseek-chat"
    doubao_ark_api_key: str = ""
    doubao_ark_base_url: str = "https://ark.cn-beijing.volces.com/api/v3"
    doubao_ark_model: str = ""
    ollama_model: str = ""
    ollama_base_url: str = "http://127.0.0.1:11434/v1"

    def build_session_instructions(self) -> str:
        """Combine persona prompt and latest persistent user memory (re-read fresh per new session)."""
        parts: list[str] = []
        if self.agy_system_prompt.strip():
            parts.append(self.agy_system_prompt.strip())
        if self.user_memory_file is not None:
            mem_path = self.user_memory_file
            mem_text = ""
            if mem_path.is_file():
                try:
                    mem_text = mem_path.read_text(encoding="utf-8").strip()
                except OSError:
                    mem_text = ""
            parts.append(
                f"【跨会话长期记忆文件：{mem_path}】\n"
                f"{mem_text or '（暂无记录）'}\n"
                f"提示：如果主人在聊天中透露了希望长期记住的个人偏好、常用目录、身份信息或习惯，你可以顺手静默更新这个 Markdown 文件，下次新会话会自动生效。"
            )
        return "\n\n".join(parts).strip()

    @classmethod
    def from_env(cls, env_path: Path | None = None) -> "BridgeConfig":
        file_vals: dict[str, str] = {}
        if env_path is not None and env_path.is_file():
            raw_vals = dotenv_values(env_path)
            file_vals = {k: v for k, v in raw_vals.items() if v is not None}
            load_dotenv(dotenv_path=env_path, override=True)
        else:
            load_dotenv(override=False)

        def _get(key: str, default: str = "") -> str:
            if key in file_vals:
                return file_vals[key]
            return os.getenv(key, default)

        workspace_raw = (_get("AGY_WORKSPACE") or "").strip()
        workspace = Path(workspace_raw).expanduser().resolve() if workspace_raw else Path.cwd().resolve()

        project_root = Path(__file__).resolve().parents[2]
        prompt_file_raw = (_get("AGY_SYSTEM_PROMPT_FILE") or "").strip()
        system_prompt = ""
        if prompt_file_raw.lower() not in {"none", "off", "false"}:
            if prompt_file_raw:
                pf = Path(prompt_file_raw).expanduser()
                if not pf.is_absolute():
                    pf = project_root / pf
                if not pf.is_file() and pf.name == "qq_persona.md":
                    pf = project_root / "prompts" / "persona.md"
            else:
                pf = project_root / "prompts" / "persona.md"
            if pf.is_file():
                system_prompt = pf.read_text(encoding="utf-8").strip()

        memory_file_raw = (_get("USER_MEMORY_FILE") or "").strip()
        memory_file: Path | None = None
        if memory_file_raw.lower() not in {"none", "off", "false"}:
            if memory_file_raw:
                mf = Path(memory_file_raw).expanduser()
                memory_file = mf if mf.is_absolute() else (project_root / mf)
            else:
                default_mf = project_root / "memory" / "user_profile.md"
                example_mf = project_root / "memory" / "user_profile.example.md"
                if not default_mf.is_file() and example_mf.is_file():
                    try:
                        default_mf.parent.mkdir(parents=True, exist_ok=True)
                        default_mf.write_text(example_mf.read_text(encoding="utf-8"), encoding="utf-8")
                    except OSError:
                        pass
                if default_mf.is_file():
                    memory_file = default_mf

        from .maintenance import DEFAULT_FALLBACK_MODELS

        fallback_raw = (_get("AGY_FALLBACK_MODELS") or "").strip()
        if fallback_raw.lower() in {"none", "off", "false"}:
            fallback_models: tuple[str, ...] = ()
        elif fallback_raw:
            fallback_models = tuple(
                part.strip() for part in fallback_raw.split(",") if part.strip()
            )
        else:
            fallback_models = DEFAULT_FALLBACK_MODELS

        return cls(
            agy_executable=resolve_agy_executable(_get("AGY_EXECUTABLE") or "agy"),
            agy_workspace=workspace,
            agy_model=(_get("AGY_MODEL") or "").strip(),
            agy_effort=(_get("AGY_EFFORT") or "").strip(),
            agy_dangerously_skip_permissions=_parse_bool(
                _get("AGY_DANGEROUSLY_SKIP_PERMISSIONS"), False
            ),
            agy_timeout_seconds=max(10, _parse_int(_get("AGY_TIMEOUT_SECONDS"), 300)),
            progress_notice_delay_seconds=max(
                0, _parse_int(_get("PROGRESS_NOTICE_DELAY_SECONDS"), 0)
            ),
            log_level=(_get("LOG_LEVEL") or "INFO").strip().upper(),
            agy_system_prompt=system_prompt,
            user_memory_file=memory_file,
            agy_prewarm=_parse_bool(_get("AGY_PREWARM"), False),
            agy_fallback_models=fallback_models,
            quota_cooldown_minutes=max(1, _parse_int(_get("QUOTA_COOLDOWN_MINUTES"), 60)),
            cache_clean_interval_hours=max(
                0.0, _parse_float(_get("CACHE_CLEAN_INTERVAL_HOURS"), 6.0)
            ),
            web_pwa_enabled=_parse_bool(_get("WEB_PWA_ENABLED"), True),
            web_pwa_host=(_get("WEB_PWA_HOST") or "0.0.0.0").strip(),
            web_pwa_port=_parse_int(_get("WEB_PWA_PORT"), 8766),
            web_access_token=(_get("WEB_ACCESS_TOKEN") or "").strip(),
            remote_desktop_enabled=_parse_bool(_get("REMOTE_DESKTOP_ENABLED"), False),
            remote_clipboard_enabled=_parse_bool(_get("REMOTE_CLIPBOARD_ENABLED"), False),
            beacon_enabled=_parse_bool(_get("BEACON_ENABLED"), False),
            beacon_git_remote=(_get("BEACON_GIT_REMOTE") or "").strip(),
            beacon_branch=(_get("BEACON_BRANCH") or "gh-pages").strip() or "gh-pages",
            public_base_url=(_get("PUBLIC_BASE_URL") or "").strip().rstrip("/"),
            allowed_origins=_parse_csv(_get("ALLOWED_ORIGINS")),
            trust_cf_proxy_headers=_parse_bool(_get("TRUST_CF_PROXY_HEADERS"), False),
            bark_push_url=(_get("BARK_PUSH_URL") or "").strip(),
            bark_allow_private_host=_parse_bool(_get("BARK_ALLOW_PRIVATE_HOST"), False),
            stayy_allow_agent_write=_parse_bool(_get("STAYY_ALLOW_AGENT_WRITE"), False),
            stayy_allow_local_llm_ports=tuple(
                int(p)
                for p in _parse_csv(_get("STAYY_ALLOW_LOCAL_LLM_PORTS") or "11434,1234")
                if p.isdigit() and 1 <= int(p) <= 65535
            )
            or (11434, 1234),
            deepseek_api_key=(_get("DEEPSEEK_API_KEY") or "").strip(),
            deepseek_base_url=(_get("DEEPSEEK_BASE_URL") or "https://api.deepseek.com/v1").strip().rstrip("/"),
            deepseek_model=(_get("DEEPSEEK_MODEL") or "deepseek-chat").strip() or "deepseek-chat",
            doubao_ark_api_key=(_get("DOUBAO_ARK_API_KEY") or "").strip(),
            doubao_ark_base_url=(_get("DOUBAO_ARK_BASE_URL") or "https://ark.cn-beijing.volces.com/api/v3").strip().rstrip("/"),
            doubao_ark_model=(_get("DOUBAO_ARK_MODEL") or "").strip(),
            ollama_model=(_get("OLLAMA_MODEL") or "").strip(),
            ollama_base_url=(_get("OLLAMA_BASE_URL") or "http://127.0.0.1:11434/v1").strip().rstrip("/"),
        )
