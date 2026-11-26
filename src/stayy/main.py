from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

from .agy_session import SessionManager
from .config import BridgeConfig
from .setup_wizard import detect_local_backends
from .web_pwa import WebPwaServer, ensure_web_access_token, get_lan_ipv4


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _check_preflight(config: BridgeConfig) -> bool:
    logger = logging.getLogger("stayy")
    ok = True

    if not config.web_pwa_enabled:
        logger.error("WEB_PWA_ENABLED 当前为关闭状态，请在 .env 中设为 true。")
        ok = False

    backends = detect_local_backends(config.agy_executable)
    if not any(v["available"] for v in backends.values()):
        logger.error(
            "未检测到可用的 Antigravity IDE、Codex Desktop 或 agy CLI。请先安装至少其一后重试。"
        )
        ok = False
    else:
        avail = [k for k, v in backends.items() if v["available"]]
        logger.info("已检测本机 AI 后端: %s", ", ".join(avail))

    if config.agy_dangerously_skip_permissions:
        logger.warning(
            "[安全提示] AGY_DANGEROUSLY_SKIP_PERMISSIONS=true 已显式开启：CLI 子进程将跳过权限确认弹窗！"
        )

    return ok


async def _run_async(config: BridgeConfig, env_file: Path) -> None:
    logger = logging.getLogger("stayy")
    logger.info("=== Stayy 核心网关启动 (port=%d) ===", config.web_pwa_port)
    logger.info("默认模型         : %s", config.agy_model or "默认")
    logger.info(
        "额度自动容灾链   : %s (冷却 %dm)",
        " -> ".join(config.agy_fallback_models[:5]) if config.agy_fallback_models else "未启用",
        config.quota_cooldown_minutes,
    )

    sessions = SessionManager(config)
    web_token = ensure_web_access_token(env_file, config.web_access_token)
    lan_ip = get_lan_ipv4()
    logger.info(
        "Stayy 局域网入口 : http://%s:%d/ （密钥保护与代次撤销已启用）",
        lan_ip,
        config.web_pwa_port,
    )
    pwa = WebPwaServer(config, session_manager=sessions, access_token=web_token, env_path=env_file)

    try:
        await pwa.run()
    except asyncio.CancelledError:
        pass
    finally:
        await sessions.shutdown_all()


def main() -> None:
    env_file = Path(".env")
    if not env_file.is_file():
        from .setup_wizard import ensure_env_configured
        ensure_env_configured(Path.cwd())

    try:
        config = BridgeConfig.from_env(env_file)
    except Exception as exc:
        print(f"配置加载失败: {exc}", file=sys.stderr)
        sys.exit(1)

    _setup_logging(config.log_level)

    if not _check_preflight(config):
        sys.exit(1)

    try:
        asyncio.run(_run_async(config, env_file))
    except KeyboardInterrupt:
        logging.getLogger("stayy").info("收到退出信号，已安全关闭 Stayy 服务。")


if __name__ == "__main__":
    main()
