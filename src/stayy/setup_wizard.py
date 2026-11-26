"""Automated installer, configurator, and zero-leak health doctor for Stayy.

Examples:
  python -m stayy.setup_wizard --non-interactive --with-tunnel --create-shortcut --doctor --json
  python -m stayy.setup_wizard --doctor --json
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any

from dotenv import dotenv_values

from .auth import atomic_write_env_token
from .config import BridgeConfig, resolve_agy_executable
from .conversations import _default_codex_dir, _default_ide_dir, list_local_conversations
from .desktop_tools import find_codex_cli_executable
from .notifier import redact_url
from .web_pwa import get_lan_ipv4

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


def _update_env_key(lines: list[str], key: str, value: str, *, only_if_empty: bool = False) -> list[str]:
    prefix = f"{key}="
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(prefix):
            cur_val = stripped[len(prefix) :].strip()
            if only_if_empty and cur_val and cur_val != "change-me":
                return lines
            lines[idx] = f"{key}={value}"
            return lines
    lines.append(f"{key}={value}")
    return lines


def ensure_env_configured(
    project_dir: Path = PROJECT_ROOT,
    *,
    force_overwrite: bool = False,
    workspace: str = "",
    pwa_port: int = 0,
) -> Path:
    """Create or update .env safely with strong cryptographic tokens and secure defaults."""
    env_path = project_dir / ".env"
    example_path = project_dir / ".env.example"

    if not env_path.is_file() or force_overwrite:
        if example_path.is_file():
            base_text = example_path.read_text(encoding="utf-8")
        else:
            base_text = (
                "WEB_PWA_ENABLED=true\n"
                "WEB_PWA_PORT=8766\n"
                "CLOUDFLARE_TUNNEL_ENABLED=true\n"
                "AGY_DANGEROUSLY_SKIP_PERMISSIONS=false\n"
                "BEACON_ENABLED=false\n"
            )
        env_path.write_text(base_text, encoding="utf-8")

    deprecated_prefixes = (
        "ONEBOT_",
        "ALLOWED_QQ_USERS=",
        "BOT_QQ=",
        "NAPCAT_DIR=",
        "CLEAN_QQ_FORMATTING=",
        "MAX_MESSAGE_LENGTH=",
        "MESSAGE_DEBOUNCE_SECONDS=",
        "AGY_PREWARM_USERS=",
    )
    lines = [
        ln
        for ln in env_path.read_text(encoding="utf-8").splitlines()
        if not any(ln.strip().startswith(p) for p in deprecated_prefixes)
    ]
    lines = _update_env_key(lines, "WEB_ACCESS_TOKEN", secrets.token_urlsafe(24), only_if_empty=True)
    lines = _update_env_key(lines, "AGY_SYSTEM_PROMPT_FILE", "prompts/persona.md")
    lines = _update_env_key(lines, "AGY_DANGEROUSLY_SKIP_PERMISSIONS", "false", only_if_empty=True)
    lines = _update_env_key(lines, "WEB_PWA_PORT", "8766", only_if_empty=True)

    if workspace.strip():
        lines = _update_env_key(lines, "AGY_WORKSPACE", str(Path(workspace.strip()).expanduser().resolve()))
    if pwa_port > 0:
        lines = _update_env_key(lines, "WEB_PWA_PORT", str(pwa_port))

    tmp = env_path.with_name(f".{env_path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(tmp, env_path)

    mem_target = project_dir / "memory" / "user_profile.md"
    mem_example = project_dir / "memory" / "user_profile.example.md"
    if not mem_target.is_file() and mem_example.is_file():
        mem_target.parent.mkdir(parents=True, exist_ok=True)
        mem_target.write_text(mem_example.read_text(encoding="utf-8"), encoding="utf-8")

    return env_path


def ensure_cloudflared(project_dir: Path = PROJECT_ROOT) -> tuple[bool, str]:
    """Locate or download official cloudflared binary for encrypted 4G/5G tunnel access."""
    bin_dir = project_dir / "bin"
    exe_name = "cloudflared.exe" if sys.platform == "win32" else "cloudflared"
    local_bin = bin_dir / exe_name
    if local_bin.is_file():
        return True, str(local_bin)

    sys_found = shutil.which("cloudflared")
    if sys_found:
        return True, sys_found

    machine = platform.machine().lower()
    is_arm = "arm" in machine or "aarch64" in machine
    if sys.platform == "win32":
        asset = "cloudflared-windows-arm64.exe" if is_arm else "cloudflared-windows-amd64.exe"
    elif sys.platform == "linux":
        asset = "cloudflared-linux-arm64" if is_arm else "cloudflared-linux-amd64"
    else:
        return False, "macOS 请运行 `brew install cloudflared` 安装外网隧道组件（局域网扫码无需此组件）"

    url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/{asset}"
    try:
        bin_dir.mkdir(parents=True, exist_ok=True)
        tmp_dest = bin_dir / f"{exe_name}.part"
        req = urllib.request.Request(url, headers={"User-Agent": "Stayy-Setup/0.1"})
        with urllib.request.urlopen(req, timeout=60) as resp, tmp_dest.open("wb") as out:
            shutil.copyfileobj(resp, out)
        tmp_dest.replace(local_bin)
        if sys.platform != "win32":
            local_bin.chmod(0o755)
        return True, str(local_bin)
    except Exception as exc:
        return False, f"自动下载 cloudflared 失败（不影响同 Wi-Fi 局域网使用）：{exc}"


def _read_lnk_metadata_win32(lnk_path: Path) -> dict[str, str]:
    """Inspect a Windows `.lnk` file's TargetPath, Arguments, and WorkingDirectory safely."""
    if sys.platform != "win32" or not lnk_path.is_file():
        return {}
    ps = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$ws = New-Object -ComObject WScript.Shell; "
        f"$s = $ws.CreateShortcut('{str(lnk_path).replace(chr(39), chr(39)*2)}'); "
        "ConvertTo-Json -Compress ([PSCustomObject]@{target=$s.TargetPath;args=$s.Arguments;wd=$s.WorkingDirectory})"
    )
    encoded = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            creationflags=CREATE_NO_WINDOW,
        )
        if res.returncode == 0 and res.stdout.strip():
            obj = json.loads(res.stdout.strip().splitlines()[-1])
            return {k: str(v or "") for k, v in obj.items()}
    except Exception:
        pass
    return {}


def is_shortcut_owned_by_stayy(meta: dict[str, str], project_dir: Path) -> bool:
    """Return True ONLY if the shortcut metadata explicitly targets this Stayy project directory."""
    if not meta:
        return False
    proj_norm = os.path.normcase(str(project_dir.resolve()))
    wd_norm = os.path.normcase(str(Path(meta.get("wd") or "").resolve())) if meta.get("wd") else ""
    target_norm = os.path.normcase(meta.get("target") or "")
    args_norm = (meta.get("args") or "").lower()
    if "-m stayy." in args_norm and (wd_norm == proj_norm or proj_norm in target_norm):
        return True
    return False


def create_windows_desktop_shortcut(
    project_dir: Path = PROJECT_ROOT,
    shortcut_name: str = "Stayy.lnk",
    *,
    desktop_dir: Path | None = None,
) -> tuple[bool, str]:
    """Create a Windows Desktop `Stayy.lnk` without EVER deleting Antigravity / other user shortcuts."""
    if sys.platform != "win32":
        return False, "桌面 .lnk 快捷方式仅适用于 Windows"

    venv_pyw = project_dir / ".venv" / "Scripts" / "pythonw.exe"
    target_exe = venv_pyw if venv_pyw.is_file() else Path(sys.executable)
    icon_path = project_dir / "assets" / "app.ico"

    desk_expr = (
        f"'{str(desktop_dir).replace(chr(39), chr(39)*2)}'"
        if desktop_dir is not None
        else "[Environment]::GetFolderPath('Desktop')"
    )
    resolved_desk = desktop_dir if desktop_dir is not None else Path.home() / "Desktop"
    lnk_candidate = (
        (desktop_dir / shortcut_name)
        if desktop_dir is not None
        else Path(os.path.expandvars(r"%USERPROFILE%\Desktop")) / shortcut_name
    )

    # Check pre-existing Stayy.lnk target before overwriting!
    if desktop_dir is not None and lnk_candidate.is_file():
        meta = _read_lnk_metadata_win32(lnk_candidate)
        if meta and not is_shortcut_owned_by_stayy(meta, project_dir):
            # Preserve user's custom unrelated shortcut under the same name!
            shortcut_name = "Stayy Remote Hub.lnk"

    ps_script = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        f"$desk = {desk_expr}; "
        f"$lnkPath = Join-Path $desk '{shortcut_name.replace(chr(39), chr(39)*2)}'; "
        "if (Test-Path -LiteralPath $lnkPath) { "
        "  $wsChk = New-Object -ComObject WScript.Shell; "
        "  $existing = $wsChk.CreateShortcut($lnkPath); "
        f"  $projNorm = '{str(project_dir.resolve()).replace(chr(39), chr(39)*2)}'.ToLowerInvariant(); "
        "  $wdLow = ([string]$existing.WorkingDirectory).ToLowerInvariant(); "
        "  $argLow = ([string]$existing.Arguments).ToLowerInvariant(); "
        "  if ($argLow -notlike '*-m stayy.*' -and $wdLow -ne $projNorm) { "
        "    $lnkPath = Join-Path $desk 'Stayy Remote Hub.lnk'; "
        "  } "
        "} "
        "$ws = New-Object -ComObject WScript.Shell; "
        "$s = $ws.CreateShortcut($lnkPath); "
        f"$s.TargetPath = '{str(target_exe).replace(chr(39), chr(39)*2)}'; "
        "$s.Arguments = '-X utf8 -m stayy.launcher'; "
        f"$s.WorkingDirectory = '{str(project_dir.resolve()).replace(chr(39), chr(39)*2)}'; "
        f"if (Test-Path '{str(icon_path).replace(chr(39), chr(39)*2)}') {{ $s.IconLocation = '{str(icon_path).replace(chr(39), chr(39)*2)},0' }}; "
        "$s.Description = 'Stayy — Hardened Local-First AI Coding & Precision PC Remote Hub'; "
        "$s.Save(); "
        "Write-Output $lnkPath"
    )
    encoded_cmd = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded_cmd],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
        if res.returncode == 0 and res.stdout.strip():
            return True, res.stdout.strip().splitlines()[-1]
        return False, (res.stderr or "创建快捷方式失败").strip()
    except Exception as exc:
        return False, str(exc)


def detect_local_backends(
    agy_executable: str = "agy",
    *,
    ide_store_dir: Path | None = None,
    codex_store_dir: Path | None = None,
    ide_exe_override: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Detect available local AI backends across Antigravity IDE, Codex Desktop, and `agy` CLI."""
    agy_resolved = resolve_agy_executable(agy_executable)
    cli_exists = bool(shutil.which(agy_resolved) or Path(agy_resolved).is_file())

    ide_dir = ide_store_dir if ide_store_dir is not None else _default_ide_dir()
    local_app_data = os.getenv("LOCALAPPDATA", "")
    ide_exe = ide_exe_override or (
        Path(local_app_data) / "Programs" / "Antigravity" / "Antigravity.exe" if local_app_data else Path("__missing__")
    )
    ide_exists = bool(
        ide_exe.is_file()
        or (ide_dir / "brain").is_dir()
        or (ide_dir / "conversation_summaries.db").is_file()
    )

    codex_dir = codex_store_dir if codex_store_dir is not None else _default_codex_dir()
    codex_cli = find_codex_cli_executable()
    codex_exists = bool(
        codex_cli is not None
        or (codex_dir / "sessions").is_dir()
        or (codex_dir / "session_index.jsonl").is_file()
        or any(codex_dir.glob("state_*.sqlite"))
    )

    return {
        "antigravity_ide": {"available": ide_exists, "detail": str(ide_exe if ide_exe.is_file() else ide_dir)},
        "codex_desktop": {"available": codex_exists, "detail": str(codex_cli or codex_dir)},
        "antigravity_cli": {"available": cli_exists, "detail": agy_resolved if cli_exists else "未安装 agy CLI"},
    }


def _scrub_secret_text(text: str, secrets_to_mask: list[str]) -> str:
    out = text
    for sec in secrets_to_mask:
        if sec and len(sec) >= 6:
            out = out.replace(sec, "***REDACTED***")
    return out


def run_doctor(
    project_dir: Path = PROJECT_ROOT,
    *,
    ide_store_dir: Path | None = None,
    codex_store_dir: Path | None = None,
    ide_exe_override: Path | None = None,
) -> dict[str, Any]:
    """Run comprehensive environment diagnostics with ZERO plaintext secret emission."""
    env_path = project_dir / ".env"
    checks: list[dict[str, Any]] = []

    py_ok = sys.version_info >= (3, 11)
    checks.append(
        {
            "name": "python_version",
            "ok": py_ok,
            "detail": f"Python {platform.python_version()} ({sys.executable})",
        }
    )

    env_vals = dotenv_values(env_path) if env_path.is_file() else {}
    agy_cfg = str(env_vals.get("AGY_EXECUTABLE") or "agy")
    raw_token = str(env_vals.get("WEB_ACCESS_TOKEN") or "").strip()
    raw_bark = str(env_vals.get("BARK_PUSH_URL") or "").strip()
    secret_list = [raw_token, raw_bark]

    backends = detect_local_backends(
        agy_cfg,
        ide_store_dir=ide_store_dir,
        codex_store_dir=codex_store_dir,
        ide_exe_override=ide_exe_override,
    )
    any_backend = any(v["available"] for v in backends.values())
    avail_names = [k for k, v in backends.items() if v["available"]]
    checks.append(
        {
            "name": "local_ai_backends",
            "ok": any_backend,
            "backends": backends,
            "detail": (
                f"已检测到本机 AI 后端：{', '.join(avail_names)}"
                if any_backend
                else "未检测到 Antigravity IDE、Codex Desktop 或 agy CLI，请先安装至少其一"
            ),
        }
    )

    cfg_ok = False
    pwa_lan_base_url = ""
    token_configured = False
    bark_configured = False
    bark_target_redacted = ""
    skip_perm_warn = False

    if env_path.is_file():
        try:
            cfg = BridgeConfig.from_env(env_path)
            if cfg.web_access_token:
                secret_list.append(cfg.web_access_token)
            if cfg.bark_push_url:
                secret_list.append(cfg.bark_push_url)
            token_configured = len(cfg.web_access_token.strip()) >= 16 and cfg.web_access_token.strip() != "change-me"
            cfg_ok = cfg.web_pwa_enabled and token_configured
            lan_ip = get_lan_ipv4()
            if cfg_ok:
                pwa_lan_base_url = f"http://{lan_ip}:{cfg.web_pwa_port}/"
            bark_configured = bool(cfg.bark_push_url)
            bark_target_redacted = redact_url(cfg.bark_push_url) if cfg.bark_push_url else ""
            skip_perm_warn = bool(cfg.agy_dangerously_skip_permissions)
        except Exception as exc:
            cfg_ok = False
            logger.debug("Doctor config parse error: %s", _scrub_secret_text(str(exc), secret_list))

    checks.append(
        {
            "name": "env_config",
            "ok": cfg_ok,
            "token_configured": token_configured,
            "bark_configured": bark_configured,
            "bark_target": bark_target_redacted,
            "skip_permissions_enabled": skip_perm_warn,
            "detail": ".env 配置已就绪（高强度访问密钥已启用，输出已脱敏）" if cfg_ok else ".env 未初始化或密钥无效",
        }
    )

    cf_bin = project_dir / "bin" / ("cloudflared.exe" if sys.platform == "win32" else "cloudflared")
    cf_path = str(cf_bin) if cf_bin.is_file() else (shutil.which("cloudflared") or "")
    checks.append(
        {
            "name": "cloudflare_tunnel_optional",
            "ok": True,
            "installed": bool(cf_path),
            "detail": cf_path if cf_path else "未安装（同 Wi-Fi 局域网与 Tailscale 不受影响）",
        }
    )

    try:
        convs = list_local_conversations(
            limit=500,
            ide_dir=ide_store_dir,
            codex_dir=codex_store_dir,
        )
        conv_detail = (
            f"已发现本机对话共 {len(convs)} 个"
            f"（Antigravity {sum(1 for x in convs if x.store=='ide')} · "
            f"Codex {sum(1 for x in convs if x.store=='codex')} · "
            f"远程 {sum(1 for x in convs if x.store=='cli')}）"
        )
    except Exception as exc:
        conv_detail = _scrub_secret_text(f"扫描会话异常：{exc}", secret_list)
    checks.append({"name": "local_conversations", "ok": True, "detail": conv_detail})

    overall = all(bool(c["ok"]) for c in checks)
    return {
        "ok": overall,
        "app_name": "Stayy",
        "project_dir": str(project_dir),
        "pwa_lan_url": pwa_lan_base_url,
        "token_configured": token_configured,
        "bark_configured": bark_configured,
        "bark_target": bark_target_redacted,
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stayy — 自动初始化与零泄漏环境自检工具")
    parser.add_argument("--non-interactive", action="store_true", help="无人值守一键配置")
    parser.add_argument("--workspace", default="", help="默认工作区目录路径")
    parser.add_argument("--port", type=int, default=0, help="移动端服务监听端口（默认 8766）")
    parser.add_argument("--with-tunnel", action="store_true", help="自动下载 cloudflared 以支持 4G/5G 外网连接")
    parser.add_argument("--create-shortcut", action="store_true", help="在 Windows 桌面创建 Stayy 快捷方式")
    parser.add_argument("--doctor", action="store_true", help="运行完整环境自检报告")
    parser.add_argument("--json", action="store_true", help="以脱敏 JSON 输出结果")
    args = parser.parse_args(argv)

    actions_taken: list[str] = []

    if not args.doctor or args.non_interactive or not (PROJECT_ROOT / ".env").is_file():
        env_file = ensure_env_configured(
            PROJECT_ROOT,
            workspace=args.workspace,
            pwa_port=args.port,
        )
        actions_taken.append(f"已配置环境变量文件：{env_file}")

    if args.with_tunnel:
        ok_cf, msg_cf = ensure_cloudflared(PROJECT_ROOT)
        actions_taken.append(f"外网隧道组件：{'已就绪 ' + msg_cf if ok_cf else msg_cf}")

    if args.create_shortcut and sys.platform == "win32":
        ok_sc, msg_sc = create_windows_desktop_shortcut(PROJECT_ROOT)
        actions_taken.append(f"桌面快捷方式：{'已创建 ' + msg_sc if ok_sc else msg_sc}")

    report = run_doctor(PROJECT_ROOT)
    report["actions"] = actions_taken

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("\n=== Stayy 部署自检报告 ===")
        for act in actions_taken:
            print(f"  [完成] {act}")
        for c in report["checks"]:
            mark = "OK" if c["ok"] else "FAIL"
            print(f"  [{mark}] {c['name']}: {c['detail']}")
        if report["pwa_lan_url"]:
            print(f"\n  手机端局域网入口: {report['pwa_lan_url']} （配对请使用启动器二维码，密钥不落地输出）")
            print("  启动桌面控制台  : .\\.venv\\Scripts\\pythonw.exe -X utf8 -m stayy.launcher")
            print("  命令行无界面启动: .\\start_all.ps1")
        print()

    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
