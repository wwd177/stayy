"""Zero-trust local AI desktop app discovery & verified-executable launch helper (Doubao, TRAE, etc.)."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from .base import CREATE_NO_WINDOW, is_path_safe_no_reparse, is_process_elevated

APP_ID_RE = re.compile(r"^[a-z0-9_]{2,32}$")


def _default_desktop_app_specs() -> list[dict[str, Any]]:
    home = Path.home()
    local_app = Path(os.getenv("LOCALAPPDATA") or home / "AppData" / "Local")
    return [
        {
            "id": "doubao",
            "name": "豆包桌面版",
            "vendor": "字节跳动",
            "accent": "#38bdf8",
            "badge": "DB",
            "description": "免 Key 直接唤起豆包电脑窗口，配合 3.2× 光学放大镜远程操作",
            "candidates": [
                Path(r"F:\LenovoSoftstore\Install\doubao\Doubao.exe"),
                local_app / "Doubao" / "Doubao.exe",
                Path(os.getenv("ProgramFiles") or r"C:\Program Files") / "Doubao" / "Doubao.exe",
                Path(os.getenv("ProgramFiles(x86)") or r"C:\Program Files (x86)") / "Doubao" / "Doubao.exe",
            ],
            "process_names": ("doubao.exe",),
        },
        {
            "id": "dsh_desktop",
            "name": "DeepSeek Harness 桌面",
            "vendor": "DeepSeek",
            "accent": "#2563eb",
            "badge": "DS",
            "description": "打开 DeepSeek Harness 完整桌面工作台并用放大镜操控",
            "candidates": [
                local_app / "Programs" / "DeepSeek Harness" / "DeepSeek Harness.exe",
            ],
            "process_names": ("deepseek harness.exe",),
        },
        {
            "id": "workbuddy_desktop",
            "name": "WorkBuddy 桌面",
            "vendor": "腾讯",
            "accent": "#0ea5e9",
            "badge": "WB",
            "description": "打开腾讯 WorkBuddy 办公协同桌面版并用放大镜操控",
            "candidates": [
                local_app / "Programs" / "WorkBuddy" / "WorkBuddy.exe",
            ],
            "process_names": ("workbuddy.exe",),
        },
        {
            "id": "copilot_desktop",
            "name": "GitHub Copilot 桌面",
            "vendor": "GitHub",
            "accent": "#a855f7",
            "badge": "CP",
            "description": "打开 GitHub Copilot 桌面客户端并配合放大镜操控",
            "candidates": [
                local_app / "GitHubCopilotChinese" / "GitHubCopilotChinese.exe",
            ],
            "process_names": ("githubcopilotchinese.exe",),
        },
        {
            "id": "trae_cn",
            "name": "TRAE CN",
            "vendor": "字节跳动",
            "accent": "#22c55e",
            "badge": "TR",
            "description": "打开 TRAE CN AI IDE 桌面端并用放大镜远程继续工作",
            "candidates": [
                local_app / "Programs" / "Trae CN" / "Trae CN.exe",
                Path(r"F:\LenovoSoftstore\Install\Trae CN\Trae CN.exe"),
            ],
            "process_names": ("trae cn.exe",),
        },
        {
            "id": "gemini_desktop",
            "name": "Google Gemini 桌面",
            "vendor": "Google",
            "accent": "#6366f1",
            "badge": "GM",
            "description": "打开本地 Google Gemini 客户端窗口配合放大镜操控",
            "candidates": [
                local_app / "Google" / "Gemini" / "Gemini.exe",
            ],
            "process_names": ("gemini.exe",),
        },
        {
            "id": "grok_bot",
            "name": "Grok Bot",
            "vendor": "xAI / 第三方桌面端",
            "accent": "#f97316",
            "badge": "GK",
            "description": "打开本机 Grok Bot 客户端配合放大镜操控",
            "candidates": [
                Path(r"F:\grok\Grok Bot\Grok Bot.exe"),
                local_app / "Programs" / "Grok Bot" / "Grok Bot.exe",
            ],
            "process_names": ("grok bot.exe",),
        },
        {
            "id": "xiaoyunque",
            "name": "小云雀 AI",
            "vendor": "小云雀",
            "accent": "#ec4899",
            "badge": "XY",
            "description": "打开小云雀 AI 桌面客户端并用放大镜操控",
            "candidates": [
                local_app / "小云雀AI" / "小云雀AI.exe",
            ],
            "process_names": ("小云雀ai.exe",),
        },
        {
            "id": "claude_desktop",
            "name": "Claude 桌面",
            "vendor": "Anthropic",
            "accent": "#d97706",
            "badge": "CL",
            "description": "打开 Claude 桌面客户端并配合放大镜操控",
            "candidates": [
                local_app / "AnthropicClaude" / "claude.exe",
                local_app / "Programs" / "Claude" / "Claude.exe",
            ],
            "process_names": ("claude.exe",),
        },
    ]


def _pe_header_digest(path: Path) -> tuple[int, str]:
    """Compute `(file_size, sha256(head_64KB + tail_4KB))` cleanly to detect post-discovery replacement."""
    try:
        st = path.stat()
        size = int(st.st_size)
        h = hashlib.sha256()
        with path.open("rb") as fh:
            h.update(fh.read(65536))
            if size > 65536:
                fh.seek(max(0, size - 4096))
                h.update(fh.read(4096))
        return size, h.hexdigest()
    except OSError:
        return -1, ""


def is_pe_executable_file(path: Path) -> bool:
    """Confirm `path` is a real `.exe` binary carrying a valid MZ header and zero reparse points."""
    if path.suffix.lower() != ".exe" or not path.is_file():
        return False
    if not is_path_safe_no_reparse(path):
        return False
    try:
        with path.open("rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


def _running_process_names_win32() -> set[str]:
    if sys.platform != "win32":
        return set()
    try:
        res = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            creationflags=CREATE_NO_WINDOW,
        )
        names: set[str] = set()
        for line in (res.stdout or "").splitlines():
            if line.startswith('"'):
                img = line.split('"', 2)[1].strip().lower()
                if img:
                    names.add(img)
        return names
    except Exception:
        return set()


def _focus_window_by_process_win32(process_stem: str) -> bool:
    """Best-effort bring an existing visible window matching `process_stem` to foreground and verify focus."""
    if sys.platform != "win32":
        return False
    ps = (
        "Add-Type -MemberDefinition '[DllImport(\"user32.dll\")] public static extern IntPtr GetForegroundWindow(); "
        "[DllImport(\"user32.dll\")] public static extern bool SetForegroundWindow(IntPtr hWnd); "
        "[DllImport(\"user32.dll\")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);' "
        "-Name StayyAppFocus -Namespace Win32; "
        f"$target = Get-Process -Name '{process_stem.replace(chr(39), chr(39)*2)}' -ErrorAction SilentlyContinue | Where-Object {{ $_.MainWindowHandle -ne 0 }} | Select-Object -First 1; "
        "if ($null -eq $target) { Write-Output 'NONE'; exit 0 }; "
        "$h = $target.MainWindowHandle; "
        "[Win32.StayyAppFocus]::ShowWindowAsync($h, 9) | Out-Null; "
        "[Win32.StayyAppFocus]::SetForegroundWindow($h) | Out-Null; "
        "Start-Sleep -Milliseconds 90; "
        "$fg = [Win32.StayyAppFocus]::GetForegroundWindow(); "
        "if ($fg -eq $h) { Write-Output 'FOCUSED' } else { Write-Output 'UNFOCUSED' }"
    )
    import base64

    enc = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            creationflags=CREATE_NO_WINDOW,
        )
        return "FOCUSED" in (res.stdout or "")
    except Exception:
        return False


def discover_desktop_ai_apps(custom_apps: list[dict[str, Any]] | None = None) -> dict[str, dict[str, Any]]:
    """Discover installed local desktop AI clients and snapshot their verified resolved exe paths."""
    running_imgs = _running_process_names_win32()
    catalog: dict[str, dict[str, Any]] = {}

    for item in _default_desktop_app_specs():
        found_exe: Path | None = None
        for cand in item["candidates"]:
            if is_pe_executable_file(cand):
                found_exe = Path(os.path.abspath(str(cand))).resolve()
                break
        if found_exe is None:
            continue
        pnames = tuple(item.get("process_names") or (found_exe.name.lower(),))
        exe_size, exe_digest = _pe_header_digest(found_exe)
        catalog[item["id"]] = {
            "id": item["id"],
            "name": item["name"],
            "vendor": item["vendor"],
            "accent": item["accent"],
            "badge": item["badge"],
            "description": item["description"],
            "exe_path": str(found_exe),
            "exe_size": exe_size,
            "exe_digest": exe_digest,
            "process_stem": found_exe.stem,
            "running": any(pn in running_imgs for pn in pnames) or found_exe.name.lower() in running_imgs,
        }

    for row in custom_apps or []:
        app_id = str(row.get("id") or "").strip().lower()
        raw_exe = str(row.get("exe_path") or "").strip()
        if not APP_ID_RE.match(app_id) or not raw_exe or app_id in catalog:
            continue
        exe_p = Path(raw_exe).expanduser()
        if not is_pe_executable_file(exe_p):
            continue
        resolved = Path(os.path.abspath(str(exe_p))).resolve()
        exe_size, exe_digest = _pe_header_digest(resolved)
        catalog[app_id] = {
            "id": app_id,
            "name": str(row.get("name") or resolved.stem),
            "vendor": str(row.get("vendor") or "自定义桌面 AI"),
            "accent": str(row.get("accent") or "#94a3b8"),
            "badge": str(row.get("badge") or app_id[:2].upper()),
            "description": str(row.get("description") or "本地配置的 AI 桌面应用"),
            "exe_path": str(resolved),
            "exe_size": exe_size,
            "exe_digest": exe_digest,
            "process_stem": resolved.stem,
            "running": resolved.name.lower() in running_imgs,
        }

    return catalog


def launch_desktop_ai_app(
    app_id: str,
    registered_entry: dict[str, Any] | None,
) -> tuple[bool, bool, str]:
    """Zero-trust launch or focus of a registered desktop AI executable (strictly zero args).

    Returns `(ok, focused, human_note)`.
    """
    if not APP_ID_RE.match((app_id or "").strip()):
        return False, False, "非法的应用标识符"
    if registered_entry is None:
        return False, False, f"未在主机白名单中找到 AI 应用：{app_id}"

    if is_process_elevated():
        return False, False, "出于权限隔离策略，Stayy 在管理员权限进程下禁止直接启动外部桌面应用，请以普通用户运行 Stayy"

    snap_exe = str(registered_entry.get("exe_path") or "")
    if not snap_exe:
        return False, False, "应用可执行文件路径无效"

    exe_path = Path(os.path.abspath(snap_exe))
    if not is_pe_executable_file(exe_path):
        return False, False, f"{registered_entry.get('name', app_id)} 路径校验失败（疑似文件缺失或存在重解析点/符号链接）"
    if str(exe_path.resolve()) != snap_exe:
        return False, False, f"{registered_entry.get('name', app_id)} 运行时路径与发现快照不一致，已拦截启动"
    snap_digest = str(registered_entry.get("exe_digest") or "")
    snap_size = registered_entry.get("exe_size")
    if snap_digest:
        cur_size, cur_digest = _pe_header_digest(exe_path)
        if cur_digest != snap_digest or (snap_size is not None and cur_size != int(snap_size)):
            return False, False, f"{registered_entry.get('name', app_id)} 程序内容自发现后发生变化，已拦截启动，请先刷新列表"

    stem = str(registered_entry.get("process_stem") or exe_path.stem)
    running_imgs = _running_process_names_win32()
    already_running = exe_path.name.lower() in running_imgs

    if already_running:
        focused = _focus_window_by_process_win32(stem)
        if focused:
            return True, True, f"已将「{registered_entry['name']}」置前到电脑屏幕，请在放大镜中操作"
        return True, False, f"「{registered_entry['name']}」已在运行但未能自动置前（已保持画面只读提示，请切屏核对）"

    try:
        subprocess.Popen(
            [str(exe_path)],
            cwd=str(exe_path.parent),
            close_fds=True,
        )
    except Exception as exc:
        return False, False, f"启动「{registered_entry['name']}」失败：{exc}"

    focused = _focus_window_by_process_win32(stem)
    return (
        True,
        focused,
        f"已在电脑启动「{registered_entry['name']}」" + ("并置前" if focused else "（请等待窗口出现并在放大镜核对）"),
    )
