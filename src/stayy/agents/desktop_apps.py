"""Zero-trust local AI desktop app discovery & verified-executable launch helper (Doubao, TRAE, etc.)."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .base import CREATE_NO_WINDOW, is_path_safe_no_reparse, is_process_elevated

APP_ID_RE = re.compile(r"^[a-z0-9_]{2,32}$")


def _default_desktop_app_specs(local_app_data: Path | None = None) -> list[dict[str, Any]]:
    home = Path.home()
    isolated = local_app_data is not None
    local_app = local_app_data or Path(os.getenv("LOCALAPPDATA") or home / "AppData" / "Local")
    prog_files = Path(os.getenv("ProgramFiles") or r"C:\Program Files")
    prog_files_x86 = Path(os.getenv("ProgramFiles(x86)") or r"C:\Program Files (x86)")

    doubao_cands = [local_app / "Doubao" / "Doubao.exe"]
    if not isolated:
        doubao_cands = [
            Path(r"F:\LenovoSoftstore\Install\doubao\Doubao.exe"),
            *doubao_cands,
            prog_files / "Doubao" / "Doubao.exe",
            prog_files_x86 / "Doubao" / "Doubao.exe",
        ]
    trae_cands = [local_app / "Programs" / "Trae CN" / "Trae CN.exe"]
    if not isolated:
        trae_cands.append(Path(r"F:\LenovoSoftstore\Install\Trae CN\Trae CN.exe"))
    grok_cands = [local_app / "Programs" / "Grok Bot" / "Grok Bot.exe"]
    if not isolated:
        grok_cands.insert(0, Path(r"F:\grok\Grok Bot\Grok Bot.exe"))

    return [
        {
            "id": "doubao",
            "name": "豆包桌面版",
            "vendor": "字节跳动",
            "accent": "#38bdf8",
            "badge": "DB",
            "description": "免 Key 直接唤起豆包电脑窗口，配合 3.2× 光学放大镜远程操作",
            "candidates": doubao_cands,
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
            "candidates": trae_cands,
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
            "candidates": grok_cands,
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
    """Bring a visible window belonging to `process_stem` to foreground cleanly using pure Win32 ctypes."""
    if sys.platform != "win32" or not (process_stem or "").strip():
        return False
    try:
        import ctypes
        from ctypes import wintypes

        target_stem = process_stem.strip().lower()
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.IsWindowVisible.argtypes = [wintypes.HWND]
        user32.IsWindowVisible.restype = wintypes.BOOL
        user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
        user32.GetWindowTextLengthW.restype = ctypes.c_int
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        user32.IsIconic.argtypes = [wintypes.HWND]
        user32.IsIconic.restype = wintypes.BOOL
        user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.ShowWindow.restype = wintypes.BOOL
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.SetForegroundWindow.restype = wintypes.BOOL
        user32.BringWindowToTop.argtypes = [wintypes.HWND]
        user32.BringWindowToTop.restype = wintypes.BOOL
        user32.GetForegroundWindow.argtypes = []
        user32.GetForegroundWindow.restype = wintypes.HWND

        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
        user32.EnumWindows.restype = wintypes.BOOL

        titled_hwnds: list[int] = []
        fallback_hwnds: list[int] = []
        proc_stem_cache: dict[int, str] = {}

        def _enum_cb(hwnd: int, _lparam: int) -> bool:
            if not user32.IsWindowVisible(hwnd):
                return True
            pid = wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pid_val = int(pid.value)
            if pid_val <= 0:
                return True
            stem = proc_stem_cache.get(pid_val)
            if stem is None:
                stem = ""
                hproc = kernel32.OpenProcess(0x1000, False, pid_val)  # PROCESS_QUERY_LIMITED_INFORMATION
                if hproc:
                    try:
                        buf = ctypes.create_unicode_buffer(520)
                        sz = wintypes.DWORD(520)
                        if kernel32.QueryFullProcessImageNameW(hproc, 0, buf, ctypes.byref(sz)):
                            stem = Path(buf.value).stem.lower()
                    finally:
                        kernel32.CloseHandle(hproc)
                proc_stem_cache[pid_val] = stem
            if stem == target_stem:
                if user32.GetWindowTextLengthW(hwnd) > 0:
                    titled_hwnds.append(hwnd)
                    return False
                fallback_hwnds.append(hwnd)
            return True

        cb_ref = WNDENUMPROC(_enum_cb)
        user32.EnumWindows(cb_ref, 0)
        cand = titled_hwnds[0] if titled_hwnds else (fallback_hwnds[0] if fallback_hwnds else 0)
        if not cand:
            return False

        if user32.IsIconic(cand):
            user32.ShowWindow(cand, 9)  # SW_RESTORE
        # Legal Alt key press/release satisfies ForegroundLock check when switching between user windows
        user32.keybd_event(0x12, 0, 0, 0)
        user32.keybd_event(0x12, 0, 0x0002, 0)
        user32.BringWindowToTop(cand)
        user32.SetForegroundWindow(cand)
        time.sleep(0.06)
        return int(user32.GetForegroundWindow() or 0) == int(cand)
    except Exception:
        return False


def discover_desktop_ai_apps(
    custom_apps: list[dict[str, Any]] | None = None,
    *,
    local_app_data: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Discover installed local desktop AI clients and snapshot their verified resolved exe paths."""
    running_imgs = _running_process_names_win32()
    catalog: dict[str, dict[str, Any]] = {}

    for item in _default_desktop_app_specs(local_app_data=local_app_data):
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
            "process_names": pnames,
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
            "process_names": (resolved.name.lower(),),
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
    pnames = tuple(registered_entry.get("process_names") or (exe_path.name.lower(),))
    running_imgs = _running_process_names_win32()
    already_running = exe_path.name.lower() in running_imgs or any(pn in running_imgs for pn in pnames)

    if already_running:
        focused = _focus_window_by_process_win32(stem)
        if focused:
            return True, True, f"已将「{registered_entry['name']}」置前到电脑屏幕，请在放大镜中操作"
        # App may be minimized to system tray without a visible HWND: wake single-instance window cleanly
        try:
            subprocess.Popen(
                [str(exe_path)],
                cwd=str(exe_path.parent),
                close_fds=True,
            )
            for _ in range(4):
                time.sleep(0.25)
                if _focus_window_by_process_win32(stem):
                    return True, True, f"已唤醒并将「{registered_entry['name']}」置前到电脑屏幕，请在放大镜中操作"
        except Exception:
            pass
        return True, False, f"「{registered_entry['name']}」已在运行但未能自动置前（已保持画面只读提示，请切屏核对）"

    try:
        subprocess.Popen(
            [str(exe_path)],
            cwd=str(exe_path.parent),
            close_fds=True,
        )
    except Exception as exc:
        return False, False, f"启动「{registered_entry['name']}」失败：{exc}"

    focused = False
    for _ in range(6):
        time.sleep(0.25)
        if _focus_window_by_process_win32(stem):
            focused = True
            break
    return (
        True,
        focused,
        f"已在电脑启动「{registered_entry['name']}」" + ("并置前" if focused else "（请等待窗口出现并在放大镜核对）"),
    )
