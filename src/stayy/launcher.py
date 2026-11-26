"""Windows 11 translucent glassmorphic desktop console for Stayy.

Features:
- Isolated local-first AI coding + 3.2x optical loupe / virtual trackpad PC remote control hub
- Short-lived one-time QR pairing codes + instant 1-click key rotation & mobile session revocation
- Explicit opt-in self-hosted GitHub Pages beacon with HTTP read-back identity verification
- Live PC conversation telemetry (Antigravity IDE + Codex Desktop synced chat counts)
- Auto-healing service watchdog, sleep-prevention toggle, and one-click Firewall UAC helper
"""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import io
import json
import math
import os
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.request
import webbrowser
import zlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any, Callable

from dotenv import dotenv_values

from .auth import load_or_create_host_id
from .beacon import publish_ios_pwa_and_beacon, resolve_explicit_beacon_target
from .conversations import list_local_conversations
from .maintenance import discover_default_cache_targets, run_safe_cache_cleanup
from .web_pwa import ensure_web_access_token, get_lan_ipv4

APP_TITLE = "Stayy"
LEGACY_TITLES: tuple[str, ...] = ()
MUTEX_NAME = "Local\\StayyLauncherSingleton_v1"

PROJECT_DIR = Path(__file__).resolve().parents[2]
RUNTIME_DIR = PROJECT_DIR / ".runtime"
ICON_PATH = PROJECT_DIR / "assets" / "app.ico"
UI_PREFS_PATH = PROJECT_DIR / ".launcher_ui.json"
STARTUP_SHORTCUT_NAME = "Stayy.lnk"
LEGACY_STARTUP_SHORTCUTS: tuple[str, ...] = ()

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
TRYCLOUDFLARE_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)

GLASS_PRESETS: tuple[tuple[str, float], ...] = (
    ("深透 82%", 0.82),
    ("凝霜 90%", 0.90),
    ("微透 95%", 0.95),
    ("纯实 100%", 1.00),
)

FIREWALL_RULE_NAME = "Stayy LAN"


# ---------------------------------------------------------------------------
# Pure-stdlib anti-aliased RGBA PNG builders for frosted glass surfaces & orbs
# ---------------------------------------------------------------------------

def _pack_png_rgba(width: int, height: int, raw_rows: bytes) -> bytes:
    def _chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    idat = zlib.compress(raw_rows, level=6)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def _hex_rgb(hex_color: str) -> tuple[float, float, float]:
    h = hex_color.lstrip("#")
    return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))


def render_glass_card_b64(
    width: int,
    height: int,
    *,
    radius: int = 16,
    outer_bg: str = "#070B14",
    top_fill: str = "#121D31",
    bottom_fill: str = "#0B1322",
    rim_top: str = "#67E8F9",
    rim_bottom: str = "#22324A",
    rim_top_alpha: float = 0.36,
    rim_bottom_alpha: float = 0.14,
) -> str:
    """Render an anti-aliased frosted glass rounded panel with a 1px specular top rim."""
    width = max(width, 24)
    height = max(height, 24)
    obr, obg, obb = _hex_rgb(outer_bg)
    tfr, tfg, tfb = _hex_rgb(top_fill)
    bfr, bfg, bfb = _hex_rgb(bottom_fill)
    rtr, rtg, rtb = _hex_rgb(rim_top)
    rbr, rbg, rbb = _hex_rgb(rim_bottom)

    hw = width * 0.5
    hh = height * 0.5
    rad = min(float(radius), hw - 1.0, hh - 1.0)
    bx = hw - 0.5 - rad
    by = hh - 0.5 - rad

    rows = bytearray()
    inv_h = 1.0 / max(height - 1, 1)

    for y in range(height):
        vy = y * inv_h
        sheen = math.exp(-vy * 5.8) * 0.08
        fill_r = tfr + (bfr - tfr) * vy + 255.0 * sheen
        fill_g = tfg + (bfg - tfg) * vy + 255.0 * sheen
        fill_b = tfb + (bfb - tfb) * vy + 255.0 * sheen

        rim_r = rtr + (rbr - rtr) * vy
        rim_g = rtg + (rbg - rtg) * vy
        rim_b = rtb + (rbb - rtb) * vy
        rim_a = rim_top_alpha + (rim_bottom_alpha - rim_top_alpha) * vy

        py = abs(y - (hh - 0.5)) - by
        rows.append(0)

        if py <= -1.5 and 2 <= y <= height - 3:
            br_r = int(min(255.0, fill_r * (1.0 - rim_a) + rim_r * rim_a) + 0.5)
            br_g = int(min(255.0, fill_g * (1.0 - rim_a) + rim_g * rim_a) + 0.5)
            br_b = int(min(255.0, fill_b * (1.0 - rim_a) + rim_b * rim_a) + 0.5)

            in_r = int(min(255.0, fill_r) + 0.5)
            in_g = int(min(255.0, fill_g) + 0.5)
            in_b = int(min(255.0, fill_b) + 0.5)

            rows.extend((br_r, br_g, br_b, 255))
            rows.extend(bytes((in_r, in_g, in_b, 255)) * (width - 2))
            rows.extend((br_r, br_g, br_b, 255))
            continue

        for x in range(width):
            px = abs(x - (hw - 0.5)) - bx
            if px <= 0.0 and py <= 0.0:
                d = max(px, py) - rad
            else:
                d = math.hypot(max(px, 0.0), max(py, 0.0)) - rad

            cov = 0.0 if d >= 0.5 else (1.0 if d <= -0.5 else (0.5 - d))
            if cov <= 0.0:
                rows.extend((int(obr), int(obg), int(obb), 255))
                continue

            rim_w = max(0.0, 1.0 - abs(d + 0.55) * 1.15) * rim_a
            cr = min(255.0, fill_r * (1.0 - rim_w) + rim_r * rim_w)
            cg = min(255.0, fill_g * (1.0 - rim_w) + rim_g * rim_w)
            cb = min(255.0, fill_b * (1.0 - rim_w) + rim_b * rim_w)

            out_r = int(obr * (1.0 - cov) + cr * cov + 0.5)
            out_g = int(obg * (1.0 - cov) + cg * cov + 0.5)
            out_b = int(obb * (1.0 - cov) + cb * cov + 0.5)
            rows.extend((out_r, out_g, out_b, 255))

    return base64.b64encode(_pack_png_rgba(width, height, bytes(rows))).decode("ascii")


def render_glow_orb_b64(size: int, core_hex: str, bg_hex: str) -> str:
    """Render an anti-aliased status orb with a soft luminous radial halo."""
    br, bg, bb = _hex_rgb(bg_hex)
    cr, cg, cb = _hex_rgb(core_hex)
    cx = cy = (size - 1) * 0.5
    core_r = size * 0.23
    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            dist = math.hypot(x - cx, y - cy)
            halo = math.exp(-((dist / (size * 0.34)) ** 2) * 2.1) * 0.44
            core = max(0.0, min(1.0, 0.5 - (dist - core_r) * 1.25))
            a = min(1.0, core + halo * (1.0 - core))
            spec = max(0.0, min(1.0, 1.0 - math.hypot(x - (cx - 1.2), y - (cy - 1.2)) / (core_r * 0.9))) * core * 0.35
            r = min(255.0, br * (1.0 - a) + cr * a + 255.0 * spec)
            g = min(255.0, bg * (1.0 - a) + cg * a + 255.0 * spec)
            b = min(255.0, bb * (1.0 - a) + cb * a + 255.0 * spec)
            rows.extend((int(r + 0.5), int(g + 0.5), int(b + 0.5), 255))
    return base64.b64encode(_pack_png_rgba(size, size, bytes(rows))).decode("ascii")


# ---------------------------------------------------------------------------
# Win32 / DWM helpers (64-bit HANDLE/HWND safe)
# ---------------------------------------------------------------------------

def _setup_win32_prototypes() -> None:
    if sys.platform != "win32":
        return
    k32 = ctypes.windll.kernel32
    u32 = ctypes.windll.user32
    k32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    k32.CreateMutexW.restype = wintypes.HANDLE
    k32.GetLastError.argtypes = []
    k32.GetLastError.restype = wintypes.DWORD
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.SetThreadExecutionState.argtypes = [wintypes.DWORD]
    k32.SetThreadExecutionState.restype = wintypes.DWORD

    u32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    u32.FindWindowW.restype = wintypes.HWND
    u32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    u32.ShowWindow.restype = wintypes.BOOL
    u32.SetForegroundWindow.argtypes = [wintypes.HWND]
    u32.SetForegroundWindow.restype = wintypes.BOOL
    u32.GetParent.argtypes = [wintypes.HWND]
    u32.GetParent.restype = wintypes.HWND


_setup_win32_prototypes()


def acquire_single_instance_mutex() -> int | None:
    if sys.platform != "win32":
        return 1
    k32 = ctypes.windll.kernel32
    u32 = ctypes.windll.user32
    handle = k32.CreateMutexW(None, False, MUTEX_NAME)
    last_err = k32.GetLastError()
    if last_err == 183:  # ERROR_ALREADY_EXISTS
        hwnd = u32.FindWindowW(None, APP_TITLE)
        if hwnd:
            u32.ShowWindow(hwnd, 9)
            u32.SetForegroundWindow(hwnd)
        if handle:
            k32.CloseHandle(handle)
        return None
    return int(handle) if handle else 1


def close_mutex_handle(handle: int | None) -> None:
    if sys.platform == "win32" and handle and handle != 1:
        try:
            ctypes.windll.kernel32.CloseHandle(wintypes.HANDLE(handle))
        except Exception:
            pass


def enable_high_dpi() -> None:
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def set_windows_app_id() -> None:
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Stayy.RemoteHub.Console")
    except Exception:
        pass


def set_prevent_system_sleep(prevent: bool) -> None:
    """Keep Windows CPU/network awake while assistant is running (still lets monitor turn off)."""
    if sys.platform != "win32":
        return
    try:
        flags = 0x80000001 if prevent else 0x80000000
        ctypes.windll.kernel32.SetThreadExecutionState(wintypes.DWORD(flags))
    except Exception:
        pass


def apply_win11_glass_dwm(root: tk.Misc) -> None:
    """Apply Windows 11 DWM dark mode, rounded corners, seamless caption & glass rim."""
    if sys.platform != "win32":
        return
    try:
        root.update_idletasks()
        frame_str = root.wm_frame()  # type: ignore[attr-defined]
        hwnd = int(frame_str, 16) if frame_str and frame_str != "0x0" else ctypes.windll.user32.GetParent(root.winfo_id())
        if not hwnd:
            hwnd = root.winfo_id()

        dwm = ctypes.windll.dwmapi
        dwm.DwmSetWindowAttribute.argtypes = [
            wintypes.HWND,
            wintypes.DWORD,
            wintypes.LPCVOID,
            wintypes.DWORD,
        ]
        dwm.DwmSetWindowAttribute.restype = ctypes.c_long

        def _set_int(attr: int, val: int) -> None:
            c_val = ctypes.c_int(val)
            dwm.DwmSetWindowAttribute(
                wintypes.HWND(hwnd),
                wintypes.DWORD(attr),
                ctypes.byref(c_val),
                ctypes.sizeof(c_val),
            )

        _set_int(20, 1)          # DWMWA_USE_IMMERSIVE_DARK_MODE
        _set_int(33, 2)          # DWMWA_WINDOW_CORNER_PREFERENCE = DWMWCP_ROUND
        _set_int(35, 0x00171717) # DWMWA_CAPTION_COLOR (#171717)
        _set_int(36, 0x00ECECEC) # DWMWA_TEXT_COLOR (#ECECEC)
        _set_int(34, 0x00333333) # DWMWA_BORDER_COLOR (#333333)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Settings, Startup Shortcut & Process Helpers
# ---------------------------------------------------------------------------

@dataclass
class LauncherSettings:
    active_model: str
    workspace: str
    web_pwa_enabled: bool
    web_pwa_port: int
    web_access_token: str
    tunnel_enabled: bool
    beacon_enabled: bool
    beacon_git_remote: str
    beacon_branch: str
    public_base_url: str
    project_dir: Path


def _bool_env(val: object, default: bool = True) -> bool:
    if val is None or str(val).strip() == "":
        return default
    return str(val).strip().lower() in {"1", "true", "yes", "y", "on"}


def load_settings() -> LauncherSettings:
    env_file = PROJECT_DIR / ".env"
    env_data = dotenv_values(env_file) if env_file.is_file() else {}
    active_model = str(env_data.get("AGY_MODEL") or "claude-sonnet-5-5-medium").strip() or "默认模型"
    workspace = str(env_data.get("AGY_WORKSPACE") or PROJECT_DIR).strip()
    web_pwa_enabled = _bool_env(env_data.get("WEB_PWA_ENABLED"), True)
    web_pwa_port = int(str(env_data.get("WEB_PWA_PORT") or "8766").strip() or 8766)
    raw_web_tok = str(env_data.get("WEB_ACCESS_TOKEN") or "").strip()
    web_tok = ensure_web_access_token(env_file, raw_web_tok) if web_pwa_enabled else raw_web_tok
    tunnel_enabled = _bool_env(env_data.get("CLOUDFLARE_TUNNEL_ENABLED"), True)
    beacon_enabled = _bool_env(env_data.get("BEACON_ENABLED"), False)
    beacon_git_remote = str(env_data.get("BEACON_GIT_REMOTE") or "").strip()
    beacon_branch = str(env_data.get("BEACON_BRANCH") or "gh-pages").strip() or "gh-pages"
    public_base_url = str(env_data.get("PUBLIC_BASE_URL") or "").strip().rstrip("/")

    return LauncherSettings(
        active_model=active_model,
        workspace=workspace,
        web_pwa_enabled=web_pwa_enabled,
        web_pwa_port=web_pwa_port,
        web_access_token=web_tok,
        tunnel_enabled=tunnel_enabled,
        beacon_enabled=beacon_enabled,
        beacon_git_remote=beacon_git_remote,
        beacon_branch=beacon_branch,
        public_base_url=public_base_url,
        project_dir=PROJECT_DIR,
    )


def load_ui_prefs() -> dict:
    if UI_PREFS_PATH.is_file():
        try:
            return json.loads(UI_PREFS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"alpha": 0.92}


def save_ui_prefs(prefs: dict) -> None:
    try:
        UI_PREFS_PATH.write_text(json.dumps(prefs, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _startup_dir() -> Path:
    appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def get_startup_shortcut_path() -> Path:
    return _startup_dir() / STARTUP_SHORTCUT_NAME


def is_autostart_enabled() -> bool:
    sdir = _startup_dir()
    if (sdir / STARTUP_SHORTCUT_NAME).is_file():
        return True
    return any((sdir / old).is_file() for old in LEGACY_STARTUP_SHORTCUTS)


def set_autostart_enabled(enable: bool) -> bool:
    sdir = _startup_dir()
    sc_path = sdir / STARTUP_SHORTCUT_NAME
    for old in LEGACY_STARTUP_SHORTCUTS:
        try:
            (sdir / old).unlink(missing_ok=True)
        except OSError:
            pass
    if not enable:
        try:
            sc_path.unlink(missing_ok=True)
            return True
        except OSError:
            return False

    target = PROJECT_DIR / ".venv" / "Scripts" / "pythonw.exe"
    icon = PROJECT_DIR / "assets" / "app.ico"
    ps = f"""
$wsh = New-Object -ComObject WScript.Shell
$sc = $wsh.CreateShortcut('{str(sc_path).replace("'", "''")}')
$sc.TargetPath = '{str(target).replace("'", "''")}'
$sc.Arguments = '-X utf8 -m stayy.launcher --minimized'
$sc.WorkingDirectory = '{str(PROJECT_DIR).replace("'", "''")}'
$sc.IconLocation = '{str(icon).replace("'", "''")},0'
$sc.Description = '开机静默启动 Stayy'
$sc.Save()
"""
    encoded_ps = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    try:
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", encoded_ps],
            check=True,
            capture_output=True,
            timeout=8,
            creationflags=CREATE_NO_WINDOW,
        )
        return sc_path.is_file()
    except Exception:
        return False


def is_tcp_port_open(host: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_stayy_gateway_identity(host: str, port: int, timeout: float = 0.6) -> str:
    """Verify whether `host:port` is genuinely our Stayy gateway (`'stayy'`), `'foreign'`, or `'closed'`."""
    if not is_tcp_port_open(host, port, timeout=min(0.35, timeout)):
        return "closed"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://{host}:{port}/ping", timeout=timeout) as resp:
            if resp.status != 200:
                return "foreign"
            data = json.loads(resp.read(4096).decode("utf-8", errors="replace"))
            if isinstance(data, dict) and data.get("ok") is True and data.get("service") == "stayy":
                return "stayy"
            return "foreign"
    except Exception:
        return "foreign"


def find_external_server_processes(exclude_pids: set[int]) -> list[int]:
    """Return running Stayy backend server PIDs outside this launcher (NEVER matches qq_agy_bridge!)."""
    ps_script = r"""
$procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
$srv = @(
    $procs | Where-Object {
        ($_.Name -ieq 'stayy.exe') -or (
            $_.Name -like 'python*' -and
            ($_.CommandLine -like '*-m stayy.main*') -and
            ($_.CommandLine -notlike '*stayy.launcher*')
        )
    } | ForEach-Object { [int]$_.ProcessId }
)
ConvertTo-Json -InputObject $srv -Compress
"""
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            creationflags=CREATE_NO_WINDOW,
        )
        raw = result.stdout.strip()
        if not raw or raw == "null":
            return []
        data = json.loads(raw)
        if isinstance(data, int):
            data = [data]
        return [int(p) for p in data if int(p) not in exclude_pids]
    except Exception:
        return []


def kill_pid_tree(pid: int) -> None:
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            timeout=8,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        pass


def is_lan_firewall_rule_present(port: int) -> bool:
    if sys.platform != "win32":
        return True
    try:
        res = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={FIREWALL_RULE_NAME}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=3,
            creationflags=CREATE_NO_WINDOW,
        )
        if res.returncode == 0 and str(port) in (res.stdout or ""):
            return True
    except Exception:
        pass
    return False


def request_lan_firewall_allow(port: int) -> bool:
    if sys.platform != "win32":
        return True
    try:
        args = (
            f'advfirewall firewall add rule name="{FIREWALL_RULE_NAME}" '
            f"dir=in action=allow protocol=TCP localport={int(port)}"
        )
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", "netsh", args, None, 0)
        return int(ret) > 32
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Glassmorphic Desktop Hub Application
# ---------------------------------------------------------------------------

class LauncherApp:
    # Authentic ChatGPT Desktop Dark Monochrome Palette
    BG = "#171717"
    GLASS_SURFACE = "#212121"
    QR_SURFACE = "#212121"
    LOG_BG = "#0D0D0D"

    TEXT_PRIMARY = "#ECECEC"
    TEXT_SECONDARY = "#B4B4B4"
    TEXT_MUTED = "#8E8EA0"

    CYAN = "#ECECEC"
    INDIGO = "#ECECEC"
    EMERALD = "#10A37F"
    AMBER = "#F59E0B"
    ROSE = "#EF4444"

    PILL_PRIMARY = "#10A37F"
    PILL_PRIMARY_HOVER = "#0D8A6A"
    PILL_INDIGO = "#2F2F2F"
    PILL_INDIGO_HOVER = "#3D3D3D"
    PILL_SLATE = "#262626"
    PILL_SLATE_HOVER = "#343434"
    PILL_DANGER = "#7F1D1D"
    PILL_DANGER_HOVER = "#991B1B"

    MAX_LOG_LINES = 2000

    def __init__(self, root: tk.Tk, settings: LauncherSettings, *, start_minimized: bool = False) -> None:
        self.root = root
        self.settings = settings
        self._prefs = load_ui_prefs()
        self._alpha: float = float(self._prefs.get("alpha", 0.92))

        self._server_proc: subprocess.Popen[str] | None = None
        self._tunnel_proc: subprocess.Popen[str] | None = None
        self._tunnel_url: str = ""
        self._tunnel_gen: int = 0
        self._server_external = False
        self._port_conflict = False
        self._desired_running = True
        self._auto_restart_timestamps: list[float] = []
        self._tunnel_restart_timestamps: list[float] = []
        self._busy = False
        self._closing = False

        gh_info = resolve_explicit_beacon_target(
            settings.project_dir,
            beacon_enabled=settings.beacon_enabled,
            explicit_remote=settings.beacon_git_remote,
        )
        self._ios_pages_url: str = gh_info[3] if gh_info else ""
        self._beacon_synced: bool = False
        self._beacon_state: str = "disabled"
        self._active_pair_code: str = ""
        self._host_id: str = load_or_create_host_id(RUNTIME_DIR)
        self._qr_mode = tk.StringVar(value="tunnel" if settings.public_base_url else "lan")
        self._qr_photo_ref: list[tk.PhotoImage] = []
        self._conv_stats_str = "正在扫描电脑端会话..."

        self._op_lock = threading.Lock()
        self._log_queue: queue.Queue[tuple[str, str, str]] = queue.Queue()
        self._ui_queue: queue.Queue[Callable[[], None]] = queue.Queue()
        self._show_debug = False
        self._show_debug_var = tk.BooleanVar(value=False)
        self._autostart_var = tk.BooleanVar(value=is_autostart_enabled())
        self._keep_awake_var = tk.BooleanVar(value=bool(self._prefs.get("keep_awake", True)))

        self._img_cache: dict[tuple, tk.PhotoImage] = {}
        self._orbs: dict[str, tk.PhotoImage] = {}

        self._configure_window(start_minimized=start_minimized)
        self._configure_dark_styles()
        self._prepare_orb_icons()
        self._build_ui()
        apply_win11_glass_dwm(self.root)
        self._apply_window_alpha(self._alpha)
        self._start_ui_loops()

        threading.Thread(target=self._refresh_conv_stats_bg, daemon=True).start()
        threading.Thread(target=self._check_firewall_bg, daemon=True).start()
        self.root.after(160, lambda: self._run_async(self._start_all_worker, False))

    def _configure_window(self, *, start_minimized: bool) -> None:
        self.root.title(APP_TITLE)
        self.root.configure(bg=self.BG)
        self.root.minsize(920, 620)
        w, h = 980, 690
        self.root.protocol("WM_DELETE_WINDOW", self._on_close_requested)

        if ICON_PATH.is_file():
            try:
                self.root.iconbitmap(default=str(ICON_PATH))
            except Exception:
                pass

        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = max((sw - w) // 2, 20)
        y = max((sh - h) // 2 - 24, 20)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

        if start_minimized:
            self.root.iconify()

    def _configure_dark_styles(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "Glass.Vertical.TScrollbar",
            gripcount=0,
            background="#1C2D46",
            darkcolor=self.LOG_BG,
            lightcolor=self.LOG_BG,
            troughcolor=self.LOG_BG,
            bordercolor=self.LOG_BG,
            arrowcolor="#64748B",
            relief="flat",
            borderwidth=0,
            arrowsize=0,
            width=8,
        )
        style.map(
            "Glass.Vertical.TScrollbar",
            background=[("active", "#38BDF8"), ("!active", "#1C2D46")],
        )

    def _prepare_orb_icons(self) -> None:
        for name, hex_col in (
            ("green", self.EMERALD),
            ("amber", self.AMBER),
            ("red", self.ROSE),
        ):
            b64 = render_glow_orb_b64(20, hex_col, self.GLASS_SURFACE)
            self._orbs[name] = tk.PhotoImage(data=b64)

    def _get_glass_image(
        self,
        width: int,
        height: int,
        *,
        radius: int = 16,
        rim_top: str = "#67E8F9",
        top_fill: str = "#121D31",
        bottom_fill: str = "#0C1525",
    ) -> tk.PhotoImage:
        key = (width, height, radius, rim_top, top_fill, bottom_fill)
        cached = self._img_cache.get(key)
        if cached is not None:
            return cached
        if len(self._img_cache) > 28:
            self._img_cache.clear()
        b64 = render_glass_card_b64(
            width,
            height,
            radius=radius,
            outer_bg=self.BG,
            top_fill=top_fill,
            bottom_fill=bottom_fill,
            rim_top=rim_top,
        )
        img = tk.PhotoImage(data=b64)
        self._img_cache[key] = img
        return img

    def _apply_window_alpha(self, alpha: float) -> None:
        self._alpha = max(0.75, min(1.0, alpha))
        try:
            self.root.attributes("-alpha", self._alpha)
        except Exception:
            pass
        if hasattr(self, "_alpha_btns"):
            for btn, val in self._alpha_btns:
                active = abs(val - self._alpha) < 0.015
                bg = "#ECECEC" if active else "#262626"
                fg = "#0D0D0D" if active else "#B4B4B4"
                btn._base_bg = bg  # type: ignore[attr-defined]
                btn.configure(bg=bg, fg=fg)
        self._prefs["alpha"] = round(self._alpha, 2)
        save_ui_prefs(self._prefs)

    def _build_ui(self) -> None:
        outer = tk.Frame(self.root, bg=self.BG, padx=24, pady=18)
        outer.pack(fill=tk.BOTH, expand=True)

        # ── Top Brand Header ──
        header = tk.Frame(outer, bg=self.BG)
        header.pack(fill=tk.X, pady=(0, 14))

        left_hdr = tk.Frame(header, bg=self.BG)
        left_hdr.pack(side=tk.LEFT, fill=tk.X, expand=True)

        title_row = tk.Frame(left_hdr, bg=self.BG)
        title_row.pack(fill=tk.X)

        emblem = tk.Label(
            title_row,
            text="✦",
            bg="#FFFFFF",
            fg="#0D0D0D",
            font=("Segoe UI Symbol", 13, "bold"),
            padx=7,
            pady=1,
        )
        emblem.pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(
            title_row,
            text="Stayy",
            bg=self.BG,
            fg=self.TEXT_PRIMARY,
            font=("Microsoft YaHei UI", 17, "bold"),
            anchor="w",
        ).pack(side=tk.LEFT)

        self.subtitle_lbl = tk.Label(
            left_hdr,
            text="Local-First AI Coding + 3.2× Touch Loupe Remote Control   ·   Wi-Fi / Tailscale / Quick Tunnel",
            bg=self.BG,
            fg=self.TEXT_MUTED,
            font=("Microsoft YaHei UI", 9),
            anchor="w",
            pady=4,
        )
        self.subtitle_lbl.pack(fill=tk.X)

        # Right Header: Translucency Switcher + System Toggles
        right_hdr = tk.Frame(header, bg=self.BG)
        right_hdr.pack(side=tk.RIGHT, anchor="ne")

        glass_bar = tk.Frame(
            right_hdr,
            bg="#212121",
            highlightbackground="#333333",
            highlightthickness=1,
            padx=6,
            pady=4,
        )
        glass_bar.pack(side=tk.TOP, anchor="e")

        tk.Label(
            glass_bar,
            text="透感",
            bg="#212121",
            fg=self.TEXT_MUTED,
            font=("Microsoft YaHei UI", 8),
            padx=4,
        ).pack(side=tk.LEFT)

        self._alpha_btns: list[tuple[tk.Button, float]] = []
        for label, val in GLASS_PRESETS:
            b = self._make_button(
                glass_bar,
                text=label,
                command=lambda v=val: self._apply_window_alpha(v),
                bg="#262626",
                hover="#363636",
                fg="#B4B4B4",
                padx=8,
                pady=2,
                font_size=8,
            )
            b.pack(side=tk.LEFT, padx=2)
            self._alpha_btns.append((b, val))

        chk_row = tk.Frame(right_hdr, bg=self.BG)
        chk_row.pack(side=tk.TOP, anchor="e", pady=(6, 0))

        tk.Checkbutton(
            chk_row,
            text="防自动休眠 (允许息屏)",
            variable=self._keep_awake_var,
            command=self._on_toggle_keep_awake,
            bg=self.BG,
            fg=self.TEXT_SECONDARY,
            selectcolor="#101B2D",
            activebackground=self.BG,
            activeforeground=self.TEXT_PRIMARY,
            font=("Microsoft YaHei UI", 8),
            bd=0,
            highlightthickness=0,
            cursor="hand2",
        ).pack(side=tk.LEFT, padx=(0, 12))

        tk.Checkbutton(
            chk_row,
            text="开机静默自启",
            variable=self._autostart_var,
            command=self._on_toggle_autostart,
            bg=self.BG,
            fg=self.TEXT_SECONDARY,
            selectcolor="#101B2D",
            activebackground=self.BG,
            activeforeground=self.TEXT_PRIMARY,
            font=("Microsoft YaHei UI", 8),
            bd=0,
            highlightthickness=0,
            cursor="hand2",
        ).pack(side=tk.LEFT)

        # ── Two-Column Hero Dashboard (Telemetry + Inline Live QR Card) ──
        hero_grid = tk.Frame(outer, bg=self.BG)
        hero_grid.pack(fill=tk.X, pady=(0, 12))
        hero_grid.columnconfigure(0, weight=1)
        hero_grid.columnconfigure(1, weight=0)

        left_col = tk.Frame(hero_grid, bg=self.BG)
        left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 14))

        self.engine_orb_lbl, self.engine_status_lbl, self.engine_detail_lbl = self._create_glass_card(
            left_col,
            title="Stayy 核心网关 · 会话同步",
            detail=f"模型：{self.settings.active_model}  ·  {self._conv_stats_str}",
            rim_color="#454545",
            pady=(0, 10),
        )

        lan_ip = get_lan_ipv4()
        self.net_orb_lbl, self.net_status_lbl, self.net_detail_lbl = self._create_glass_card(
            left_col,
            title="网络连接 · 局域网 / 私网与安全隧道",
            detail=f"局域网：http://{lan_ip}:{self.settings.web_pwa_port}  ·  准备中...",
            rim_color="#454545",
            pady=(0, 12),
        )

        # Action Pill Bar inside Left Column (compact spacing so zero buttons ever clip)
        self.btn_bar = tk.Frame(left_col, bg=self.BG)
        self.btn_bar.pack(fill=tk.X)

        self.btn_start = self._make_button(
            self.btn_bar,
            text="▶ 启动",
            command=lambda: self._run_async(self._start_all_worker, False),
            bg=self.PILL_PRIMARY,
            hover=self.PILL_PRIMARY_HOVER,
            padx=11,
        )
        self.btn_start.pack(side=tk.LEFT, padx=(0, 5))

        self.btn_restart = self._make_button(
            self.btn_bar,
            text="↻ 重启接管",
            command=lambda: self._run_async(self._start_all_worker, True),
            bg=self.PILL_SLATE,
            hover=self.PILL_SLATE_HOVER,
            highlight="#383838",
            padx=10,
        )
        self.btn_restart.pack(side=tk.LEFT, padx=(0, 5))

        self.btn_stop = self._make_button(
            self.btn_bar,
            text="■ 停止",
            command=lambda: self._run_async(self._stop_all_worker, True),
            bg=self.PILL_DANGER,
            hover=self.PILL_DANGER_HOVER,
            padx=10,
        )
        self.btn_stop.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_revoke = self._make_button(
            self.btn_bar,
            text="🔒 踢出并换密",
            command=lambda: self._run_async(self._revoke_tokens_worker),
            bg="#3B1D24",
            hover="#5C2532",
            highlight="#6B2C3B",
            fg="#FCA5A5",
            padx=9,
        )
        self.btn_revoke.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_open_web = self._make_button(
            self.btn_bar,
            text="🖥 网页",
            command=self._open_local_browser,
            bg="#ECECEC",
            hover="#FFFFFF",
            fg="#0D0D0D",
            padx=9,
        )
        self.btn_open_web.pack(side=tk.LEFT, padx=(0, 5))

        self.btn_folder = self._make_button(
            self.btn_bar,
            text="📂 目录",
            command=self._open_config_folder,
            bg=self.PILL_SLATE,
            hover=self.PILL_SLATE_HOVER,
            highlight="#383838",
            padx=9,
        )
        self.btn_folder.pack(side=tk.LEFT, padx=(0, 5))

        self.btn_clean = self._make_button(
            self.btn_bar,
            text="🧹 清理",
            command=self._clean_cache_async,
            bg=self.PILL_SLATE,
            hover=self.PILL_SLATE_HOVER,
            highlight="#383838",
            padx=9,
        )
        self.btn_clean.pack(side=tk.LEFT)

        # Right Column: Inline QR Pairing Card
        qr_card = tk.Frame(
            hero_grid,
            bg=self.QR_SURFACE,
            highlightbackground="#333333",
            highlightthickness=1,
            padx=14,
            pady=12,
            width=286,
        )
        qr_card.grid(row=0, column=1, sticky="ns")

        qr_hdr = tk.Frame(qr_card, bg=self.QR_SURFACE)
        qr_hdr.pack(fill=tk.X)
        tk.Label(
            qr_hdr,
            text="扫码直连",
            bg=self.QR_SURFACE,
            fg=self.TEXT_PRIMARY,
            font=("Microsoft YaHei UI", 10, "bold"),
        ).pack(side=tk.LEFT)

        self.qr_tab_ios = self._make_button(
            qr_hdr,
            text="📲 永久App",
            command=lambda: self._switch_qr_mode("ios"),
            bg="#ECECEC",
            hover="#FFFFFF",
            fg="#0D0D0D",
            padx=7,
            pady=2,
            font_size=8,
        )
        self.qr_tab_lan = self._make_button(
            qr_hdr,
            text="Wi-Fi",
            command=lambda: self._switch_qr_mode("lan"),
            bg="#2F2F2F",
            hover="#3D3D3D",
            fg="#B4B4B4",
            padx=7,
            pady=2,
            font_size=8,
        )
        self.qr_tab_tunnel = self._make_button(
            qr_hdr,
            text="外网",
            command=lambda: self._switch_qr_mode("tunnel"),
            bg="#2F2F2F",
            hover="#3D3D3D",
            fg="#B4B4B4",
            padx=7,
            pady=2,
            font_size=8,
        )
        self.qr_tab_tunnel.pack(side=tk.RIGHT, padx=(3, 0))
        self.qr_tab_lan.pack(side=tk.RIGHT, padx=(3, 0))
        if self._ios_pages_url and self._beacon_synced:
            self.qr_tab_ios.pack(side=tk.RIGHT)

        self.qr_img_lbl = tk.Label(
            qr_card,
            bg=self.QR_SURFACE,
            fg=self.TEXT_SECONDARY,
            font=("Microsoft YaHei UI", 8),
            pady=4,
        )
        self.qr_img_lbl.pack(pady=(6, 2))

        self.qr_url_lbl = tk.Label(
            qr_card,
            text="",
            bg=self.QR_SURFACE,
            fg=self.TEXT_SECONDARY,
            font=("Consolas", 8),
            wraplength=250,
        )
        self.qr_url_lbl.pack()

        qr_actions = tk.Frame(qr_card, bg=self.QR_SURFACE)
        qr_actions.pack(pady=(6, 0))

        self._make_button(
            qr_actions,
            text="复制一次性配对链接",
            command=self._copy_qr_link,
            bg="#2F2F2F",
            hover="#3D3D3D",
            padx=10,
            pady=4,
            font_size=8,
        ).pack(side=tk.LEFT, padx=3)

        self.fw_btn = self._make_button(
            qr_actions,
            text="放行防火墙",
            command=self._allow_firewall,
            bg="#2F2F2F",
            hover="#10A37F",
            padx=9,
            pady=4,
            font_size=8,
        )

        self._render_inline_qr()

        # ── Log Stream Header ──
        log_hdr = tk.Frame(outer, bg=self.BG)
        log_hdr.pack(fill=tk.X, pady=(2, 6))

        tk.Label(
            log_hdr,
            text="实时运行流",
            bg=self.BG,
            fg=self.TEXT_PRIMARY,
            font=("Microsoft YaHei UI", 10, "bold"),
        ).pack(side=tk.LEFT)

        self._make_button(
            log_hdr,
            text="清空日志",
            command=self._clear_logs,
            bg="#101B2D",
            hover="#1B2E4B",
            fg=self.TEXT_SECONDARY,
            padx=10,
            pady=2,
            font_size=8,
        ).pack(side=tk.RIGHT)

        tk.Checkbutton(
            log_hdr,
            text="显示底层隧道帧",
            variable=self._show_debug_var,
            command=lambda: setattr(self, "_show_debug", bool(self._show_debug_var.get())),
            bg=self.BG,
            fg=self.TEXT_MUTED,
            selectcolor="#101B2D",
            activebackground=self.BG,
            activeforeground=self.TEXT_PRIMARY,
            font=("Microsoft YaHei UI", 8),
            bd=0,
            highlightthickness=0,
            cursor="hand2",
        ).pack(side=tk.RIGHT, padx=(0, 12))

        # ── Frosted Glass Terminal Panel ──
        log_glass_border = tk.Frame(outer, bg="#1E324D", padx=1, pady=1)
        log_glass_border.pack(fill=tk.BOTH, expand=True)

        inner_log = tk.Frame(log_glass_border, bg=self.LOG_BG, padx=4, pady=4)
        inner_log.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(
            inner_log,
            bg=self.LOG_BG,
            fg="#CBD5E1",
            insertbackground="#CBD5E1",
            selectbackground="#1E3A5F",
            font=("Consolas", 9),
            wrap=tk.WORD,
            relief=tk.FLAT,
            bd=0,
            highlightthickness=0,
            padx=10,
            pady=6,
            state=tk.DISABLED,
        )
        scrollbar = ttk.Scrollbar(
            inner_log,
            orient=tk.VERTICAL,
            command=self.log_text.yview,
            style="Glass.Vertical.TScrollbar",
        )
        self.log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(2, 0))
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.log_text.tag_configure("ts", foreground="#475569")
        self.log_text.tag_configure("sys", foreground="#94A3B8")
        self.log_text.tag_configure("engine", foreground="#38BDF8")
        self.log_text.tag_configure("tunnel", foreground="#34D399")
        self.log_text.tag_configure("warn", foreground="#FBBF24")
        self.log_text.tag_configure("err", foreground="#FB7185")

        tk.Label(
            outer,
            text="最小化窗口后「Stayy」会在后台静默值守；点击『🔒 踢出并换密』可立即切断全部已连接手机会话。",
            bg=self.BG,
            fg="#475569",
            font=("Microsoft YaHei UI", 8),
            anchor="w",
            pady=5,
        ).pack(fill=tk.X)

    def _create_glass_card(
        self,
        parent: tk.Frame,
        *,
        title: str,
        detail: str,
        rim_color: str,
        pady: tuple[int, int] = (0, 8),
    ) -> tuple[tk.Label, tk.Label, tk.Label]:
        card_canvas = tk.Canvas(
            parent,
            bg=self.BG,
            height=92,
            bd=0,
            highlightthickness=0,
            relief=tk.FLAT,
        )
        card_canvas.pack(fill=tk.X, pady=pady)

        content = tk.Frame(card_canvas, bg=self.GLASS_SURFACE)

        tk.Label(
            content,
            text=title,
            bg=self.GLASS_SURFACE,
            fg="#7C93B0",
            font=("Segoe UI", 8, "bold"),
            anchor="w",
        ).pack(fill=tk.X)

        status_row = tk.Frame(content, bg=self.GLASS_SURFACE)
        status_row.pack(fill=tk.X, pady=(4, 3))

        orb_lbl = tk.Label(status_row, image=self._orbs["amber"], bg=self.GLASS_SURFACE, bd=0)
        orb_lbl.pack(side=tk.LEFT, padx=(0, 8))

        status_lbl = tk.Label(
            status_row,
            text="正在检测状态...",
            bg=self.GLASS_SURFACE,
            fg=self.TEXT_PRIMARY,
            font=("Microsoft YaHei UI", 11, "bold"),
            anchor="w",
        )
        status_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        detail_lbl = tk.Label(
            content,
            text=detail,
            bg=self.GLASS_SURFACE,
            fg="#64748B",
            font=("Microsoft YaHei UI", 8),
            anchor="w",
        )
        detail_lbl.pack(fill=tk.X)

        bg_item = card_canvas.create_image(0, 0, anchor="nw")
        win_item = card_canvas.create_window(16, 12, anchor="nw", window=content)
        resize_after_id: list[str | None] = [None]

        def _redraw(event: tk.Event) -> None:  # type: ignore[type-arg]
            w, h = max(event.width, 60), max(event.height, 60)
            card_canvas.itemconfigure(win_item, width=max(w - 32, 30))

            def _render() -> None:
                resize_after_id[0] = None
                if self._closing:
                    return
                img = self._get_glass_image(
                    w,
                    h,
                    radius=15,
                    rim_top=rim_color,
                    top_fill=self.GLASS_SURFACE,
                    bottom_fill=self.GLASS_SURFACE,
                )
                card_canvas.itemconfigure(bg_item, image=img)

            if resize_after_id[0] is not None:
                try:
                    self.root.after_cancel(resize_after_id[0])
                except Exception:
                    pass
            resize_after_id[0] = self.root.after(25, _render)

        card_canvas.bind("<Configure>", _redraw)
        return (orb_lbl, status_lbl, detail_lbl)

    def _make_button(
        self,
        parent: tk.Widget,
        text: str,
        command,
        bg: str,
        hover: str,
        fg: str = "#F8FAFC",
        highlight: str | None = None,
        padx: int = 14,
        pady: int = 7,
        font_size: int = 9,
    ) -> tk.Button:
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=hover,
            activeforeground="#FFFFFF",
            disabledforeground="#475569",
            font=("Microsoft YaHei UI", font_size, "bold"),
            relief=tk.FLAT,
            bd=0,
            highlightthickness=1 if highlight else 0,
            highlightbackground=highlight or bg,
            highlightcolor=highlight or bg,
            padx=padx,
            pady=pady,
            cursor="hand2",
        )
        btn._base_bg = bg  # type: ignore[attr-defined]
        btn._hover_bg = hover  # type: ignore[attr-defined]
        btn.bind(
            "<Enter>",
            lambda _e: btn.configure(bg=btn._hover_bg) if btn["state"] == tk.NORMAL else None,  # type: ignore[attr-defined]
        )
        btn.bind("<Leave>", lambda _e: btn.configure(bg=btn._base_bg))  # type: ignore[attr-defined]
        return btn

    def _read_admin_state(self) -> dict[str, Any] | None:
        adm_file = RUNTIME_DIR / "admin.json"
        if not adm_file.is_file():
            return None
        try:
            data = json.loads(adm_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("port") and data.get("admin_token"):
                return data
        except Exception:
            pass
        return None

    def _admin_request(self, method: str, path: str, timeout: float = 2.0) -> dict[str, Any] | None:
        st = self._read_admin_state()
        if not st:
            return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(
            f"http://127.0.0.1:{int(st['port'])}{path}",
            method=method.upper(),
            data=(b"{}" if method.upper() == "POST" else None),
            headers={"X-Admin-Token": str(st["admin_token"])},
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                return json.loads(resp.read(16384).decode("utf-8", errors="replace"))
        except Exception:
            return None

    def _refresh_pair_code_worker(self) -> None:
        res = self._admin_request("POST", "/admin/pair")
        if res and res.get("ok") and res.get("code"):
            self._active_pair_code = str(res["code"])
            self._post_ui(self._render_inline_qr)

    def _revoke_tokens_worker(self) -> None:
        self._enqueue_log("安全", "正在轮换访问密钥并强制踢出全部已连接手机...", "warn")
        res = self._admin_request("POST", "/admin/revoke", timeout=4.0)
        if not res or not res.get("ok"):
            self._enqueue_log("安全", "撤销失败：Stayy 服务未就绪或写入 .env 失败。", "err")
            return
        self.settings = load_settings()
        closed_n = int(res.get("closed_clients") or 0)
        new_ep = int(res.get("auth_epoch") or 0)
        self._active_pair_code = ""
        pair_res = self._admin_request("POST", "/admin/pair")
        if pair_res and pair_res.get("ok"):
            self._active_pair_code = str(pair_res.get("code") or "")
        self._post_ui(self._render_inline_qr)
        self._enqueue_log(
            "安全",
            f"✓ 已轮换密钥至第 {new_ep} 代并强制断开 {closed_n} 台在线设备，旧会话已全部失效。",
            "tunnel",
        )
        if self._ios_pages_url and self._tunnel_url:
            threading.Thread(
                target=self._sync_ios_beacon_worker,
                args=(self._tunnel_url, self._tunnel_gen),
                daemon=True,
            ).start()

    def _current_qr_url(self) -> str:
        tok = self.settings.web_access_token
        mode = self._qr_mode.get()
        pair = self._active_pair_code
        query_suffix = f"?pair={pair}" if pair else f"?token={tok}"
        if mode == "ios" and self._ios_pages_url and self._beacon_synced:
            # Fragment `#key=` stays strictly client-side and never enters CDN logs!
            return f"{self._ios_pages_url}#key={tok}"
        if mode == "tunnel":
            base = self.settings.public_base_url or self._tunnel_url
            return f"{base.rstrip('/')}/{query_suffix}" if base else ""
        lan_ip = get_lan_ipv4()
        return f"http://{lan_ip}:{self.settings.web_pwa_port}/{query_suffix}"

    def _switch_qr_mode(self, mode: str) -> None:
        self._qr_mode.set(mode)
        self._render_inline_qr()

    def _render_inline_qr(self) -> None:
        if self._closing:
            return
        if self._ios_pages_url and self._beacon_synced:
            if not self.qr_tab_ios.winfo_ismapped():
                self.qr_tab_ios.pack(side=tk.RIGHT)
        elif self.qr_tab_ios.winfo_ismapped():
            self.qr_tab_ios.pack_forget()

        m = self._qr_mode.get()
        for btn, active in (
            (self.qr_tab_ios, m == "ios"),
            (self.qr_tab_lan, m == "lan"),
            (self.qr_tab_tunnel, m == "tunnel"),
        ):
            bg = "#ECECEC" if active else "#2F2F2F"
            fg = "#0D0D0D" if active else "#B4B4B4"
            btn._base_bg = bg  # type: ignore[attr-defined]
            btn.configure(bg=bg, fg=fg)

        target_u = self._current_qr_url()
        if not target_u:
            self.qr_img_lbl.configure(
                image="",
                text="\n正在建立外网连接...\n（同 Wi-Fi 可点 Wi-Fi 扫码，或配置 Tailscale）\n",
            )
            self.qr_url_lbl.configure(text="等待公网/隧道地址就绪")
            return

        try:
            import segno
            buf = io.BytesIO()
            segno.make(target_u, error="m").save(
                buf, kind="png", scale=4, border=2, dark="#ECECEC", light=self.QR_SURFACE
            )
            b64 = base64.b64encode(buf.getvalue()).decode("ascii")
            photo = tk.PhotoImage(data=b64)
            self._qr_photo_ref.clear()
            self._qr_photo_ref.append(photo)
            self.qr_img_lbl.configure(image=photo, text="")
            if m == "ios":
                self.qr_url_lbl.configure(text="自建信标已验真 (使用 #key 客户端分片)")
            else:
                masked = target_u.split("?")[0] + (" (一次性配对码)" if self._active_pair_code else "")
                self.qr_url_lbl.configure(text=masked)
        except Exception as exc:
            self.qr_img_lbl.configure(image="", text=f"二维码渲染失败：{exc}")

    def _copy_qr_link(self) -> None:
        # Mint a fresh one-time pairing link when available so repeated copies never collide
        res = self._admin_request("POST", "/admin/pair")
        if res and res.get("ok") and res.get("code"):
            self._active_pair_code = str(res["code"])
        lan_ip = get_lan_ipv4()
        fallback = f"http://{lan_ip}:{self.settings.web_pwa_port}/?token={self.settings.web_access_token}"
        u = self._current_qr_url() or fallback
        self.root.clipboard_clear()
        self.root.clipboard_append(u)
        self._render_inline_qr()
        self.qr_url_lbl.configure(text="✓ 已复制一次性配对链接！")

    def _open_local_browser(self) -> None:
        res = self._admin_request("POST", "/admin/pair")
        if res and res.get("ok") and res.get("code"):
            url = f"http://127.0.0.1:{self.settings.web_pwa_port}/?pair={res['code']}"
        else:
            url = f"http://127.0.0.1:{self.settings.web_pwa_port}/?token={self.settings.web_access_token}"
        webbrowser.open(url)

    def _check_firewall_bg(self) -> None:
        ok = is_lan_firewall_rule_present(self.settings.web_pwa_port)
        if not ok:
            self._post_ui(lambda: self.fw_btn.pack(side=tk.LEFT, padx=3))

    def _allow_firewall(self) -> None:
        if request_lan_firewall_allow(self.settings.web_pwa_port):
            self.qr_url_lbl.configure(text=f"✓ 已放行局域网端口 {self.settings.web_pwa_port}")
            self.fw_btn.pack_forget()

    def _refresh_conv_stats_bg(self) -> None:
        try:
            items = list_local_conversations(limit=500)
            n_ide = sum(1 for x in items if x.store == "ide")
            n_codex = sum(1 for x in items if x.store == "codex")
            n_cli = sum(1 for x in items if x.store == "cli")
            parts = [f"Antigravity {n_ide}"]
            if n_codex > 0:
                parts.append(f"Codex {n_codex}")
            if n_cli > 0:
                parts.append(f"远程 {n_cli}")
            self._conv_stats_str = f"{' · '.join(parts)}（共 {len(items)}）"
            self._post_ui(
                lambda: self.engine_detail_lbl.configure(
                    text=f"模型：{self.settings.active_model}  ·  会话：{self._conv_stats_str}"
                )
            )
        except Exception:
            pass

    def _on_toggle_autostart(self) -> None:
        want = bool(self._autostart_var.get())
        ok = set_autostart_enabled(want)
        if not ok:
            self._autostart_var.set(not want)
            self._enqueue_log("系统", "设置开机自启快捷方式失败。", "err")
            return
        msg = "已开启开机静默自启（开机后自动最小化值守）。" if want else "已关闭开机自启。"
        self._enqueue_log("系统", msg, "sys")

    def _on_toggle_keep_awake(self) -> None:
        want = bool(self._keep_awake_var.get())
        self._prefs["keep_awake"] = want
        save_ui_prefs(self._prefs)
        set_prevent_system_sleep(want and self._desired_running)
        msg = "已开启防自动休眠保活（屏幕仍可正常熄灭省电）。" if want else "已关闭防休眠保活。"
        self._enqueue_log("系统", msg, "sys")

    def _enqueue_log(self, source: str, message: str, tag: str = "sys") -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_queue.put((ts, source, f"{tag}|{message}"))

    def _post_ui(self, fn: Callable[[], None]) -> None:
        if not self._closing:
            self._ui_queue.put(fn)

    def _start_ui_loops(self) -> None:
        self._drain_ui_and_logs()
        self._schedule_health_poll()

    def _drain_ui_and_logs(self) -> None:
        if self._closing:
            return
        for _ in range(50):
            try:
                fn = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                fn()
            except tk.TclError:
                return

        batch: list[tuple[str, str, str, str]] = []
        for _ in range(80):
            try:
                ts, source, payload = self._log_queue.get_nowait()
            except queue.Empty:
                break
            tag, _, msg = payload.partition("|")
            batch.append((ts, source, tag, msg))

        if batch:
            self.log_text.configure(state=tk.NORMAL)
            for ts, source, tag, msg in batch:
                self.log_text.insert(tk.END, f"{ts}  ", "ts")
                self.log_text.insert(tk.END, f"[{source}] ", tag)
                self.log_text.insert(
                    tk.END,
                    f"{msg}\n",
                    "err" if tag == "err" else ("warn" if tag == "warn" else ""),
                )

            line_count = int(self.log_text.index("end-1c").split(".")[0])
            if line_count > self.MAX_LOG_LINES:
                self.log_text.delete("1.0", f"{line_count - self.MAX_LOG_LINES}.0")
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)

        self.root.after(80, self._drain_ui_and_logs)

    def _schedule_health_poll(self) -> None:
        if self._closing:
            return
        threading.Thread(target=self._health_poll_worker, daemon=True).start()
        self.root.after(2500, self._schedule_health_poll)

    def _health_poll_worker(self, force: bool = False) -> None:
        if self._closing or (self._busy and not force):
            return
        gw_ident = probe_stayy_gateway_identity("127.0.0.1", self.settings.web_pwa_port, timeout=0.45)
        pwa_open = gw_ident == "stayy"
        if pwa_open and not self._active_pair_code:
            res = self._admin_request("POST", "/admin/pair")
            if res and res.get("ok") and res.get("code"):
                self._active_pair_code = str(res["code"])
                self._post_ui(self._render_inline_qr)
        srv_alive = self._server_proc is not None and self._server_proc.poll() is None
        tun_alive = self._tunnel_proc is not None and self._tunnel_proc.poll() is None

        need_srv_heal = (
            self._desired_running
            and not self._busy
            and not srv_alive
            and not self._server_external
            and not self._port_conflict
            and not self._closing
        )
        need_tun_heal = (
            self._desired_running
            and not self._busy
            and not self._port_conflict
            and self.settings.web_pwa_enabled
            and self.settings.tunnel_enabled
            and pwa_open
            and not tun_alive
            and not self._closing
        )

        if (need_srv_heal or need_tun_heal) and self._op_lock.acquire(blocking=False):
            try:
                if (
                    self._desired_running
                    and not self._closing
                    and not self._server_external
                    and not self._port_conflict
                    and (self._server_proc is None or self._server_proc.poll() is not None)
                ):
                    now = time.monotonic()
                    self._auto_restart_timestamps = [t for t in self._auto_restart_timestamps if now - t < 120.0]
                    if len(self._auto_restart_timestamps) < 3:
                        self._auto_restart_timestamps.append(now)
                        self._enqueue_log("系统", "检测到核心服务未就绪，正在自动自愈拉起...", "warn")
                        self._launch_server()
                        srv_alive = self._server_proc is not None and self._server_proc.poll() is None

                if (
                    self._desired_running
                    and not self._closing
                    and not self._port_conflict
                    and self.settings.web_pwa_enabled
                    and self.settings.tunnel_enabled
                    and pwa_open
                    and (self._tunnel_proc is None or self._tunnel_proc.poll() is not None)
                ):
                    now_t = time.monotonic()
                    self._tunnel_restart_timestamps = [t for t in self._tunnel_restart_timestamps if now_t - t < 180.0]
                    if len(self._tunnel_restart_timestamps) < 4:
                        self._tunnel_restart_timestamps.append(now_t)
                        self._enqueue_log("Tunnel", "检测到外网加密隧道中断，正在自动重连并同步信标...", "warn")
                        self._launch_tunnel()
                        tun_alive = self._tunnel_proc is not None and self._tunnel_proc.poll() is None
            finally:
                self._op_lock.release()

        self._post_ui(lambda: self._refresh_status_ui(pwa_open, srv_alive, tun_alive))

    def _refresh_status_ui(self, pwa_open: bool, srv_alive: bool, tun_alive: bool) -> None:
        if self._closing:
            return
        lan_ip = get_lan_ipv4()
        port = self.settings.web_pwa_port

        if self._port_conflict:
            self._set_card(
                self.engine_orb_lbl,
                self.engine_status_lbl,
                "red",
                f"端口冲突 · 本地 :{port} 已被其他未知程序占用（已阻止公网隧道映射）",
            )
            self._set_card(self.net_orb_lbl, self.net_status_lbl, "red", "网络与外网隧道已安全阻断")
            return

        if srv_alive and pwa_open:
            self._set_card(
                self.engine_orb_lbl,
                self.engine_status_lbl,
                "green",
                f"在线值守中 · 本地端口 :{port} 已就绪",
            )
        elif self._server_external and pwa_open:
            self._set_card(
                self.engine_orb_lbl,
                self.engine_status_lbl,
                "green",
                f"后台运行中 · 端口 :{port} 已连通（可点『重启并接管』统一管理）",
            )
        elif srv_alive:
            self._set_card(self.engine_orb_lbl, self.engine_status_lbl, "amber", "正在启动 Stayy 核心网关...")
        else:
            self._set_card(self.engine_orb_lbl, self.engine_status_lbl, "red", "服务已停止")

        if pwa_open:
            ext_addr = self.settings.public_base_url or (self._tunnel_url if tun_alive else "")
            if ext_addr:
                self._set_card(
                    self.net_orb_lbl,
                    self.net_status_lbl,
                    "green",
                    "双通道全通 · Wi-Fi 直连 + 安全外网通道",
                )
                self.net_detail_lbl.configure(
                    text=f"局域网：http://{lan_ip}:{port}   ·   外网：{ext_addr}"
                )
            elif tun_alive:
                self._set_card(
                    self.net_orb_lbl,
                    self.net_status_lbl,
                    "green",
                    f"Wi-Fi 直连已就绪 (http://{lan_ip}:{port}) · 正在分配隧道...",
                )
            else:
                self._set_card(
                    self.net_orb_lbl,
                    self.net_status_lbl,
                    "green",
                    f"局域网直连已就绪 · http://{lan_ip}:{port}",
                )
                self.net_detail_lbl.configure(text="手机连同一 Wi-Fi（或 Tailscale 私网）扫右侧二维码即可配对")
        else:
            self._set_card(self.net_orb_lbl, self.net_status_lbl, "red", "网络监听未启动")

    def _set_card(self, orb_lbl: tk.Label, lbl: tk.Label, orb_key: str, text: str) -> None:
        orb_img = self._orbs.get(orb_key)
        if orb_img is not None:
            orb_lbl.configure(image=orb_img)
        lbl.configure(text=text)

    def _set_buttons_busy(self, busy: bool) -> None:
        state = tk.DISABLED if busy else tk.NORMAL
        for btn in (self.btn_start, self.btn_restart, self.btn_stop, self.btn_revoke):
            btn.configure(state=state)

    def _run_async(self, fn, *args) -> None:
        def _wrapper() -> None:
            if not self._op_lock.acquire(blocking=False):
                return
            try:
                self._busy = True
                self._post_ui(lambda: self._set_buttons_busy(True))
                fn(*args)
            finally:
                self._busy = False
                self._op_lock.release()
                if not self._closing:
                    self._post_ui(lambda: self._set_buttons_busy(False))
                    self._health_poll_worker(force=True)

        threading.Thread(target=_wrapper, daemon=True).start()

    def _start_all_worker(self, takeover: bool) -> None:
        self._desired_running = True
        if self._keep_awake_var.get():
            set_prevent_system_sleep(True)
        self._auto_restart_timestamps.clear()
        self.settings = load_settings()
        self._post_ui(self._render_inline_qr)
        threading.Thread(target=self._refresh_conv_stats_bg, daemon=True).start()

        if takeover:
            self._enqueue_log("系统", "正在平滑重启并接管 Stayy 全部服务...", "sys")
            self._stop_all_internal(include_external=True)
            time.sleep(0.5)
        else:
            self._enqueue_log("系统", "正在启动 Stayy 核心网关...", "sys")

        managed_pids: set[int] = {os.getpid()}
        if self._server_proc and self._server_proc.poll() is None:
            managed_pids.add(self._server_proc.pid)

        self._port_conflict = False
        ext_srv = find_external_server_processes(managed_pids)
        gw_ident = probe_stayy_gateway_identity("127.0.0.1", self.settings.web_pwa_port, timeout=0.6)

        if self._server_proc and self._server_proc.poll() is None:
            self._server_external = False
            self._enqueue_log("系统", "Stayy 核心网关已在本窗口运行中。", "sys")
        elif gw_ident == "stayy" or (ext_srv and gw_ident != "foreign"):
            self._server_external = True
            self._enqueue_log(
                "系统",
                "检测到后台已有通过身份校验的 Stayy 核心进程，已安全复用（点『↻ 重启接管』可加载最新配置）。",
                "sys",
            )
        elif gw_ident == "foreign":
            self._server_external = False
            self._port_conflict = True
            self._enqueue_log(
                "系统",
                f"端口冲突：本地端口 :{self.settings.web_pwa_port} 已被其他非 Stayy 程序占用！已中止建立公网隧道，请修改 WEB_PWA_PORT 或关闭占用程序。",
                "err",
            )
            return
        else:
            self._server_external = False
            self._launch_server()
            for _ in range(12):
                time.sleep(0.25)
                gw_ident = probe_stayy_gateway_identity("127.0.0.1", self.settings.web_pwa_port, timeout=0.45)
                if gw_ident == "stayy":
                    break
                if self._server_proc is not None and self._server_proc.poll() is not None:
                    break

        if gw_ident == "stayy":
            self._refresh_pair_code_worker()

        if self.settings.web_pwa_enabled and self.settings.tunnel_enabled and gw_ident == "stayy":
            if self._tunnel_proc is None or self._tunnel_proc.poll() is not None:
                self._launch_tunnel()

    def _launch_server(self) -> None:
        venv_python = self.settings.project_dir / ".venv" / "Scripts" / "python.exe"
        py_exe = venv_python if venv_python.is_file() else Path(sys.executable)
        if py_exe.name.lower() == "pythonw.exe":
            candidate = py_exe.with_name("python.exe")
            if candidate.is_file():
                py_exe = candidate

        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUNBUFFERED"] = "1"
        agy_bin = Path(os.environ.get("LOCALAPPDATA", "")) / "agy" / "bin"
        if agy_bin.is_dir():
            env["PATH"] = f"{agy_bin};{env.get('PATH', '')}"

        cmd = [str(py_exe), "-X", "utf8", "-u", "-m", "stayy.main"]
        self._enqueue_log("系统", "正在拉起反重力核心会话服务...", "sys")
        try:
            self._server_proc = subprocess.Popen(
                cmd,
                cwd=str(self.settings.project_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env,
                creationflags=CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
            )
            threading.Thread(
                target=self._stream_process_output,
                args=(self._server_proc, "Engine", "engine"),
                daemon=True,
            ).start()
        except Exception as exc:
            self._enqueue_log("系统", f"启动核心引擎失败：{exc}", "err")

    def _launch_tunnel(self) -> None:
        cf_exe = self.settings.project_dir / "bin" / "cloudflared.exe"
        if not cf_exe.is_file():
            which_cf = shutil.which("cloudflared")
            if which_cf and Path(which_cf).is_file():
                cf_exe = Path(which_cf)
            else:
                self._enqueue_log("系统", "未检测到 cloudflared.exe，当前可通过同 Wi-Fi 1ms 扫码直连。", "warn")
                return

        self._tunnel_gen += 1
        cur_gen = self._tunnel_gen
        self._tunnel_url = ""
        cmd = [
            str(cf_exe),
            "tunnel",
            "--url",
            f"http://127.0.0.1:{self.settings.web_pwa_port}",
            "--protocol",
            "http2",
            "--edge-ip-version",
            "4",
            "--no-autoupdate",
        ]
        self._enqueue_log("系统", "正在建立全球 4G/5G 加密隧道 (HTTP/2 直连)...", "sys")
        try:
            env = os.environ.copy()
            env["NO_PROXY"] = "127.0.0.1,localhost,::1"
            env["no_proxy"] = "127.0.0.1,localhost,::1"
            self._tunnel_proc = subprocess.Popen(
                cmd,
                cwd=str(self.settings.project_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env,
                creationflags=CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
            )
            threading.Thread(
                target=self._stream_process_output,
                args=(self._tunnel_proc, "Tunnel", "tunnel", cur_gen),
                daemon=True,
            ).start()
        except Exception as exc:
            self._enqueue_log("系统", f"启动加密隧道失败：{exc}", "warn")

    def _stream_process_output(
        self,
        proc: subprocess.Popen[str],
        source: str,
        default_tag: str,
        tun_gen: int = 0,
    ) -> None:
        assert proc.stdout is not None
        try:
            for raw_line in proc.stdout:
                if self._closing:
                    break
                line = ANSI_RE.sub("", raw_line).rstrip("\r\n")
                if not line.strip():
                    continue

                if source == "Tunnel":
                    m_cf = TRYCLOUDFLARE_RE.search(line)
                    if m_cf and tun_gen == self._tunnel_gen and not self._tunnel_url:
                        self._tunnel_url = m_cf.group(0)
                        self._enqueue_log(
                            "Tunnel",
                            f"全球 4G/5G 加密隧道已就绪：{self._tunnel_url}",
                            "tunnel",
                        )
                        self._post_ui(self._render_inline_qr)
                        threading.Thread(target=self._health_poll_worker, daemon=True).start()
                        threading.Thread(
                            target=self._sync_ios_beacon_worker,
                            args=(self._tunnel_url, tun_gen),
                            daemon=True,
                        ).start()
                    if not self._show_debug:
                        continue

                if source == "Engine" and "auto-switching to " in line:
                    new_m = line.split("auto-switching to ", 1)[1].split()[0].strip()
                    if new_m:
                        self._post_ui(
                            lambda m=new_m: self.engine_detail_lbl.configure(
                                text=f"当前模型：{m} (额度自动容灾切换)  ·  {self._conv_stats_str}"
                            )
                        )

                tag = default_tag
                if "[ERROR]" in line or "未找到 agy" in line:
                    tag = "err"
                elif "[WARNING]" in line or "[warn]" in line.lower():
                    tag = "warn"

                self._enqueue_log(source, line, tag)
        except Exception as exc:
            if not self._closing:
                self._enqueue_log("系统", f"{source} 日志流中断：{exc}", "warn")
        finally:
            code = proc.poll()
            if not self._closing and code is not None:
                self._enqueue_log("系统", f"{source} 进程已退出（退出码 {code}）。", "warn")

    def _sync_ios_beacon_worker(self, tunnel_url: str, tun_gen: int = 0) -> None:
        if not self._ios_pages_url or not tunnel_url or (tun_gen and tun_gen != self._tunnel_gen):
            return
        lan_url = f"http://{get_lan_ipv4()}:{self.settings.web_pwa_port}"
        ok, state_code, info = publish_ios_pwa_and_beacon(
            self.settings.project_dir,
            access_token=self.settings.web_access_token,
            tunnel_url=tunnel_url,
            lan_url=lan_url,
            host_id=self._host_id,
            beacon_enabled=self.settings.beacon_enabled,
            explicit_remote=self.settings.beacon_git_remote,
            beacon_branch=self.settings.beacon_branch,
            verify_live=True,
        )
        if tun_gen and tun_gen != self._tunnel_gen:
            return
        self._beacon_state = state_code
        if ok:
            self._beacon_synced = True
            self._enqueue_log(
                "Tunnel",
                f"✓ 已推送并读回验真用户自建信标 -> {info}",
                "tunnel",
            )
            self._post_ui(self._render_inline_qr)
        else:
            self._beacon_synced = False
            self._enqueue_log("Tunnel", f"信标未就绪 [{state_code}]：{info}", "warn")
            self._post_ui(self._render_inline_qr)

    def _stop_all_worker(self, include_external: bool) -> None:
        self._desired_running = False
        set_prevent_system_sleep(False)
        self._enqueue_log("系统", "正在停止 Stayy 后台服务...", "sys")
        self._stop_all_internal(include_external=include_external)
        self._active_pair_code = ""
        self._post_ui(self._render_inline_qr)
        self._enqueue_log("系统", "所有 Stayy 服务已安全停止。", "sys")

    def _stop_all_internal(self, include_external: bool) -> None:
        self._tunnel_gen += 1
        if self._tunnel_proc and self._tunnel_proc.poll() is None:
            kill_pid_tree(self._tunnel_proc.pid)
        self._tunnel_proc = None
        self._tunnel_url = ""

        if self._server_proc and self._server_proc.poll() is None:
            kill_pid_tree(self._server_proc.pid)
        self._server_proc = None
        self._server_external = False
        self._port_conflict = False

        if include_external:
            for pid in find_external_server_processes({os.getpid()}):
                kill_pid_tree(pid)

    def _open_config_folder(self) -> None:
        try:
            os.startfile(str(self.settings.project_dir))  # type: ignore[attr-defined]
        except Exception as exc:
            self._enqueue_log("系统", f"打开目录失败：{exc}", "err")

    def _clean_cache_async(self) -> None:
        def _worker() -> None:
            targets = discover_default_cache_targets(self.settings.project_dir)
            rep = run_safe_cache_cleanup(targets, force_all_expired_zero=True)
            self._enqueue_log("系统", rep.format_human(), "sys")

        threading.Thread(target=_worker, daemon=True).start()

    def _clear_logs(self) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _has_running_managed_services(self) -> bool:
        return self._server_proc is not None and self._server_proc.poll() is None

    def _on_close_requested(self) -> None:
        if self._has_running_managed_services():
            choice = messagebox.askyesnocancel(
                "关闭 Stayy",
                "Stayy 当前正在运行中。\n\n"
                "• 点击「是」：停止后台服务并彻底退出\n"
                "• 点击「否」：最小化到任务栏，继续安静值守\n"
                "• 点击「取消」：返回窗口",
                parent=self.root,
            )
            if choice is None:
                return
            if choice is False:
                self.root.iconify()
                return

            self._desired_running = False
            self._closing = True
            self.root.withdraw()

            def _shutdown_bg() -> None:
                try:
                    self._stop_all_internal(include_external=False)
                finally:
                    try:
                        self.root.quit()
                    except Exception:
                        pass

            threading.Thread(target=_shutdown_bg, daemon=True).start()
            return

        self._closing = True
        self.root.destroy()


def main() -> None:
    enable_high_dpi()
    set_windows_app_id()

    mutex_handle = acquire_single_instance_mutex()
    if mutex_handle is None:
        return

    start_minimized = "--minimized" in sys.argv
    root: tk.Tk | None = None
    try:
        settings = load_settings()
        root = tk.Tk()
        LauncherApp(root, settings, start_minimized=start_minimized)
        root.mainloop()
    finally:
        set_prevent_system_sleep(False)
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass
        close_mutex_handle(mutex_handle)


if __name__ == "__main__":
    main()
