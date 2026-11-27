"""Desktop capture, secure media validation, and workspace/Git inspection utilities for Stayy."""

from __future__ import annotations

import base64
import json
import logging
import math
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
_DESKTOP_UIA_LOCK = threading.Lock()
_GDIP_LOCK = threading.Lock()
_IDE_ACTION_LOCK = threading.Lock()
_IDE_ACTION_TOKENS: dict[str, dict[str, Any]] = {}

THOUGHT_TAG_RE = re.compile(
    r"<(?:thought|thinking|analysis)\b[^>]*>.*?</(?:thought|thinking|analysis)>",
    re.IGNORECASE | re.DOTALL,
)
SEND_IMAGE_RE = re.compile(r"\[SEND_IMAGE:\s*[\"']?([^\]\"'\r\n]+?)[\"']?\s*\]", re.IGNORECASE)
SEND_FILE_RE = re.compile(r"\[SEND_FILE:\s*[\"']?([^\]\"'\r\n]+?)[\"']?\s*\]", re.IGNORECASE)

PROJECT_INBOX_DIR = Path(__file__).resolve().parents[2] / "inbox"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

ALLOWED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
MAX_SEND_IMAGE_BYTES = 20 * 1024 * 1024
MAX_SEND_FILE_BYTES = 100 * 1024 * 1024
SENSITIVE_FILENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "agents.local.json",
    "admin.json",
    "beacon_state.json",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "auth.json",
    "passkey.json",
    "cookies.sqlite",
    "credentials.json",
}
SENSITIVE_KEY_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}


def is_sensitive_path(path_or_rel: Path | str) -> bool:
    """Return True when filename or suffix matches credentials, private keys, or Stayy runtime secrets."""
    name_low = Path(str(path_or_rel)).name.strip().lower()
    if not name_low:
        return False
    if name_low in SENSITIVE_FILENAMES or name_low.startswith(".env"):
        return True
    return Path(name_low).suffix in SENSITIVE_KEY_SUFFIXES

HIDDEN_DIR_SKIP = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
}

MODEL_ALIASES: dict[str, str] = {
    "fast": "claude-sonnet-5-5-low",
    "balanced": "claude-sonnet-5-5-medium",
    "smart": "claude-opus-5-5-medium",
    "opus": "claude-opus-5-5-medium",
    "sonnet": "claude-sonnet-5-5-medium",
    "gemini": "gemini-4-neon-medium",
    "flash": "gemini-3.8-flash-medium",
}


def sanitize_filename(name: str) -> str:
    """Keep a safe basename without path traversal characters."""
    base = Path(name or "file.bin").name
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", base).strip(" .")
    return (cleaned or "file.bin")[:120]


def is_safe_outbound_file(path: Path, *, image_only: bool = False) -> bool:
    """Block sensitive credential files and enforce extension / size limits."""
    try:
        resolved = path.resolve()
        if not resolved.is_file():
            return False
        name_low = resolved.name.lower()
        if is_sensitive_path(resolved):
            logger.warning("Blocked sending sensitive file: %s", resolved)
            return False
        size = resolved.stat().st_size
        if image_only:
            if resolved.suffix.lower() not in ALLOWED_IMAGE_EXTS:
                return False
            return 0 < size <= MAX_SEND_IMAGE_BYTES
        return 0 < size <= MAX_SEND_FILE_BYTES
    except OSError:
        return False


def prune_inbox(inbox_dir: Path, keep: int = 35, prefix_only: str = "") -> None:
    if not inbox_dir.is_dir():
        return
    files = sorted(
        (
            p
            for p in inbox_dir.iterdir()
            if p.is_file() and (not prefix_only or p.name.startswith(prefix_only))
        ),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for old in files[keep:]:
        try:
            old.unlink()
        except OSError:
            pass


_WIN32_DPI_READY = False
_JPEG_ENCODER_CLSID_BYTES: bytes | None = None


def _ensure_win32_dpi_aware() -> None:
    global _WIN32_DPI_READY
    if _WIN32_DPI_READY or sys.platform != "win32":
        return
    _WIN32_DPI_READY = True
    try:
        import ctypes

        user32 = ctypes.windll.user32
        # Try Per-Monitor V2 DPI Awareness (-4) first, fallback to system DPI aware
        try:
            user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        except Exception:
            user32.SetProcessDPIAware()
    except Exception:
        pass


def get_desktop_cursor_ratio() -> dict[str, float | int]:
    """Return current Windows physical cursor position normalized to VirtualScreen `[0.0, 1.0]`."""
    if sys.platform != "win32":
        return {"x_ratio": 0.5, "y_ratio": 0.5, "screen_w": 1920, "screen_h": 1080}
    _ensure_win32_dpi_aware()
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        vx = int(user32.GetSystemMetrics(76))
        vy = int(user32.GetSystemMetrics(77))
        vw = max(1, int(user32.GetSystemMetrics(78)))
        vh = max(1, int(user32.GetSystemMetrics(79)))
        pt = wintypes.POINT()
        if user32.GetCursorPos(ctypes.byref(pt)):
            xr = max(0.0, min(1.0, (pt.x - vx) / max(1, vw - 1)))
            yr = max(0.0, min(1.0, (pt.y - vy) / max(1, vh - 1)))
            return {"x_ratio": round(xr, 5), "y_ratio": round(yr, 5), "screen_w": vw, "screen_h": vh}
        return {"x_ratio": 0.5, "y_ratio": 0.5, "screen_w": vw, "screen_h": vh}
    except Exception:
        return {"x_ratio": 0.5, "y_ratio": 0.5, "screen_w": 1920, "screen_h": 1080}


def _capture_desktop_gdiplus_fast(dest: Path, max_width: int, quality: int) -> bool:
    """Serialize Win32 GDI/GDI+ desktop capture across threads."""
    if sys.platform != "win32":
        return False
    with _GDIP_LOCK:
        return _capture_desktop_gdiplus_fast_locked(dest, max_width, quality)


def _capture_desktop_gdiplus_fast_locked(dest: Path, max_width: int, quality: int) -> bool:
    """Fast ~35ms pure-ctypes Win32 GDI + GDI+ JPEG screen capture with hardware cursor stamped at exact hotspot."""
    if sys.platform != "win32":
        return False
    _ensure_win32_dpi_aware()
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32
    gdiplus = ctypes.windll.gdiplus

    # Explicit 64-bit Win32 handle types so HBITMAP / HDC / GpBitmap pointers > 0x7FFFFFFF are NEVER truncated!
    user32.GetDC.argtypes = [wintypes.HWND]
    user32.GetDC.restype = wintypes.HDC
    user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    user32.ReleaseDC.restype = ctypes.c_int
    user32.DrawIconEx.argtypes = [
        wintypes.HDC, ctypes.c_int, ctypes.c_int, wintypes.HANDLE,
        ctypes.c_int, ctypes.c_int, wintypes.UINT, wintypes.HBRUSH, wintypes.UINT,
    ]
    user32.DrawIconEx.restype = wintypes.BOOL

    gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
    gdi32.CreateCompatibleDC.restype = wintypes.HDC
    gdi32.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
    gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
    gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
    gdi32.SelectObject.restype = wintypes.HGDIOBJ
    gdi32.BitBlt.argtypes = [
        wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HDC, ctypes.c_int, ctypes.c_int, wintypes.DWORD,
    ]
    gdi32.BitBlt.restype = wintypes.BOOL
    gdi32.StretchBlt.argtypes = [
        wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.DWORD,
    ]
    gdi32.StretchBlt.restype = wintypes.BOOL
    gdi32.SetStretchBltMode.argtypes = [wintypes.HDC, ctypes.c_int]
    gdi32.SetBrushOrgEx.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    gdi32.DeleteObject.restype = wintypes.BOOL
    gdi32.DeleteDC.argtypes = [wintypes.HDC]
    gdi32.DeleteDC.restype = wintypes.BOOL
    gdi32.CreateDIBSection.argtypes = [
        wintypes.HDC,
        ctypes.c_void_p,
        wintypes.UINT,
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.HANDLE,
        wintypes.DWORD,
    ]
    gdi32.CreateDIBSection.restype = wintypes.HBITMAP

    gdiplus.GdiplusStartup.argtypes = [ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_void_p]
    gdiplus.GdiplusShutdown.argtypes = [ctypes.c_size_t]
    gdiplus.GdipCreateBitmapFromScan0.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    gdiplus.GdipSaveImageToFile.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p]
    gdiplus.GdipDisposeImage.argtypes = [ctypes.c_void_p]

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [
            ("biSize", wintypes.DWORD),
            ("biWidth", wintypes.LONG),
            ("biHeight", wintypes.LONG),
            ("biPlanes", wintypes.WORD),
            ("biBitCount", wintypes.WORD),
            ("biCompression", wintypes.DWORD),
            ("biSizeImage", wintypes.DWORD),
            ("biXPelsPerMeter", wintypes.LONG),
            ("biYPelsPerMeter", wintypes.LONG),
            ("biClrUsed", wintypes.DWORD),
            ("biClrImportant", wintypes.DWORD),
        ]

    class CURSORINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("flags", wintypes.DWORD),
            ("hCursor", wintypes.HANDLE),
            ("ptScreenPos", wintypes.POINT),
        ]

    class ICONINFO(ctypes.Structure):
        _fields_ = [
            ("fIcon", wintypes.BOOL),
            ("xHotspot", wintypes.DWORD),
            ("yHotspot", wintypes.DWORD),
            ("hbmMask", wintypes.HBITMAP),
            ("hbmColor", wintypes.HBITMAP),
        ]

    class GdiplusStartupInput(ctypes.Structure):
        _fields_ = [
            ("GdiplusVersion", ctypes.c_uint32),
            ("DebugEventCallback", ctypes.c_void_p),
            ("SuppressBackgroundThread", wintypes.BOOL),
            ("SuppressExternalCodecs", wintypes.BOOL),
        ]

    class EncoderParameter(ctypes.Structure):
        _fields_ = [
            ("Guid", ctypes.c_byte * 16),
            ("NumberOfValues", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
            ("Value", ctypes.c_void_p),
        ]

    class EncoderParameters(ctypes.Structure):
        _fields_ = [
            ("Count", ctypes.c_uint),
            ("Parameter", EncoderParameter * 1),
        ]

    vx = int(user32.GetSystemMetrics(76))
    vy = int(user32.GetSystemMetrics(77))
    vw = int(user32.GetSystemMetrics(78))
    vh = int(user32.GetSystemMetrics(79))
    if vw <= 0 or vh <= 0:
        return False

    target_w = min(vw, max(320, int(max_width)))
    target_h = max(180, int(round(vh * (target_w / float(vw)))))

    hdc_screen = user32.GetDC(0)
    if not hdc_screen:
        return False
    hdc_src = 0
    hbmp_src = 0
    old_src = 0
    hdc_dst = 0
    hbmp_dst = 0
    old_dst = 0
    gdip_token = ctypes.c_size_t(0)
    gp_bitmap = ctypes.c_void_p(0)

    try:
        hdc_src = gdi32.CreateCompatibleDC(hdc_screen)
        hbmp_src = gdi32.CreateCompatibleBitmap(hdc_screen, vw, vh)
        if not hdc_src or not hbmp_src:
            return False
        old_src = gdi32.SelectObject(hdc_src, hbmp_src)
        # SRCCOPY (0x00CC0020) | CAPTUREBLT (0x40000000)
        if not gdi32.BitBlt(hdc_src, 0, 0, vw, vh, hdc_screen, vx, vy, 0x40CC0020):
            return False

        # Stamp hardware mouse cursor onto `hdc_src` with hotspot compensation so mobile user sees real PC pointer!
        ci = CURSORINFO()
        ci.cbSize = ctypes.sizeof(CURSORINFO)
        if user32.GetCursorInfo(ctypes.byref(ci)) and (ci.flags & 0x00000001) and ci.hCursor:
            hx, hy = 0, 0
            ii = ICONINFO()
            if user32.GetIconInfo(ci.hCursor, ctypes.byref(ii)):
                hx = int(ii.xHotspot)
                hy = int(ii.yHotspot)
                if ii.hbmMask:
                    gdi32.DeleteObject(ii.hbmMask)
                if ii.hbmColor:
                    gdi32.DeleteObject(ii.hbmColor)
            user32.DrawIconEx(
                hdc_src,
                int(ci.ptScreenPos.x - vx - hx),
                int(ci.ptScreenPos.y - vy - hy),
                ci.hCursor,
                0,
                0,
                0,
                0,
                0x0003,  # DI_NORMAL
            )

        # Render into a top-down 32-bit RGB DIB section and wrap its raw pixel buffer via `GdipCreateBitmapFromScan0`
        # (PixelFormat32bppRGB = 0x0022009, completely compliant with GDI+ memory contract!)
        hdc_dst = gdi32.CreateCompatibleDC(hdc_screen)
        if not hdc_dst:
            return False
        bmi = BITMAPINFOHEADER()
        bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.biWidth = target_w
        bmi.biHeight = -target_h  # Top-down scanlines
        bmi.biPlanes = 1
        bmi.biBitCount = 32
        bmi.biCompression = 0  # BI_RGB
        bits_ptr = ctypes.c_void_p(0)
        hbmp_dst = gdi32.CreateDIBSection(hdc_screen, ctypes.byref(bmi), 0, ctypes.byref(bits_ptr), None, 0)
        if not hbmp_dst or not bits_ptr.value:
            return False
        old_dst = gdi32.SelectObject(hdc_dst, hbmp_dst)
        if target_w < vw:
            gdi32.SetStretchBltMode(hdc_dst, 4)  # HALFTONE crisp downscale
            gdi32.SetBrushOrgEx(hdc_dst, 0, 0, None)
            if not gdi32.StretchBlt(hdc_dst, 0, 0, target_w, target_h, hdc_src, 0, 0, vw, vh, 0x00CC0020):
                return False
        else:
            if not gdi32.BitBlt(hdc_dst, 0, 0, target_w, target_h, hdc_src, 0, 0, 0x00CC0020):
                return False
        gdi32.GdiFlush()

        startup_in = GdiplusStartupInput(1, None, False, False)
        if gdiplus.GdiplusStartup(ctypes.byref(gdip_token), ctypes.byref(startup_in), None) != 0:
            return False

        stride = target_w * 4
        # PixelFormat32bppRGB = 0x00022009 (ignores GDI's zeroed alpha byte!)
        if gdiplus.GdipCreateBitmapFromScan0(
            target_w, target_h, stride, 0x00022009, bits_ptr, ctypes.byref(gp_bitmap)
        ) != 0 or not gp_bitmap:
            return False

        # Standard Windows GDI+ Built-in JPEG Encoder CLSID: {557CF401-1A04-11D3-9A73-0000F81EF32E}
        jpeg_clsid = uuid.UUID("{557cf401-1a04-11d3-9a73-0000f81ef32e}").bytes_le
        # EncoderQuality GUID: {1D5BE4B5-FA4A-452D-9CDD-5DB35105E7EB}
        qual_guid = uuid.UUID("{1d5be4b5-fa4a-452d-9cdd-5db35105e7eb}").bytes_le

        q_val = ctypes.c_ulong(max(30, min(95, int(quality))))
        enc_params = EncoderParameters()
        enc_params.Count = 1
        enc_params.Parameter[0].Guid = (ctypes.c_byte * 16).from_buffer_copy(qual_guid)
        enc_params.Parameter[0].NumberOfValues = 1
        enc_params.Parameter[0].Type = 4  # EncoderParameterValueTypeLong
        enc_params.Parameter[0].Value = ctypes.cast(ctypes.pointer(q_val), ctypes.c_void_p)

        clsid_buf = (ctypes.c_byte * 16).from_buffer_copy(jpeg_clsid)
        status = gdiplus.GdipSaveImageToFile(
            gp_bitmap,
            ctypes.c_wchar_p(str(dest)),
            ctypes.byref(clsid_buf),
            ctypes.byref(enc_params),
        )
        return status == 0 and dest.is_file() and dest.stat().st_size > 0
    except Exception as exc:
        logger.debug("Fast GDI+ capture fallback triggered: %s", exc)
        return False
    finally:
        if gp_bitmap:
            gdiplus.GdipDisposeImage(gp_bitmap)
        if gdip_token.value:
            gdiplus.GdiplusShutdown(gdip_token)
        if old_dst and hdc_dst:
            gdi32.SelectObject(hdc_dst, old_dst)
        if hbmp_dst:
            gdi32.DeleteObject(hbmp_dst)
        if hdc_dst:
            gdi32.DeleteDC(hdc_dst)
        if old_src and hdc_src:
            gdi32.SelectObject(hdc_src, old_src)
        if hbmp_src:
            gdi32.DeleteObject(hbmp_src)
        if hdc_src:
            gdi32.DeleteDC(hdc_src)
        if hdc_screen:
            user32.ReleaseDC(0, hdc_screen)


def capture_desktop_fast_jpeg_sync(
    inbox_dir: Path, max_width: int = 1600, quality: int = 80
) -> Path:
    """Capture a scaled, crisp JPEG desktop frame (~100-180 KB) with live cursor in ~35ms."""
    preview_dir = inbox_dir / "previews"
    preview_dir.mkdir(parents=True, exist_ok=True)
    dest = preview_dir / f"preview_{int(time.time() * 1000)}_{uuid.uuid4().hex[:5]}.jpg"

    if _capture_desktop_gdiplus_fast(dest, max_width=max_width, quality=quality):
        prune_inbox(preview_dir, keep=28, prefix_only="preview_")
        return dest

    ps_script = f"""
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class DpiHelper {{
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
}}
"@
[DpiHelper]::SetProcessDPIAware() | Out-Null
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
$srcBmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$srcGfx = [System.Drawing.Graphics]::FromImage($srcBmp)
$srcGfx.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$srcGfx.Dispose()

$targetW = [Math]::Min($bounds.Width, {int(max_width)})
$targetH = [int]([Math]::Round($bounds.Height * ($targetW / [double]$bounds.Width)))
if ($targetW -lt $bounds.Width) {{
    $outBmp = New-Object System.Drawing.Bitmap $targetW, $targetH
    $outGfx = [System.Drawing.Graphics]::FromImage($outBmp)
    $outGfx.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $outGfx.DrawImage($srcBmp, 0, 0, $targetW, $targetH)
    $outGfx.Dispose()
    $srcBmp.Dispose()
}} else {{
    $outBmp = $srcBmp
}}

$codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object {{ $_.MimeType -eq 'image/jpeg' }} | Select-Object -First 1
$ep = New-Object System.Drawing.Imaging.EncoderParameters 1
$ep.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality, [long]{int(quality)})
$outBmp.Save('{str(dest).replace("'", "''")}', $codec, $ep)
$ep.Dispose()
$outBmp.Dispose()
"""
    subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            ps_script,
        ],
        check=True,
        capture_output=True,
        timeout=15,
        creationflags=CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )
    prune_inbox(preview_dir, keep=28, prefix_only="preview_")
    return dest


def _resolve_inside_workspace(workspace: Path, rel_path: str) -> Path | None:
    """Resolve a relative path strictly inside `workspace`, preventing path traversal."""
    try:
        ws_root = workspace.resolve()
        clean_rel = (rel_path or "").strip().lstrip("/\\")
        target = (ws_root / clean_rel).resolve() if clean_rel else ws_root
        if target != ws_root and ws_root not in target.parents:
            return None
        return target
    except OSError:
        return None


def inspect_workspace_git(workspace: Path) -> dict[str, Any]:
    """Return branch name and changed/untracked files for `workspace` (like Termote / Claude Code UI)."""
    ws = workspace.resolve()
    if not ws.is_dir():
        return {"is_git": False, "branch": "", "changes": []}

    extra = {"creationflags": CREATE_NO_WINDOW} if sys.platform == "win32" else {}
    try:
        branch_res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(ws),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=4,
            **extra,
        )
        if branch_res.returncode != 0:
            return {"is_git": False, "branch": "", "changes": []}
        branch = branch_res.stdout.strip()

        st_res = subprocess.run(
            ["git", "-c", "core.quotepath=false", "status", "--porcelain=v1", "-uall"],
            cwd=str(ws),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            **extra,
        )
        changes: list[dict[str, str]] = []
        for raw in (st_res.stdout or "").splitlines():
            if len(raw) < 4:
                continue
            code = raw[:2].strip() or "M"
            rel = raw[3:].strip()
            if " -> " in rel:
                old_rel, new_rel = rel.split(" -> ", 1)
                old_rel = old_rel.strip().strip('"')
                new_rel = new_rel.strip().strip('"')
                if is_sensitive_path(old_rel) or is_sensitive_path(new_rel):
                    continue
                rel = new_rel
            else:
                rel = rel.strip('"')
                if is_sensitive_path(rel):
                    continue
            changes.append({"status": code, "path": rel})
            if len(changes) >= 120:
                break
        return {"is_git": True, "branch": branch, "changes": changes}
    except Exception:
        return {"is_git": False, "branch": "", "changes": []}


def get_workspace_file_diff(workspace: Path, rel_path: str, max_chars: int = 24000) -> dict[str, Any]:
    """Return unified git diff (or new-file preview for untracked files) inside `workspace`."""
    target = _resolve_inside_workspace(workspace, rel_path)
    if target is None or is_sensitive_path(target):
        return {"ok": False, "path": rel_path, "diff": "无法读取该路径或敏感配置文件已受保护。"}

    ws = workspace.resolve()
    rel_clean = str(target.relative_to(ws)).replace("\\", "/")
    extra = {"creationflags": CREATE_NO_WINDOW} if sys.platform == "win32" else {}
    try:
        st_chk = subprocess.run(
            ["git", "-c", "core.quotepath=false", "status", "--porcelain=v1"],
            cwd=str(ws),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=4,
            **extra,
        )
        for st_line in (st_chk.stdout or "").splitlines():
            if len(st_line) < 4:
                continue
            rel_st = st_line[3:].strip()
            if " -> " in rel_st:
                old_st, new_st = rel_st.split(" -> ", 1)
                old_clean = old_st.strip().strip('"')
                new_clean = new_st.strip().strip('"')
                if (new_clean == rel_clean or old_clean == rel_clean) and (
                    is_sensitive_path(old_clean) or is_sensitive_path(new_clean)
                ):
                    return {"ok": False, "path": rel_clean, "diff": "无法读取该路径或敏感配置文件已受保护。"}

        res = subprocess.run(
            ["git", "-c", "core.quotepath=false", "diff", "HEAD", "--", rel_clean],
            cwd=str(ws),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            **extra,
        )
        diff_txt = (res.stdout or "").strip()
        if not diff_txt:
            # Might be untracked or repo has no HEAD commit yet
            res2 = subprocess.run(
                ["git", "-c", "core.quotepath=false", "diff", "--", rel_clean],
                cwd=str(ws),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                **extra,
            )
            diff_txt = (res2.stdout or "").strip()
        if not diff_txt and target.is_file():
            raw_txt = target.read_text(encoding="utf-8", errors="replace")
            added = "\n".join(f"+{ln}" for ln in raw_txt.splitlines()[:300])
            diff_txt = f"--- /dev/null\n+++ b/{rel_clean}\n@@ 新文件预览 @@\n{added}"
        for dline in diff_txt.splitlines():
            ref_path = ""
            if dline.startswith("--- a/"):
                ref_path = dline[6:].strip()
            elif dline.startswith("+++ b/"):
                ref_path = dline[6:].strip()
            elif dline.startswith("rename from "):
                ref_path = dline[12:].strip()
            elif dline.startswith("rename to "):
                ref_path = dline[10:].strip()
            if ref_path and is_sensitive_path(ref_path.strip('"')):
                return {"ok": False, "path": rel_clean, "diff": "无法读取该路径或敏感配置文件已受保护。"}
        if len(diff_txt) > max_chars:
            diff_txt = diff_txt[:max_chars] + "\n\n... (Diff 较长，已截断显示前 24KB)"
        return {"ok": True, "path": rel_clean, "diff": diff_txt or "（无文本差异或二进制文件）"}
    except Exception as exc:
        return {"ok": False, "path": rel_clean, "diff": f"读取 Diff 失败：{exc}"}


def list_workspace_directory(workspace: Path, rel_dir: str = "") -> dict[str, Any]:
    """List directories and safe files inside `workspace / rel_dir` for mobile file explorer."""
    target = _resolve_inside_workspace(workspace, rel_dir)
    ws = workspace.resolve()
    if target is None or not target.is_dir():
        return {"ok": False, "rel_dir": "", "entries": []}

    rel_norm = "" if target == ws else str(target.relative_to(ws)).replace("\\", "/")
    dirs: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []

    try:
        for child in sorted(target.iterdir(), key=lambda p: p.name.lower()):
            name = child.name
            if is_sensitive_path(child):
                continue
            child_rel = str(child.relative_to(ws)).replace("\\", "/")
            if child.is_dir():
                if name in HIDDEN_DIR_SKIP:
                    continue
                dirs.append({"name": name, "rel_path": child_rel, "is_dir": True, "size": 0})
            elif child.is_file():
                try:
                    sz = child.stat().st_size
                except OSError:
                    sz = 0
                files.append({"name": name, "rel_path": child_rel, "is_dir": False, "size": sz})
    except OSError:
        pass

    return {
        "ok": True,
        "workspace": str(ws),
        "rel_dir": rel_norm,
        "entries": (dirs + files)[:180],
    }


def read_workspace_file_preview(workspace: Path, rel_path: str, max_chars: int = 24000) -> dict[str, Any]:
    """Read a safe UTF-8 text preview (or image metadata) of a file inside `workspace`."""
    safe_max_chars = min(max(1024, int(max_chars)), 128000)
    target = _resolve_inside_workspace(workspace, rel_path)
    ws = workspace.resolve()
    if (
        target is None
        or not target.is_file()
        or is_sensitive_path(target)
        or not is_safe_outbound_file(target, image_only=False)
    ):
        return {"ok": False, "path": rel_path, "error": "文件不存在或属于受保护的隐私配置。"}

    rel_clean = str(target.relative_to(ws)).replace("\\", "/")
    ext = target.suffix.lower()
    is_img = ext in ALLOWED_IMAGE_EXTS
    size = target.stat().st_size
    if is_img:
        return {"ok": True, "path": rel_clean, "name": target.name, "size": size, "is_image": True, "content": ""}

    try:
        with target.open("rb") as fh:
            raw_bytes = fh.read(safe_max_chars * 3)
        if b"\x00" in raw_bytes[:2048]:
            return {
                "ok": True,
                "path": rel_clean,
                "name": target.name,
                "size": size,
                "is_image": False,
                "is_binary": True,
                "content": "",
            }
        txt = raw_bytes.decode("utf-8", errors="replace")
        truncated = len(txt) > safe_max_chars or size > len(raw_bytes)
        if len(txt) > safe_max_chars:
            txt = txt[:safe_max_chars]
        return {
            "ok": True,
            "path": rel_clean,
            "name": target.name,
            "size": size,
            "is_image": False,
            "is_binary": False,
            "truncated": truncated,
            "content": txt,
        }
    except OSError as exc:
        return {"ok": False, "path": rel_clean, "error": str(exc)}


_CACHED_CODEX_CLI: Path | None = None
_CODEX_CLI_CHECKED: bool = False


def find_codex_cli_executable() -> Path | None:
    """Locate official OpenAI `codex.exe` CLI (PATH or WindowsApps `OpenAI.Codex` bundle)."""
    global _CACHED_CODEX_CLI, _CODEX_CLI_CHECKED
    if _CODEX_CLI_CHECKED:
        return _CACHED_CODEX_CLI
    _CODEX_CLI_CHECKED = True

    direct = shutil.which("codex")
    if direct:
        p = Path(direct)
        if p.is_file():
            _CACHED_CODEX_CLI = p
            return p

    if sys.platform == "win32":
        try:
            res = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-WindowStyle",
                    "Hidden",
                    "-Command",
                    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
                    "$pkg = Get-AppxPackage -Name 'OpenAI.Codex' -ErrorAction SilentlyContinue | "
                    "Sort-Object Version -Descending | Select-Object -First 1; "
                    "if ($pkg) { Join-Path $pkg.InstallLocation 'app\\resources\\codex.exe' }",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                creationflags=CREATE_NO_WINDOW,
            )
            cand_raw = (res.stdout or "").strip().splitlines()
            if cand_raw:
                cand = Path(cand_raw[-1].strip())
                if cand.is_file():
                    _CACHED_CODEX_CLI = cand
                    return cand
        except Exception as exc:
            logger.debug("Codex CLI discovery skipped: %s", exc)

    return None


def _run_powershell_script(
    ps_script: str,
    *,
    env: dict[str, str] | None = None,
    timeout: float = 16.0,
    sta: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Execute a PowerShell script via UTF-8 Base64 stdin pipe (immune to Win32 32,767-char WinError 206 & GBK encoding)."""
    b64_payload = base64.b64encode(ps_script.encode("utf-8")).decode("ascii")
    bootstrap = (
        "$raw = [Console]::In.ReadToEnd().Trim(); "
        "if ($raw) { Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($raw))) }"
    )
    cmd = ["powershell.exe"]
    if sta:
        cmd.append("-Sta")
    cmd.extend(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", bootstrap])
    return subprocess.run(
        cmd,
        input=b64_payload,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
    )


def send_prompt_to_antigravity_ide_window(
    conversation_id: str,
    title: str,
    prompt: str,
) -> tuple[bool, str]:
    """Deliver a user prompt directly into the live PC Antigravity Desktop IDE window via Windows UIA.

    Switches to `conversation_id` in the left Sidebar if another chat is currently shown, verifies the
    active webview Document URL matches `/c/<conversation_id>`, pastes `prompt` via Clipboard (`Ctrl+V`,
    immune to Chinese Pinyin IME composition), and presses `Enter`.
    """
    if sys.platform != "win32":
        return (False, "仅支持 Windows 桌面窗口投递")

    cid = (conversation_id or "").strip()
    if not cid:
        return (False, "会话 ID 为空")

    ps_script = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class AgyWin32 {
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetClipboardSequenceNumber();
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, int dx, int dy, int dwData, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    public static void ClickAt(int x, int y) {
        SetCursorPos(x, y);
        System.Threading.Thread.Sleep(35);
        mouse_event(0x0002, 0, 0, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(25);
        mouse_event(0x0004, 0, 0, 0, UIntPtr.Zero);
    }

    public static void WheelDownAt(int x, int y) {
        SetCursorPos(x, y);
        System.Threading.Thread.Sleep(30);
        mouse_event(0x0800, 0, 0, -480, UIntPtr.Zero);
    }

    public static void PasteAndEnter() {
        keybd_event(0x11, 0, 0, UIntPtr.Zero);
        keybd_event(0x56, 0, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(25);
        keybd_event(0x56, 0, 0x0002, UIntPtr.Zero);
        keybd_event(0x11, 0, 0x0002, UIntPtr.Zero);
    }

    public static void PressEnter() {
        keybd_event(0x0D, 0, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(25);
        keybd_event(0x0D, 0, 0x0002, UIntPtr.Zero);
    }
}
"@

[AgyWin32]::SetProcessDPIAware() | Out-Null

$targetCid = $env:AGY_TARGET_CID
$targetTitle = $env:AGY_TARGET_TITLE
$promptBytes = [Convert]::FromBase64String($env:AGY_PROMPT_B64)
$promptText = [System.Text.Encoding]::UTF8.GetString($promptBytes)
$ideBrainDir = $env:AGY_IDE_BRAIN_DIR

function Get-ActiveCid($winEl) {
    $docCond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.ControlType]::Document
    )
    $docs = $winEl.FindAll([System.Windows.Automation.TreeScope]::Descendants, $docCond)
    foreach ($d in $docs) {
        try {
            $vp = $null
            if ($d.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$vp)) {
                $u = [string]$vp.Current.Value
                if ($u -match '/c/([A-Za-z0-9_-]{6,80})') {
                    return $Matches[1]
                }
            }
        } catch {}
    }
    return ""
}

function Find-ChatInputBox($winEl) {
    $wRect = $winEl.Current.BoundingRectangle
    $minTop = if (-not $wRect.IsEmpty) { $wRect.Top + 88 } else { 80 }
    $inputNameRe = 'Message input|Ask anything|输入任何问题|询问任何问题|有问题|发送消息|输入消息|向.*提问|Prompt|Chat input|继续对话'
    $excludeRe = 'Editor content|Monaco|编辑器|Search|搜索|查找|Filter|筛选|Command|命令面板|Terminal|终端|xterm'
    $composerBtnRe = '^(Send|发送|提交|Stop|停止|Attach|添加|上传|切换模型|Select model)\b|发送消息|Send message'

    $orTypes = New-Object System.Windows.Automation.OrCondition(
        (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::ComboBox)),
        (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit))
    )
    $allBoxes = $winEl.FindAll([System.Windows.Automation.TreeScope]::Descendants, $orTypes)
    $composerCandidates = @()
    $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker

    foreach ($bx in $allBoxes) {
        try {
            $r = $bx.Current.BoundingRectangle
            if ($r.IsEmpty -or $r.Width -lt 130 -or $r.Height -lt 16 -or $r.Top -lt $minTop) { continue }
            $nm = [string]$bx.Current.Name
            $cls = [string]$bx.Current.ClassName
            $aid = [string]$bx.Current.AutomationId
            if ("$nm $cls $aid" -match $excludeRe) { continue }
            if ($nm -match $inputNameRe) {
                return $bx
            }
            # Secondary positive check (never blind fallback!): compact height <= 220px AND parent container holds a chat composer button
            if ($bx.Current.IsKeyboardFocusable -and $r.Height -le 220 -and $r.Width -ge 175) {
                $parent = $walker.GetParent($bx)
                if ($null -ne $parent) {
                    $btnCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
                    $sibBtns = $parent.FindAll([System.Windows.Automation.TreeScope]::Descendants, $btnCond)
                    foreach ($sb in $sibBtns) {
                        if ([string]$sb.Current.Name -match $composerBtnRe) {
                            $composerCandidates += $bx
                            break
                        }
                    }
                }
            }
        } catch {}
    }
    if ($composerCandidates.Count -eq 1) { return $composerCandidates[0] }
    return $null
}

$root = [System.Windows.Automation.AutomationElement]::RootElement
$topChildren = $root.FindAll(
    [System.Windows.Automation.TreeScope]::Children,
    [System.Windows.Automation.Condition]::TrueCondition
)

$agyWin = $null
$bestScore = -1
foreach ($el in $topChildren) {
    try {
        $hwndVal = $el.Current.NativeWindowHandle
        if ($hwndVal -eq 0) { continue }
        $proc = Get-Process -Id $el.Current.ProcessId -ErrorAction SilentlyContinue
        if ($null -eq $proc -or $proc.ProcessName -ne 'Antigravity') { continue }
        $score = 10
        $wName = [string]$el.Current.Name
        if ($wName -match 'Antigravity') { $score += 20 }
        if ($targetTitle.Length -ge 3 -and $wName.IndexOf($targetTitle.Substring(0, [Math]::Min(10, $targetTitle.Length)), [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $score += 60
        }
        $curDocCid = Get-ActiveCid $el
        if ($curDocCid -eq $targetCid) {
            $agyWin = $el
            break
        }
        if ($score -gt $bestScore) {
            $bestScore = $score
            $agyWin = $el
        }
    } catch {}
}

if ($null -eq $agyWin) {
    Write-Output "ERR:未检测到打开的 Antigravity 桌面端窗口"
    exit 0
}

$hwnd = [IntPtr]$agyWin.Current.NativeWindowHandle
$winPid = $agyWin.Current.ProcessId
if ([AgyWin32]::IsIconic($hwnd)) {
    [AgyWin32]::ShowWindow($hwnd, 9) | Out-Null
    Start-Sleep -Milliseconds 220
}
try {
    $wshell = New-Object -ComObject WScript.Shell
    $wshell.AppActivate($winPid) | Out-Null
} catch {}
# Nudge Alt key state legally so Windows ForegroundLock permits bringing user's own IDE window to front
[AgyWin32]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero)
[AgyWin32]::keybd_event(0x12, 0, 0x0002, [UIntPtr]::Zero)
[AgyWin32]::BringWindowToTop($hwnd) | Out-Null
[AgyWin32]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 150

function Find-ConversationLink($scopeEl, $cidStr, $titleStr) {
    $linkCond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.ControlType]::Hyperlink
    )
    $links = $scopeEl.FindAll([System.Windows.Automation.TreeScope]::Descendants, $linkCond)
    $bestByTitle = $null
    foreach ($lnk in $links) {
        try {
            $vp = $null
            if ($lnk.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$vp)) {
                $href = [string]$vp.Current.Value
                if ($href -match ("/c/" + [regex]::Escape($cidStr) + "([/?#]|$)")) {
                    return $lnk
                }
            }
            if ($null -eq $bestByTitle -and $titleStr.Length -gt 0) {
                $rawName = [string]$lnk.Current.Name
                $cleanName = ($rawName -replace '\s+\d+\s*(秒|分钟|小时|天|周|个月|年).*$', '').Trim()
                if ($cleanName -eq $titleStr) {
                    $bestByTitle = $lnk
                } elseif ($cleanName.Length -ge 4) {
                    $stem = ($cleanName -replace '(\.\.\.|…)+$', '').Trim()
                    if ($stem.Length -ge 4 -and $titleStr.StartsWith($stem, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $bestByTitle = $lnk
                    } elseif ($cleanName.StartsWith($titleStr, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $bestByTitle = $lnk
                    }
                }
            }
        } catch {}
    }
    return $bestByTitle
}

function Activate-Element($el) {
    $rect = $el.Current.BoundingRectangle
    if (-not $rect.IsEmpty -and $rect.Width -gt 4 -and $rect.Height -gt 4) {
        $x = [int]($rect.Left + [Math]::Min(90, $rect.Width / 2))
        $y = [int]($rect.Top + ($rect.Height / 2))
        [AgyWin32]::ClickAt($x, $y)
        return $true
    }
    $inv = $null
    if ($el.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$inv)) {
        $inv.Invoke()
        return $true
    }
    return $false
}

$activeCid = Get-ActiveCid $agyWin
if ($activeCid -ne $targetCid) {
    $navCond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.ControlType]::Custom
    )
    $sidebar = $null
    $allDesc = $agyWin.FindAll(
        [System.Windows.Automation.TreeScope]::Descendants,
        (New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::NameProperty,
            "Sidebar"
        ))
    )
    if ($allDesc.Count -gt 0) {
        $sidebar = $allDesc.Item(0)
    } else {
        $toggleBtns = $agyWin.FindAll(
            [System.Windows.Automation.TreeScope]::Descendants,
            (New-Object System.Windows.Automation.PropertyCondition(
                [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
                [System.Windows.Automation.ControlType]::Button
            ))
        )
        foreach ($b in $toggleBtns) {
            if ($b.Current.Name -match '切换侧边栏|Toggle Sidebar') {
                Activate-Element $b | Out-Null
                Start-Sleep -Milliseconds 280
                break
            }
        }
        $allDesc2 = $agyWin.FindAll(
            [System.Windows.Automation.TreeScope]::Descendants,
            (New-Object System.Windows.Automation.PropertyCondition(
                [System.Windows.Automation.AutomationElement]::NameProperty,
                "Sidebar"
            ))
        )
        if ($allDesc2.Count -gt 0) { $sidebar = $allDesc2.Item(0) }
    }

    $searchScope = if ($null -ne $sidebar) { $sidebar } else { $agyWin }
    $targetLink = Find-ConversationLink $searchScope $targetCid $targetTitle

    if ($null -eq $targetLink -and $null -ne $sidebar) {
        $sRect = $sidebar.Current.BoundingRectangle
        if (-not $sRect.IsEmpty -and $sRect.Width -gt 20 -and $sRect.Height -gt 60) {
            $sx = [int]($sRect.Left + ($sRect.Width / 2))
            $sy = [int]($sRect.Top + ($sRect.Height * 0.65))
            for ($sc = 0; $sc -lt 4; $sc++) {
                [AgyWin32]::WheelDownAt($sx, $sy)
                Start-Sleep -Milliseconds 220
                $targetLink = Find-ConversationLink $sidebar $targetCid $targetTitle
                if ($null -ne $targetLink) { break }
            }
        }
    }

    $clickedLink = $false
    if ($null -ne $targetLink) {
        $clickedLink = Activate-Element $targetLink
        for ($w = 0; $w -lt 14; $w++) {
            Start-Sleep -Milliseconds 180
            $activeCid = Get-ActiveCid $agyWin
            if ($activeCid -eq $targetCid) { break }
        }
    }

    $activeCid = Get-ActiveCid $agyWin
    $winTitleNow = [string]$agyWin.Current.Name
    $titleAligned = ($targetTitle.Length -ge 3 -and $winTitleNow.IndexOf($targetTitle.Substring(0, [Math]::Min(8, $targetTitle.Length)), [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
    if ($activeCid -ne $targetCid -and -not ($activeCid -eq "" -and ($clickedLink -or $titleAligned))) {
        Write-Output "ERR:桌面端当前未能确认切换到该会话窗口"
        exit 0
    }
}

$msgBox = Find-ChatInputBox $agyWin
if ($null -eq $msgBox) {
    Write-Output "ERR:未找到桌面端对话输入框"
    exit 0
}

$boxRect = $msgBox.Current.BoundingRectangle
if ($boxRect.IsEmpty -or $boxRect.Width -lt 30 -or $boxRect.Height -lt 10) {
    Write-Output "ERR:桌面端对话输入框当前不可见"
    exit 0
}

$clipKind = "empty"
$oldClipText = ""
$oldClipImg = $null
$oldClipFiles = $null
try {
    if ([System.Windows.Forms.Clipboard]::ContainsText()) {
        $clipKind = "text"
        $oldClipText = [System.Windows.Forms.Clipboard]::GetText()
    } elseif ([System.Windows.Forms.Clipboard]::ContainsImage()) {
        $clipKind = "image"
        $oldClipImg = [System.Windows.Forms.Clipboard]::GetImage()
    } elseif ([System.Windows.Forms.Clipboard]::ContainsFileDropList()) {
        $clipKind = "files"
        $oldClipFiles = [System.Windows.Forms.Clipboard]::GetFileDropList()
    }
} catch {}

[AgyWin32]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 40
if ([AgyWin32]::GetForegroundWindow() -ne $hwnd) {
    Write-Output "ERR:桌面窗口未处于前台焦点（可能电脑已锁屏），已安全中止投递"
    exit 0
}

$cx = [int]($boxRect.Left + [Math]::Min(120, $boxRect.Width / 2))
$cy = [int]($boxRect.Top + ($boxRect.Height / 2))
[AgyWin32]::ClickAt($cx, $cy)
Start-Sleep -Milliseconds 140

[System.Windows.Forms.Clipboard]::SetText($promptText)
$clipSeqAfterSet = [AgyWin32]::GetClipboardSequenceNumber()
Start-Sleep -Milliseconds 50

try {
    $recheckCid = Get-ActiveCid $agyWin
    if ([AgyWin32]::GetForegroundWindow() -ne $hwnd -or ($recheckCid -ne "" -and $recheckCid -ne $targetCid)) {
        Write-Output "ERR:桌面窗口焦点或目标会话发生变化，已安全中止投递"
        exit 0
    }
    [AgyWin32]::PasteAndEnter()
    Start-Sleep -Milliseconds 230
    if ([AgyWin32]::GetForegroundWindow() -ne $hwnd) {
        Write-Output "ERR:粘贴后桌面窗口失去焦点，已中止回车提交（草稿保留在输入框）"
        exit 0
    }
    [AgyWin32]::PressEnter()
    Start-Sleep -Milliseconds 180
} finally {
    try {
        if ([AgyWin32]::GetClipboardSequenceNumber() -eq $clipSeqAfterSet) {
            if ($clipKind -eq "text") { [System.Windows.Forms.Clipboard]::SetText($oldClipText) }
            elseif ($clipKind -eq "image" -and $null -ne $oldClipImg) { [System.Windows.Forms.Clipboard]::SetImage($oldClipImg) }
            elseif ($clipKind -eq "files" -and $null -ne $oldClipFiles) { [System.Windows.Forms.Clipboard]::SetFileDropList($oldClipFiles) }
            else { [System.Windows.Forms.Clipboard]::Clear() }
        }
    } catch {}
}

Write-Output "OK:已投递至电脑端 Antigravity 窗口"
"""

    env = os.environ.copy()
    env["AGY_TARGET_CID"] = cid
    env["AGY_TARGET_TITLE"] = (title or "").strip()
    env["AGY_PROMPT_B64"] = base64.b64encode((prompt or "").encode("utf-8")).decode("ascii")

    with _DESKTOP_UIA_LOCK:
        try:
            res = _run_powershell_script(ps_script, env=env, timeout=16, sta=True)
            lines = [ln.strip() for ln in (res.stdout or "").splitlines() if ln.strip()]
            for ln in reversed(lines):
                if ln.startswith("OK:"):
                    return (True, ln.removeprefix("OK:").strip())
                if ln.startswith("ERR:"):
                    return (False, ln.removeprefix("ERR:").strip())
            err_tail = (res.stderr or "").strip()[:160]
            return (False, f"桌面窗口投递未返回确认 {err_tail}".strip())
        except Exception as exc:
            return (False, f"桌面窗口投递异常：{exc}")


def cancel_antigravity_ide_window_turn(conversation_id: str) -> bool:
    """Click the Stop/Cancel button in the open PC Antigravity IDE window if matching `conversation_id`."""
    if sys.platform != "win32" or not (conversation_id or "").strip():
        return False

    ps_script = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class AgyStopWin32 {
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, int dx, int dy, int dwData, UIntPtr dwExtraInfo);
    public static void ClickAt(int x, int y) {
        SetCursorPos(x, y);
        System.Threading.Thread.Sleep(30);
        mouse_event(0x0002, 0, 0, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(25);
        mouse_event(0x0004, 0, 0, 0, UIntPtr.Zero);
    }
}
"@
[AgyStopWin32]::SetProcessDPIAware() | Out-Null
$cid = $env:AGY_TARGET_CID
$root = [System.Windows.Automation.AutomationElement]::RootElement
foreach ($el in $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)) {
    try {
        if ($el.Current.NativeWindowHandle -eq 0) { continue }
        $p = Get-Process -Id $el.Current.ProcessId -ErrorAction SilentlyContinue
        if ($null -eq $p -or $p.ProcessName -ne 'Antigravity') { continue }
        $docs = $el.FindAll([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Document)))
        $matched = $false
        foreach ($d in $docs) {
            try {
                $vp = $d.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
                if ([string]$vp.Current.Value -match ("/c/" + [regex]::Escape($cid))) { $matched = $true; break }
            } catch {}
        }
        if (-not $matched) { continue }
        $btns = $el.FindAll([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)))
        foreach ($b in $btns) {
            if ($b.Current.Name -match '取消|停止|Stop|Cancel') {
                $r = $b.Current.BoundingRectangle
                if (-not $r.IsEmpty -and $r.Width -gt 6) {
                    [AgyStopWin32]::SetForegroundWindow([IntPtr]$el.Current.NativeWindowHandle) | Out-Null
                    [AgyStopWin32]::ClickAt([int]($r.Left + $r.Width / 2), [int]($r.Top + $r.Height / 2))
                    Write-Output "STOPPED"
                    exit 0
                }
            }
        }
    } catch {}
}
"""
    encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    env = os.environ.copy()
    env["AGY_TARGET_CID"] = conversation_id.strip()
    with _DESKTOP_UIA_LOCK:
        try:
            res = subprocess.run(
                ["powershell.exe", "-Sta", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=8,
                creationflags=CREATE_NO_WINDOW,
            )
            return "STOPPED" in (res.stdout or "")
        except Exception:
            return False


def open_new_antigravity_ide_chat_window() -> tuple[bool, str]:
    """Click `+ 新建会话` (`New Conversation`) in the open PC Antigravity Desktop window."""
    if sys.platform != "win32":
        return (False, "仅支持 Windows 桌面窗口操作")

    ps_script = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class AgyNewWin32 {
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetClipboardSequenceNumber();
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, int dx, int dy, int dwData, UIntPtr dwExtraInfo);
    public static void ClickAt(int x, int y) {
        SetCursorPos(x, y);
        System.Threading.Thread.Sleep(35);
        mouse_event(0x0002, 0, 0, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(25);
        mouse_event(0x0004, 0, 0, 0, UIntPtr.Zero);
    }
}
"@
[AgyNewWin32]::SetProcessDPIAware() | Out-Null

$root = [System.Windows.Automation.AutomationElement]::RootElement
$agyWin = $null
foreach ($el in $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)) {
    try {
        if ($el.Current.NativeWindowHandle -eq 0) { continue }
        $p = Get-Process -Id $el.Current.ProcessId -ErrorAction SilentlyContinue
        if ($null -eq $p -or $p.ProcessName -ne 'Antigravity') { continue }
        $agyWin = $el
        if ($el.Current.Name -match 'Antigravity') { break }
    } catch {}
}
if ($null -eq $agyWin) {
    Write-Output "ERR:未检测到打开的 Antigravity 桌面窗口"
    exit 0
}

$hwnd = [IntPtr]$agyWin.Current.NativeWindowHandle
if ([AgyNewWin32]::IsIconic($hwnd)) {
    [AgyNewWin32]::ShowWindow($hwnd, 9) | Out-Null
    Start-Sleep -Milliseconds 220
}
try { (New-Object -ComObject WScript.Shell).AppActivate($agyWin.Current.ProcessId) | Out-Null } catch {}
[AgyNewWin32]::BringWindowToTop($hwnd) | Out-Null
[AgyNewWin32]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 120

function Activate-El($el) {
    $r = $el.Current.BoundingRectangle
    if (-not $r.IsEmpty -and $r.Width -gt 4 -and $r.Height -gt 4) {
        [AgyNewWin32]::ClickAt([int]($r.Left + [Math]::Min(80, $r.Width / 2)), [int]($r.Top + $r.Height / 2))
        return $true
    }
    $inv = $null
    if ($el.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$inv)) {
        $inv.Invoke()
        return $true
    }
    return $false
}

$sidebarDesc = $agyWin.FindAll([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "Sidebar")))
if ($sidebarDesc.Count -eq 0) {
    $btns = $agyWin.FindAll([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)))
    foreach ($b in $btns) {
        if ($b.Current.Name -match '切换侧边栏|Toggle Sidebar') {
            Activate-El $b | Out-Null
            Start-Sleep -Milliseconds 260
            break
        }
    }
}

$orCond = New-Object System.Windows.Automation.OrCondition(
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)),
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Hyperlink))
)
$candidates = $agyWin.FindAll([System.Windows.Automation.TreeScope]::Descendants, $orCond)
$newBtn = $null
foreach ($c in $candidates) {
    $nm = [string]$c.Current.Name
    if ($nm -match '新建会话|新建对话|New Conversation|New Chat') {
        $newBtn = $c
        break
    }
}

if ($null -eq $newBtn) {
    Write-Output "ERR:未在桌面窗口中找到「新建会话」按钮"
    exit 0
}

Activate-El $newBtn | Out-Null
Start-Sleep -Milliseconds 260
Write-Output "OK:已在电脑端打开新对话窗口"
"""
    encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    with _DESKTOP_UIA_LOCK:
        try:
            res = subprocess.run(
                ["powershell.exe", "-Sta", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                creationflags=CREATE_NO_WINDOW,
            )
            for ln in reversed([x.strip() for x in (res.stdout or "").splitlines() if x.strip()]):
                if ln.startswith("OK:"):
                    return (True, ln.removeprefix("OK:").strip())
                if ln.startswith("ERR:"):
                    return (False, ln.removeprefix("ERR:").strip())
            return (False, "打开电脑端新对话未返回确认")
        except Exception as exc:
            return (False, f"打开电脑端新对话异常：{exc}")


def create_and_send_antigravity_ide_new_chat(
    prompt: str,
    ide_store_dir: Path | None = None,
) -> tuple[bool, str, str]:
    """Create a brand-new conversation in the open PC Antigravity window, submit `prompt`, and return `(ok, new_cid, note)`."""
    if sys.platform != "win32":
        return (False, "", "仅支持 Windows 桌面窗口投递")

    ide_root = ide_store_dir if ide_store_dir is not None else (Path.home() / ".gemini" / "antigravity")
    brain_dir = ide_root / "brain"
    before_ids: set[str] = set()
    if brain_dir.is_dir():
        try:
            before_ids = {d.name for d in brain_dir.iterdir() if d.is_dir()}
        except OSError:
            pass

    ps_script = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class AgyCreateWin32 {
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetClipboardSequenceNumber();
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, int dx, int dy, int dwData, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    public static void ClickAt(int x, int y) {
        SetCursorPos(x, y);
        System.Threading.Thread.Sleep(35);
        mouse_event(0x0002, 0, 0, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(25);
        mouse_event(0x0004, 0, 0, 0, UIntPtr.Zero);
    }
    public static void PasteClip() {
        keybd_event(0x11, 0, 0, UIntPtr.Zero);
        keybd_event(0x56, 0, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(25);
        keybd_event(0x56, 0, 0x0002, UIntPtr.Zero);
        keybd_event(0x11, 0, 0x0002, UIntPtr.Zero);
    }
    public static void PressEnter() {
        keybd_event(0x0D, 0, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(25);
        keybd_event(0x0D, 0, 0x0002, UIntPtr.Zero);
    }
}
"@
[AgyCreateWin32]::SetProcessDPIAware() | Out-Null

$promptBytes = [Convert]::FromBase64String($env:AGY_PROMPT_B64)
$promptText = [System.Text.Encoding]::UTF8.GetString($promptBytes)
$ideBrainDir = $env:AGY_IDE_BRAIN_DIR

$root = [System.Windows.Automation.AutomationElement]::RootElement
$agyWin = $null
foreach ($el in $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)) {
    try {
        if ($el.Current.NativeWindowHandle -eq 0) { continue }
        $p = Get-Process -Id $el.Current.ProcessId -ErrorAction SilentlyContinue
        if ($null -eq $p -or $p.ProcessName -ne 'Antigravity') { continue }
        $agyWin = $el
        if ($el.Current.Name -match 'Antigravity') { break }
    } catch {}
}
if ($null -eq $agyWin) {
    Write-Output "ERR:未检测到打开的 Antigravity 桌面端窗口"
    exit 0
}

$hwnd = [IntPtr]$agyWin.Current.NativeWindowHandle
if ([AgyCreateWin32]::IsIconic($hwnd)) {
    [AgyCreateWin32]::ShowWindow($hwnd, 9) | Out-Null
    Start-Sleep -Milliseconds 220
}
try { (New-Object -ComObject WScript.Shell).AppActivate($agyWin.Current.ProcessId) | Out-Null } catch {}
[AgyCreateWin32]::BringWindowToTop($hwnd) | Out-Null
[AgyCreateWin32]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 140

function Get-ActiveCid($winEl) {
    $docCond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.ControlType]::Document
    )
    foreach ($d in $winEl.FindAll([System.Windows.Automation.TreeScope]::Descendants, $docCond)) {
        try {
            $vp = $d.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
            if ($null -ne $vp) {
                $u = [string]$vp.Current.Value
                if ($u -match '/c/([A-Za-z0-9_-]{6,80})') {
                    return $Matches[1]
                }
            }
        } catch {}
    }
    return ""
}

function Activate-El($el) {
    $r = $el.Current.BoundingRectangle
    if (-not $r.IsEmpty -and $r.Width -gt 4 -and $r.Height -gt 4) {
        [AgyCreateWin32]::ClickAt([int]($r.Left + [Math]::Min(80, $r.Width / 2)), [int]($r.Top + $r.Height / 2))
        return $true
    }
    $inv = $null
    if ($el.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$inv)) {
        $inv.Invoke()
        return $true
    }
    return $false
}

$prevCid = Get-ActiveCid $agyWin
$prevHasHistory = $false
if ($prevCid -ne "" -and $ideBrainDir -ne "") {
    $prevTf = Join-Path $ideBrainDir "$prevCid\.system_generated\logs\transcript.jsonl"
    if (Test-Path -LiteralPath $prevTf) {
        try {
            if ((Get-Item -LiteralPath $prevTf).Length -gt 0) { $prevHasHistory = $true }
        } catch { $prevHasHistory = $true }
    }
}

if ($prevHasHistory) {
    $sidebarDesc = $agyWin.FindAll([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "Sidebar")))
    if ($sidebarDesc.Count -eq 0) {
        $btns = $agyWin.FindAll([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)))
        foreach ($b in $btns) {
            if ($b.Current.Name -match '切换侧边栏|Toggle Sidebar') {
                Activate-El $b | Out-Null
                Start-Sleep -Milliseconds 260
                break
            }
        }
    }
    $orCond = New-Object System.Windows.Automation.OrCondition(
        (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)),
        (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Hyperlink))
    )
    $newBtn = $null
    foreach ($c in $agyWin.FindAll([System.Windows.Automation.TreeScope]::Descendants, $orCond)) {
        if ([string]$c.Current.Name -match '新建会话|新建对话|New Conversation|New Chat') {
            $newBtn = $c
            break
        }
    }
    if ($null -eq $newBtn) {
        Write-Output "ERR:未找到桌面窗口「新建会话」按钮"
        exit 0
    }
    Activate-El $newBtn | Out-Null
    for ($i = 0; $i -lt 12; $i++) {
        Start-Sleep -Milliseconds 160
        $curCid = Get-ActiveCid $agyWin
        if ($curCid -ne $prevCid) { break }
    }
    $afterClickCid = Get-ActiveCid $agyWin
    if ($afterClickCid -ne "" -and $afterClickCid -eq $prevCid) {
        Write-Output "ERR:桌面窗口未能切换到新建会话页"
        exit 0
    }
}

$msgBox = $null
$wRect2 = $agyWin.Current.BoundingRectangle
$minTop2 = if (-not $wRect2.IsEmpty) { $wRect2.Top + 88 } else { 80 }
$inRe2 = 'Message input|Ask anything|输入任何问题|询问任何问题|有问题|发送消息|输入消息|向.*提问|Prompt|Chat input|继续对话'
$exRe2 = 'Editor content|Monaco|编辑器|Search|搜索|查找|Filter|筛选|Command|命令面板|Terminal|终端|xterm'
$orCondBox = New-Object System.Windows.Automation.OrCondition(
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::ComboBox)),
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit))
)
foreach ($bx2 in $agyWin.FindAll([System.Windows.Automation.TreeScope]::Descendants, $orCondBox)) {
    try {
        $r2 = $bx2.Current.BoundingRectangle
        if ($r2.IsEmpty -or $r2.Width -lt 130 -or $r2.Height -lt 16 -or $r2.Top -lt $minTop2) { continue }
        $nm2 = [string]$bx2.Current.Name
        $cls2 = [string]$bx2.Current.ClassName
        if ("$nm2 $cls2" -match $exRe2) { continue }
        if ($nm2 -match $inRe2) { $msgBox = $bx2; break }
    } catch {}
}
if ($null -eq $msgBox) {
    Write-Output "ERR:未找到新建会话输入框"
    exit 0
}
$boxRect = $msgBox.Current.BoundingRectangle
if ($boxRect.IsEmpty -or $boxRect.Width -lt 30 -or $boxRect.Height -lt 10) {
    Write-Output "ERR:新建会话输入框不可见"
    exit 0
}

$clipKind = "empty"
$oldClipText = ""
$oldClipImg = $null
$oldClipFiles = $null
try {
    if ([System.Windows.Forms.Clipboard]::ContainsText()) {
        $clipKind = "text"
        $oldClipText = [System.Windows.Forms.Clipboard]::GetText()
    } elseif ([System.Windows.Forms.Clipboard]::ContainsImage()) {
        $clipKind = "image"
        $oldClipImg = [System.Windows.Forms.Clipboard]::GetImage()
    } elseif ([System.Windows.Forms.Clipboard]::ContainsFileDropList()) {
        $clipKind = "files"
        $oldClipFiles = [System.Windows.Forms.Clipboard]::GetFileDropList()
    }
} catch {}

[AgyCreateWin32]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 40
if ([AgyCreateWin32]::GetForegroundWindow() -ne $hwnd) {
    Write-Output "ERR:桌面窗口未处于前台焦点，已安全中止新建投递"
    exit 0
}

[AgyCreateWin32]::ClickAt([int]($boxRect.Left + [Math]::Min(120, $boxRect.Width / 2)), [int]($boxRect.Top + $boxRect.Height / 2))
Start-Sleep -Milliseconds 140

[System.Windows.Forms.Clipboard]::SetText($promptText)
$clipSeqAfterSet = [AgyCreateWin32]::GetClipboardSequenceNumber()
Start-Sleep -Milliseconds 50

$newCid = ""
try {
    if ([AgyCreateWin32]::GetForegroundWindow() -ne $hwnd) {
        Write-Output "ERR:桌面窗口失去焦点，已安全中止新建投递"
        exit 0
    }
    [AgyCreateWin32]::PasteClip()
    Start-Sleep -Milliseconds 230
    if ([AgyCreateWin32]::GetForegroundWindow() -ne $hwnd) {
        Write-Output "ERR:粘贴后桌面窗口失去焦点，已中止回车提交（草稿保留在输入框）"
        exit 0
    }
    [AgyCreateWin32]::PressEnter()

    for ($w = 0; $w -lt 22; $w++) {
        Start-Sleep -Milliseconds 180
        $cand = Get-ActiveCid $agyWin
        if ($cand -ne "" -and ((-not $prevHasHistory) -or ($cand -ne $prevCid))) {
            $newCid = $cand
            break
        }
    }
} finally {
    try {
        if ([AgyCreateWin32]::GetClipboardSequenceNumber() -eq $clipSeqAfterSet) {
            if ($clipKind -eq "text") { [System.Windows.Forms.Clipboard]::SetText($oldClipText) }
            elseif ($clipKind -eq "image" -and $null -ne $oldClipImg) { [System.Windows.Forms.Clipboard]::SetImage($oldClipImg) }
            elseif ($clipKind -eq "files" -and $null -ne $oldClipFiles) { [System.Windows.Forms.Clipboard]::SetFileDropList($oldClipFiles) }
            else { [System.Windows.Forms.Clipboard]::Clear() }
        }
    } catch {}
}

Write-Output "OK:$newCid"
"""
    env = os.environ.copy()
    env["AGY_PROMPT_B64"] = base64.b64encode((prompt or "").encode("utf-8")).decode("ascii")
    env["AGY_IDE_BRAIN_DIR"] = str(brain_dir)

    with _DESKTOP_UIA_LOCK:
        try:
            res = _run_powershell_script(ps_script, env=env, timeout=18, sta=True)
            ok_matched = False
            new_cid = ""
            for ln in reversed([x.strip() for x in (res.stdout or "").splitlines() if x.strip()]):
                if ln.startswith("OK:"):
                    ok_matched = True
                    new_cid = ln.removeprefix("OK:").strip()
                    break
                if ln.startswith("ERR:"):
                    return (False, "", ln.removeprefix("ERR:").strip())

            if not ok_matched:
                return (False, "", "新建桌面会话未返回确认")

            # Fallback: only accept an unambiguous single newly created brain/<uuid> directory
            if not new_cid and brain_dir.is_dir():
                for _ in range(10):
                    time.sleep(0.45)
                    try:
                        candidates = [
                            d
                            for d in brain_dir.iterdir()
                            if d.is_dir() and d.name != "tempmediaStorage" and d.name not in before_ids
                        ]
                        if len(candidates) == 1:
                            new_cid = candidates[0].name
                            break
                        if len(candidates) > 1:
                            break
                    except OSError:
                        pass

            if not new_cid:
                return (False, "", "未能唯一定位新建桌面会话 ID，请点击同步刷新")

            return (True, new_cid, "已在电脑端新建 Antigravity 会话并发送")
        except Exception as exc:
            return (False, "", f"新建桌面会话异常：{exc}")


def inspect_antigravity_ide_actions(conversation_id: str = "") -> list[dict[str, Any]]:
    """Read-only scan of open Antigravity IDE windows for pending confirmation buttons + bounded card context.

    Does NOT issue any auto-click token (enforces Branch B safety).
    Marks detections as `verified: False` when conversation ID or confirmation context cannot be confirmed.
    """
    if sys.platform != "win32":
        return []

    ps_script = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$reqCid = $env:AGY_REQ_CID
$exactAllow = @(
    'proceed', 'accept', 'accept all', 'allow', 'allow once', 'approve',
    'run', 'run command', 'continue', 'retry', 'confirm',
    '继续', '接受', '全部接受', '允许', '仅允许一次', '同意', '运行', '执行', '重试', '确认'
)

$walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
$root = [System.Windows.Automation.AutomationElement]::RootElement
$found = @()
foreach ($el in $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)) {
    try {
        $hwnd = [long]$el.Current.NativeWindowHandle
        if ($hwnd -eq 0) { continue }
        $p = Get-Process -Id $el.Current.ProcessId -ErrorAction SilentlyContinue
        if ($null -eq $p -or $p.ProcessName -ne 'Antigravity') { continue }

        $activeCid = ""
        $docCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Document)
        foreach ($d in $el.FindAll([System.Windows.Automation.TreeScope]::Descendants, $docCond)) {
            try {
                $vp = $d.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
                if ($null -ne $vp -and ([string]$vp.Current.Value -match '/c/([A-Za-z0-9_-]{6,80})')) {
                    $activeCid = $Matches[1]
                    break
                }
            } catch {}
        }
        if ($reqCid -ne "" -and $activeCid -ne "" -and $activeCid -ne $reqCid) { continue }

        $btnCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
        foreach ($b in $el.FindAll([System.Windows.Automation.TreeScope]::Descendants, $btnCond)) {
            try {
                if (-not $b.Current.IsEnabled -or $b.Current.IsOffscreen) { continue }
                $invCheck = $null
                if (-not $b.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$invCheck)) { continue }
                $nm = ([string]$b.Current.Name).Trim()
                if ($exactAllow -notcontains $nm.ToLowerInvariant()) { continue }
                $r = $b.Current.BoundingRectangle
                if ($r.IsEmpty -or $r.Width -lt 18 -or $r.Height -lt 14) { continue }

                # Collect bounded context text from ancestor card container (up to 6 levels, 400 chars)
                $ctxParts = New-Object System.Collections.Generic.List[string]
                $container = $b
                for ($depth = 0; $depth -lt 5; $depth++) {
                    $par = $walker.GetParent($container)
                    if ($null -eq $par -or [long]$par.Current.NativeWindowHandle -eq $hwnd) { break }
                    $container = $par
                    $pr = $container.Current.BoundingRectangle
                    if (-not $pr.IsEmpty -and $pr.Height -ge 72 -and $pr.Width -ge 180) { break }
                }
                if ($null -ne $container) {
                    $txtCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
                    foreach ($tNode in $container.FindAll([System.Windows.Automation.TreeScope]::Descendants, $txtCond)) {
                        $tStr = ([string]$tNode.Current.Name).Trim()
                        if ($tStr -and $tStr -ne $nm -and $ctxParts.Count -lt 12) {
                            $ctxParts.Add($tStr)
                        }
                    }
                }
                $rawCtx = ($ctxParts -join ' · ')
                $isTrunc = $false
                if ($rawCtx.Length -gt 400) {
                    $rawCtx = $rawCtx.Substring(0, 400)
                    $isTrunc = $true
                }

                $found += [PSCustomObject]@{
                    hwnd = $hwnd
                    cid  = $activeCid
                    label = $nm
                    context_summary = $rawCtx
                    truncated = $isTrunc
                }
                if ($found.Count -ge 6) { break }
            } catch {}
        }
    } catch {}
}
ConvertTo-Json -InputObject @($found) -Compress
"""
    req_cid = (conversation_id or "").strip()
    env = os.environ.copy()
    env["AGY_REQ_CID"] = req_cid

    try:
        res = _run_powershell_script(ps_script, env=env, timeout=6, sta=True)
        raw = (res.stdout or "").strip()
        if not raw or raw == "null":
            return []
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            parsed = [parsed]
        if not isinstance(parsed, list):
            return []

        out: list[dict[str, Any]] = []
        for item in parsed[:6]:
            if not isinstance(item, dict):
                continue
            hwnd = int(item.get("hwnd") or 0)
            label = str(item.get("label") or "").strip()
            cid = str(item.get("cid") or "").strip()
            ctx = str(item.get("context_summary") or "").strip()
            trunc = bool(item.get("truncated"))
            if not hwnd or not label:
                continue

            # Strict fail-closed verification flags
            verified = True
            reason = ""
            if not cid or (req_cid and cid != req_cid):
                verified = False
                reason = "unverified_window"
            elif not ctx:
                verified = False
                reason = "missing_context"
            elif trunc:
                verified = False
                reason = "context_truncated"

            out.append(
                {
                    "hwnd": hwnd,
                    "conversation_id": cid,
                    "label": label,
                    "context_summary": ctx,
                    "truncated": trunc,
                    "verified": verified,
                    "reason": reason,
                    "mode": "manual_screen_only",
                }
            )
        return out
    except Exception as exc:
        logger.debug("inspect_antigravity_ide_actions failed: %s", exc)
        return []


def invoke_antigravity_ide_action(action_token: str) -> tuple[bool, str]:
    """Branch B safety policy: Stayy disables blind token-based button invocation."""
    _ = action_token
    return (
        False,
        "为防连续同文审批弹窗替身误触，Stayy 已禁用盲点自动放行，请使用 3.2× 放大镜看屏手动点击。",
    )


ALLOWED_REMOTE_KEYS: dict[str, int] = {
    "enter": 0x0D,
    "esc": 0x1B,
    "space": 0x20,
    "tab": 0x09,
    "backspace": 0x08,
    "delete": 0x2E,
    "up": 0x26,
    "down": 0x28,
    "left": 0x25,
    "right": 0x27,
    "home": 0x24,
    "end": 0x23,
    "pgup": 0x21,
    "pgdn": 0x22,
}

ALLOWED_REMOTE_HOTKEYS: dict[str, tuple[list[int], int]] = {
    "ctrl+c": ([0x11], 0x43),
    "ctrl+v": ([0x11], 0x56),
    "ctrl+x": ([0x11], 0x58),
    "ctrl+z": ([0x11], 0x5A),
    "ctrl+y": ([0x11], 0x59),
    "ctrl+a": ([0x11], 0x41),
    "ctrl+s": ([0x11], 0x53),
    "ctrl+w": ([0x11], 0x57),
    "ctrl+r": ([0x11], 0x52),
    "alt+tab": ([0x12], 0x09),
    "win+d": ([0x5B], 0x44),
}


def _send_unicode_text_win32(text: str, press_enter: bool = False) -> int:
    """Inject single-line Unicode UTF-16LE code units in atomic chunks via Win32 `SendInput(KEYEVENTF_UNICODE)`.

    Embedded CR/LF characters are converted to spaces so `press_enter=False` can NEVER accidentally execute
    commands or submit chat forms; `VK_RETURN` is sent strictly at the end only when `press_enter=True`.
    Returns the number of characters successfully delivered.
    """
    import ctypes
    from ctypes import wintypes

    ULONG_PTR = ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [
            ("wVk", wintypes.WORD),
            ("wScan", wintypes.WORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ULONG_PTR),
        ]

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [
            ("dx", wintypes.LONG),
            ("dy", wintypes.LONG),
            ("mouseData", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ULONG_PTR),
        ]

    class _INPUT_UNION(ctypes.Union):
        _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT)]

    class INPUT(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("u", _INPUT_UNION)]

    safe_single_line = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    send_input_fn = ctypes.windll.user32.SendInput
    send_input_fn.argtypes = [wintypes.UINT, ctypes.c_void_p, ctypes.c_int]
    send_input_fn.restype = wintypes.UINT

    delivered_chars = 0
    chunk_size = 64
    for start_idx in range(0, len(safe_single_line), chunk_size):
        sub = safe_single_line[start_idx : start_idx + chunk_size]
        batch: list[INPUT] = []
        for ch in sub:
            utf16_bytes = ch.encode("utf-16-le")
            for offset in range(0, len(utf16_bytes), 2):
                unit = int.from_bytes(utf16_bytes[offset : offset + 2], "little")
                for flg in (0x0004, 0x0004 | 0x0002):
                    inp = INPUT(type=1)
                    inp.u.ki = KEYBDINPUT(0, unit, flg, 0, 0)
                    batch.append(inp)
        if not batch:
            continue
        arr = (INPUT * len(batch))(*batch)
        sent = int(send_input_fn(len(batch), ctypes.byref(arr), ctypes.sizeof(INPUT)))
        if sent != len(batch):
            if delivered_chars == 0 and sent == 0:
                raise RuntimeError("Win32 SendInput 被系统安全策略拦截（如当前前台为管理员权限窗口）")
            raise RuntimeError(f"输入仅部分送达（已完成约 {delivered_chars} 字，后续被目标窗口中断，未重复重发）")
        delivered_chars += len(sub)

    if press_enter:
        ent_batch: list[INPUT] = []
        for flg in (0, 0x0002):
            inp = INPUT(type=1)
            inp.u.ki = KEYBDINPUT(0x0D, 0, flg, 0, 0)
            ent_batch.append(inp)
        ent_arr = (INPUT * 2)(*ent_batch)
        sent_ent = int(send_input_fn(2, ctypes.byref(ent_arr), ctypes.sizeof(INPUT)))
        if sent_ent != 2:
            raise RuntimeError(f"已输入 {delivered_chars} 字，但末尾回车键未能完整送达")

    return delivered_chars


def perform_desktop_remote_input(
    action: str,
    x_ratio: float = 0.5,
    y_ratio: float = 0.5,
    key_name: str = "",
    text: str = "",
) -> tuple[bool, str]:
    """Perform sub-2ms DPI-accurate remote mouse/scroll, whitelisted key/hotkey, or Unicode text input on Windows."""
    if sys.platform != "win32":
        return (False, "仅支持 Windows 远程桌面控制")

    act = (action or "").strip().lower()
    allowed_actions = {
        "click",
        "double_click",
        "right_click",
        "move",
        "scroll_up",
        "scroll_down",
        "key",
        "hotkey",
        "type_text",
    }
    if act not in allowed_actions:
        return (False, f"不支持的远程动作：{act}")

    xr = 0.5
    yr = 0.5
    vk = 0
    hotkey_spec: tuple[list[int], int] | None = None
    clean_text = ""

    if act == "key":
        k_clean = (key_name or "").strip().lower()
        if k_clean not in ALLOWED_REMOTE_KEYS:
            return (False, f"按键不在安全白名单中：{k_clean}")
        vk = ALLOWED_REMOTE_KEYS[k_clean]
    elif act == "hotkey":
        hk_clean = (key_name or "").strip().lower()
        if hk_clean not in ALLOWED_REMOTE_HOTKEYS:
            return (False, f"组合键不在安全白名单中：{hk_clean}")
        hotkey_spec = ALLOWED_REMOTE_HOTKEYS[hk_clean]
    elif act == "type_text":
        clean_text = str(text or "").replace("\x00", "")
        if not clean_text:
            return (False, "输入文本不能为空")
        if len(clean_text) > 2000:
            return (False, "单次直输文本上限为 2000 字")
    else:
        try:
            xr_val = float(x_ratio)
            yr_val = float(y_ratio)
        except (TypeError, ValueError):
            return (False, "远程坐标格式无效")
        if not (math.isfinite(xr_val) and math.isfinite(yr_val)):
            return (False, "远程坐标必须为有限数值")
        if xr_val < 0.0 or xr_val > 1.0 or yr_val < 0.0 or yr_val > 1.0:
            return (False, "远程坐标超出屏幕边界")
        xr = xr_val
        yr = yr_val

    _ensure_win32_dpi_aware()
    with _DESKTOP_UIA_LOCK:
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            user32.mouse_event.argtypes = [
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_size_t,
            ]
            user32.keybd_event.argtypes = [
                wintypes.BYTE,
                wintypes.BYTE,
                wintypes.DWORD,
                ctypes.c_size_t,
            ]

            vx = int(user32.GetSystemMetrics(76))
            vy = int(user32.GetSystemMetrics(77))
            vw = max(1, int(user32.GetSystemMetrics(78)))
            vh = max(1, int(user32.GetSystemMetrics(79)))
            px = int(round(vx + (vw - 1) * xr))
            py = int(round(vy + (vh - 1) * yr))

            if act == "move":
                user32.SetCursorPos(px, py)
                return (True, f"已移动光标至 ({px}, {py})")
            if act == "click":
                user32.SetCursorPos(px, py)
                time.sleep(0.012)
                user32.mouse_event(0x0002, 0, 0, 0, 0)
                time.sleep(0.015)
                user32.mouse_event(0x0004, 0, 0, 0, 0)
                return (True, f"已点击桌面 ({px}, {py})")
            if act == "double_click":
                user32.SetCursorPos(px, py)
                time.sleep(0.012)
                for i in range(2):
                    user32.mouse_event(0x0002, 0, 0, 0, 0)
                    time.sleep(0.012)
                    user32.mouse_event(0x0004, 0, 0, 0, 0)
                    if i == 0:
                        time.sleep(0.035)
                return (True, f"已双击桌面 ({px}, {py})")
            if act == "right_click":
                user32.SetCursorPos(px, py)
                time.sleep(0.012)
                user32.mouse_event(0x0008, 0, 0, 0, 0)
                time.sleep(0.015)
                user32.mouse_event(0x0010, 0, 0, 0, 0)
                return (True, f"已右键点击 ({px}, {py})")
            if act in {"scroll_up", "scroll_down"}:
                user32.SetCursorPos(px, py)
                time.sleep(0.008)
                delta = 360 if act == "scroll_up" else (-360 & 0xFFFFFFFF)
                user32.mouse_event(0x0800, 0, 0, delta, 0)
                return (True, "已滚动画面")
            if act == "key":
                user32.keybd_event(vk, 0, 0, 0)
                time.sleep(0.015)
                user32.keybd_event(vk, 0, 0x0002, 0)
                return (True, f"已发送按键 {key_name.upper()}")
            if act == "hotkey" and hotkey_spec is not None:
                mods, main_vk = hotkey_spec
                pressed_mods: list[int] = []
                try:
                    for mv in mods:
                        user32.keybd_event(mv, 0, 0, 0)
                        pressed_mods.append(mv)
                    time.sleep(0.012)
                    user32.keybd_event(main_vk, 0, 0, 0)
                    time.sleep(0.018)
                    user32.keybd_event(main_vk, 0, 0x0002, 0)
                finally:
                    for mv in reversed(pressed_mods):
                        user32.keybd_event(mv, 0, 0x0002, 0)
                return (True, f"已发送快捷键 {key_name.upper()}")
            if act == "type_text":
                press_ent = (key_name or "").strip().lower() == "enter"
                n_sent = _send_unicode_text_win32(clean_text, press_enter=press_ent)
                suffix = " 并回车" if press_ent else ""
                return (True, f"已输入 {n_sent} 字到电脑焦点{suffix}")
            return (False, "未知动作")
        except Exception as exc:
            return (False, f"远程桌面输入异常：{exc}")

def get_pc_clipboard_text(max_chars: int = 12000) -> dict[str, Any]:
    """Read plain text from the PC clipboard safely without persisting sensitive content."""
    if sys.platform != "win32":
        return {"ok": False, "text": "", "truncated": False}

    ps_script = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
if ([System.Windows.Forms.Clipboard]::ContainsText()) {
    $t = [System.Windows.Forms.Clipboard]::GetText()
    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($t))
    Write-Output "CLIP_B64:$b64"
} else {
    Write-Output "CLIP_EMPTY"
}
"""
    encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    with _DESKTOP_UIA_LOCK:
        try:
            res = subprocess.run(
                ["powershell.exe", "-Sta", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                creationflags=CREATE_NO_WINDOW,
            )
            for ln in reversed([x.strip() for x in (res.stdout or "").splitlines() if x.strip()]):
                if ln.startswith("CLIP_B64:"):
                    raw_txt = base64.b64decode(ln.removeprefix("CLIP_B64:")).decode("utf-8", errors="replace")
                    truncated = len(raw_txt) > max_chars
                    return {"ok": True, "text": raw_txt[:max_chars], "truncated": truncated, "length": len(raw_txt)}
                if ln == "CLIP_EMPTY":
                    return {"ok": True, "text": "", "truncated": False, "length": 0}
            return {"ok": False, "text": "", "truncated": False}
        except Exception as exc:
            return {"ok": False, "text": "", "truncated": False, "error": str(exc)}


def set_pc_clipboard_text(text: str) -> tuple[bool, str]:
    """Write UTF-8 text from mobile directly into the PC Windows clipboard."""
    if sys.platform != "win32":
        return (False, "仅支持 Windows 剪贴板同步")
    val = str(text or "")
    if not val:
        return (False, "剪贴板文本为空")
    if len(val.encode("utf-8")) > 65536:
        return (False, "文本超过 64KB 安全上限")

    ps_script = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
$bytes = [Convert]::FromBase64String($env:AGY_CLIP_SET_B64)
$txt = [System.Text.Encoding]::UTF8.GetString($bytes)
[System.Windows.Forms.Clipboard]::SetText($txt)
Write-Output "OK"
"""
    encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    env = os.environ.copy()
    env["AGY_CLIP_SET_B64"] = base64.b64encode(val.encode("utf-8")).decode("ascii")
    with _DESKTOP_UIA_LOCK:
        try:
            res = subprocess.run(
                ["powershell.exe", "-Sta", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                creationflags=CREATE_NO_WINDOW,
            )
            if "OK" in (res.stdout or ""):
                return (True, f"已写入电脑剪贴板（{len(val)} 字）")
            return (False, "写入电脑剪贴板未确认")
        except Exception as exc:
            return (False, f"写入电脑剪贴板失败：{exc}")


def inspect_pc_system_and_ports(workspace: Path | None = None) -> dict[str, Any]:
    """Return a fast read-only snapshot of PC CPU/RAM/Disk/Battery & active local dev ports."""
    target_disk = workspace if (workspace and workspace.exists()) else Path.cwd()
    disk_free_gb = 0.0
    disk_total_gb = 0.0
    try:
        du = shutil.disk_usage(target_disk)
        disk_free_gb = round(du.free / (1024**3), 1)
        disk_total_gb = round(du.total / (1024**3), 1)
    except OSError:
        pass

    info: dict[str, Any] = {
        "cpu_pct": 0,
        "ram_used_gb": 0.0,
        "ram_total_gb": 0.0,
        "ram_pct": 0,
        "disk_free_gb": disk_free_gb,
        "disk_total_gb": disk_total_gb,
        "battery_pct": None,
        "charging": None,
        "ports": [],
    }
    if sys.platform != "win32":
        return info

    ps_script = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Measure-Object -Property LoadPercentage -Average
$bat = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
$totalMb = if ($os) { [double]$os.TotalVisibleMemorySize / 1024.0 } else { 0 }
$freeMb = if ($os) { [double]$os.FreePhysicalMemory / 1024.0 } else { 0 }
$usedMb = [Math]::Max(0, $totalMb - $freeMb)

$conns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -ge 1024 -and $_.LocalPort -lt 49152 } |
    Sort-Object LocalPort
$seenPorts = @{}
$ports = @()
foreach ($c in $conns) {
    $pt = [int]$c.LocalPort
    if ($seenPorts.ContainsKey($pt)) { continue }
    $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    $pname = if ($p) { [string]$p.ProcessName } else { "" }
    if ($pname -in @("svchost", "System", "lsass", "services", "wininit", "spoolsv")) { continue }
    $seenPorts[$pt] = $true
    $ports += [PSCustomObject]@{
        port = $pt
        pid = [int]$c.OwningProcess
        process = $pname
        addr = [string]$c.LocalAddress
    }
    if ($ports.Count -ge 16) { break }
}

$out = [PSCustomObject]@{
    cpu_pct = if ($cpu -and $null -ne $cpu.Average) { [int][Math]::Round($cpu.Average) } else { 0 }
    ram_used_gb = [Math]::Round($usedMb / 1024.0, 1)
    ram_total_gb = [Math]::Round($totalMb / 1024.0, 1)
    ram_pct = if ($totalMb -gt 0) { [int][Math]::Round(($usedMb / $totalMb) * 100) } else { 0 }
    battery_pct = if ($bat) { [int]$bat.EstimatedChargeRemaining } else { $null }
    charging = if ($bat) { [bool]($bat.BatteryStatus -eq 2) } else { $null }
    ports = @($ports)
}
ConvertTo-Json -InputObject $out -Depth 4 -Compress
"""
    encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    try:
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=6,
            creationflags=CREATE_NO_WINDOW,
        )
        raw = (res.stdout or "").strip()
        if raw:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                info.update(parsed)
    except Exception as exc:
        logger.debug("inspect_pc_system_and_ports warning: %s", exc)
    return info
