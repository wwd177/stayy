"""Generate crisp multi-resolution Stayy desktop (.ico) and PWA (.png) icons.

Uses only the Python standard library (struct + zlib) to render an anti-aliased
OLED obsidian-emerald rounded-square badge featuring Stayy's precision lens/anchor mark.
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return lo if v < lo else (hi if v > hi else v)


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def _sdf_rounded_box(px: float, py: float, bx: float, by: float, r: float) -> float:
    qx = abs(px) - bx + r
    qy = abs(py) - by + r
    return math.hypot(max(qx, 0.0), max(qy, 0.0)) + min(max(qx, qy), 0.0) - r


def _sdf_circle(px: float, py: float, cx: float, cy: float, r: float) -> float:
    return math.hypot(px - cx, py - cy) - r


def _blend(
    dst: tuple[float, float, float, float], src: tuple[float, float, float, float]
) -> tuple[float, float, float, float]:
    sr, sg, sb, sa = src
    dr, dg, db, da = dst
    out_a = sa + da * (1.0 - sa)
    if out_a <= 1e-6:
        return (0.0, 0.0, 0.0, 0.0)
    out_r = (sr * sa + dr * da * (1.0 - sa)) / out_a
    out_g = (sg * sa + dg * da * (1.0 - sa)) / out_a
    out_b = (sb * sa + db * da * (1.0 - sa)) / out_a
    return (out_r, out_g, out_b, out_a)


def _sample(u: float, v: float) -> tuple[float, float, float, float]:
    px = u * 2.0 - 1.0
    py = v * 2.0 - 1.0

    # Outer obsidian rounded badge
    bg_d = _sdf_rounded_box(px, py, 0.90, 0.90, 0.30)
    bg_a = _clamp(0.5 - bg_d * 48.0)
    if bg_a <= 0.0:
        return (0.0, 0.0, 0.0, 0.0)

    # Rich obsidian-to-deep-emerald ambient base
    gt = _clamp((u * 0.55 + v * 0.85) * 0.85)
    r = _lerp(13.0 / 255.0, 10.0 / 255.0, gt)
    g = _lerp(20.0 / 255.0, 38.0 / 255.0, gt)
    b = _lerp(24.0 / 255.0, 32.0 / 255.0, gt)

    # Top-left subtle emerald aura
    glow = math.exp(-((px + 0.30) ** 2 + (py + 0.35) ** 2) * 2.1)
    r = _clamp(r + glow * 0.04)
    g = _clamp(g + glow * 0.24)
    b = _clamp(b + glow * 0.16)

    col = (r, g, b, bg_a)

    # Crisp rim highlight
    border_d = abs(bg_d + 0.025)
    border_a = _clamp(1.0 - border_d * 60.0) * 0.34
    if border_a > 0:
        col = _blend(col, (0.30, 0.92, 0.65, border_a * bg_a))

    # Stayy stylized precision ring ("S"/beacon radar arc)
    dist = math.hypot(px, py)
    ang = math.atan2(py, px)
    ring_d = abs(dist - 0.44) - 0.085
    # Open a crisp notch at bottom-right to create a sleek open orbital reticle
    in_notch = (-0.52 < ang < 0.22)
    ring_a = _clamp(0.5 - ring_d * 48.0) if not in_notch else 0.0
    if ring_a > 0.0:
        rt = _clamp((px + py + 0.9) * 0.55)
        rr = _lerp(0.95, 0.22, rt)
        rg = _lerp(0.99, 0.90, rt)
        rb = _lerp(0.97, 0.60, rt)
        col = _blend(col, (rr, rg, rb, ring_a))

    # Inner glowing emerald precision core (Stayy reticle center)
    core_d = _sdf_circle(px, py, 0.0, 0.0, 0.14)
    core_a = _clamp(0.5 - core_d * 48.0)
    if core_a > 0.0:
        col = _blend(col, (0.06, 0.85, 0.54, core_a))

    # Crisp satellite status dot inside the notch
    sat_d = _sdf_circle(px, py, 0.42, -0.06, 0.078)
    sat_a = _clamp(0.5 - sat_d * 48.0)
    if sat_a > 0.0:
        col = _blend(col, (1.0, 1.0, 1.0, sat_a))

    return col


def _render_png(size: int) -> bytes:
    samples = 2 if size >= 64 else 3
    rows = bytearray()
    inv_s = 1.0 / samples
    for y in range(size):
        rows.append(0)
        for x in range(size):
            r = g = b = a = 0.0
            for sy in range(samples):
                v = (y + (sy + 0.5) * inv_s) / size
                for sx in range(samples):
                    u = (x + (sx + 0.5) * inv_s) / size
                    cr, cg, cb, ca = _sample(u, v)
                    r += cr * ca
                    g += cg * ca
                    b += cb * ca
                    a += ca
            n = samples * samples
            a /= n
            if a > 1e-6:
                r /= a * n
                g /= a * n
                b /= a * n
            rows.extend(
                (
                    int(_clamp(r) * 255 + 0.5),
                    int(_clamp(g) * 255 + 0.5),
                    int(_clamp(b) * 255 + 0.5),
                    int(_clamp(a) * 255 + 0.5),
                )
            )

    def _chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(rows), level=9)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", idat)
        + _chunk(b"IEND", b"")
    )


def build_all_assets(assets_dir: Path) -> None:
    assets_dir.mkdir(parents=True, exist_ok=True)
    ico_sizes = (256, 64, 48, 32, 16)
    pngs = [(sz, _render_png(sz)) for sz in ico_sizes]
    header = struct.pack("<HHH", 0, 1, len(pngs))
    entries = bytearray()
    offset = 6 + 16 * len(pngs)
    for sz, png_data in pngs:
        dim = 0 if sz >= 256 else sz
        entries.extend(struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png_data), offset))
        offset += len(png_data)
    (assets_dir / "app.ico").write_bytes(header + bytes(entries) + b"".join(p for _, p in pngs))

    for fname, sz in (("icon-192.png", 192), ("apple-touch-icon.png", 180), ("icon-512.png", 512)):
        (assets_dir / fname).write_bytes(_render_png(sz))


if __name__ == "__main__":
    out_dir = Path(__file__).resolve().parent.parent / "assets"
    build_all_assets(out_dir)
    print(f"Generated Stayy icons in: {out_dir}")
