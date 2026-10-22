#!/usr/bin/env python3
"""Render PHProtect's monochrome shield icon set.

Pure geometry, supersampled 4x with Pillow, then box-filtered down. Run from
the repo root: `python tools/make_icons.py`.
"""
import math
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "src" / "icons"
SIZES = (16, 32, 48, 128)
MASTER = 512
SS = 4

BG = (40, 43, 48, 255)
SHIELD = (245, 245, 245, 255)
SHIELD_EDGE = SHIELD
KEY = BG


def shield_points(cx: float, top: float, half: float, r: float, side: float, tip: float):
    """A classic shield: rounded top corners, straight flanks, pointed base."""
    def arc(ccx, ccy, radius, a0, a1, steps=14):
        return [(ccx + radius * math.cos(a0 + (a1 - a0) * i / steps),
                 ccy + radius * math.sin(a0 + (a1 - a0) * i / steps))
                for i in range(steps + 1)]

    pts = arc(cx - half + r, top + r, r, math.pi, 1.5 * math.pi)          # top-left corner
    pts += arc(cx + half - r, top + r, r, 1.5 * math.pi, 2 * math.pi)     # top-right corner
    pts.append((cx + half, side))
    # Quadratic curve from the right flank down to the bottom tip.
    for i in range(1, 25):
        t = i / 24
        x = (1 - t) ** 2 * (cx + half) + 2 * (1 - t) * t * (cx + half - 14) + t * t * cx
        y = (1 - t) ** 2 * side + 2 * (1 - t) * t * (tip - 60) + t * t * tip
        pts.append((x, y))
    left = [(2 * cx - x, y) for (x, y) in reversed(pts)][:-1]
    return pts + left


def render() -> Image.Image:
    n = MASTER * SS
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    def s(v: float) -> float:
        return v * SS

    # Rounded background tile.
    d.rounded_rectangle((0, 0, n - 1, n - 1), radius=s(108), fill=BG)

    pts = shield_points(256, 92, 168, 44, 288, 462)
    d.polygon([(s(x), s(y)) for x, y in pts], fill=SHIELD, outline=SHIELD_EDGE)
    d.line([(s(x), s(y)) for x, y in pts] + [(s(pts[0][0]), s(pts[0][1]))], fill=SHIELD_EDGE, width=s(6), joint="curve")

    # Keyhole: circle plus a flared stem.
    d.ellipse((s(204), s(196), s(308), s(300)), fill=KEY)
    d.polygon([(s(230), s(278)), (s(282), s(278)), (s(302), s(392)), (s(210), s(392))], fill=KEY)
    # Browser icons use the full canvas so the mark stays legible at 16px.
    # Store-listing padding is applied separately by make_store_assets.py.
    return img


def main() -> None:
    master = render()
    OUT.mkdir(parents=True, exist_ok=True)
    for size in SIZES:
        master.resize((size, size), Image.LANCZOS).save(OUT / f"icon-{size}.png", optimize=True)
        print(f"wrote icon-{size}.png")


if __name__ == "__main__":
    main()
