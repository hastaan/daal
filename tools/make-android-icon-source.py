#!/usr/bin/env python3
"""Compose the Android launcher-icon source from the raw daal eagle.

Output: client-shared/branding/daal-app-icon-1024.png — the eagle cropped to
its bounding box, scaled to 60% (inside the adaptive-icon safe zone), centered
on the app's dark-teal background (--bg oklch(28% 0.04 215) -> #0D2E35).

Run from repo root:  python3 tools/make-android-icon-source.py
Then:                tools/patch-android-icons.sh
"""
import math
import os
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EAGLE = os.path.join(ROOT, "client-shared/branding/sources/daal-eagle-transparent.png")
OUT = os.path.join(ROOT, "client-shared/branding/daal-app-icon-1024.png")
SZ = 1024
SCALE = 0.60  # longer eagle side as fraction of canvas; keeps adaptive safe zone


def oklch_to_srgb(L, C, Hdeg):
    h = math.radians(Hdeg)
    a, b = C * math.cos(h), C * math.sin(h)
    l_ = L + 0.3963377774 * a + 0.2158037573 * b
    m_ = L - 0.1055613458 * a - 0.0638541728 * b
    s_ = L - 0.0894841775 * a - 1.2914855480 * b
    l, m, s = l_ ** 3, m_ ** 3, s_ ** 3
    r = 4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s
    g = -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s
    bb = -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s
    enc = lambda x: 12.92 * x if x <= 0.0031308 else 1.055 * (x ** (1 / 2.4)) - 0.055
    return tuple(round(enc(max(0.0, min(1.0, v))) * 255) for v in (r, g, bb))


def main():
    bg = oklch_to_srgb(0.28, 0.04, 215)
    eagle = Image.open(EAGLE).convert("RGBA")
    eagle = eagle.crop(eagle.getbbox())  # tight bounds
    target = int(SZ * SCALE)
    w, h = eagle.size
    nw, nh = (target, int(h * target / w)) if w >= h else (int(w * target / h), target)
    eagle_r = eagle.resize((nw, nh), Image.LANCZOS)
    canvas = Image.new("RGBA", (SZ, SZ), bg + (255,))
    canvas.alpha_composite(eagle_r, ((SZ - nw) // 2, (SZ - nh) // 2))
    canvas.convert("RGB").save(OUT)
    print("wrote %s (bg #%02X%02X%02X)" % (OUT, *bg))


if __name__ == "__main__":
    main()
