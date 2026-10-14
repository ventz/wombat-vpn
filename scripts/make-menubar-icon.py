#!/usr/bin/env -S uv run --with pillow --with numpy --quiet python
"""Makes the menu bar's "W" template image from the app icon's ribbon.

The ribbon is the white/gray part of the artwork (low saturation, fairly bright), the tile is
saturated red. The template keeps the ribbon's shading as alpha, so the folds of the "W" stay
readable at 18 pt; macOS tints a template image to match the menu bar.

    scripts/make-menubar-icon.py assets/icon-source.png Resources/MenuBarW
    -> Resources/MenuBarW.png (18 pt tall) and Resources/MenuBarW@2x.png
"""
import sys

import numpy as np
from PIL import Image

HEIGHT_PT = 16      # the glyph; the menu bar is 22-24 pt tall
MIN_ALPHA = 0.55    # darkest fold vs the brightest ribbon face

source, destination = sys.argv[1], sys.argv[2]

rgb = np.asarray(Image.open(source).convert("RGB")).astype(np.float32) / 255
high, low = rgb.max(axis=2), rgb.min(axis=2)
saturation = np.where(high > 0, (high - low) / np.maximum(high, 1e-6), 0)
ribbon = (saturation < 0.22) & (high > 0.42)

ys, xs = np.nonzero(ribbon)
top, bottom, left, right = ys.min(), ys.max() + 1, xs.min(), xs.max() + 1
shade = (high - 0.42) / (1 - 0.42)
alpha = np.where(ribbon, MIN_ALPHA + (1 - MIN_ALPHA) * np.clip(shade, 0, 1), 0)[top:bottom, left:right]

glyph = np.zeros((*alpha.shape, 4), dtype=np.uint8)
glyph[..., 3] = (alpha * 255).round().astype(np.uint8)
image = Image.fromarray(glyph, "RGBA")

for scale, suffix in ((1, ""), (2, "@2x")):
    height = HEIGHT_PT * scale
    width = round(image.width * height / image.height)
    image.resize((width, height), Image.LANCZOS).save(f"{destination}{suffix}.png")
    print(f"{destination}{suffix}.png  {width}x{height}")
