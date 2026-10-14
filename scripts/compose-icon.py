#!/usr/bin/env -S uv run --with pillow --with numpy --quiet python
"""Composes the app icon onto Apple's exact macOS icon shape.

The source artwork is a finished tile (white ribbon "W" on deep red) with its own
corner radius, 3D rim and transparent margin. macOS 26 only shows an
icon full-size when it matches the system shape -- an 824 px tile, corner radius
185, inside a 1024 px canvas. Anything else is shrunk onto a gray "legacy" plate.

So the artwork is scaled slightly past the tile (FILL) and clipped to that exact
shape: the generated rim and corners fall outside the mask, and the soft shadow
below matches Moo's.
"""
import sys

import numpy as np
from PIL import Image, ImageChops, ImageDraw, ImageFilter

CANVAS = 1024
TILE = 824          # Apple's macOS icon grid
RADIUS = 185        # system tile corner radius
FILL = 1.06         # artwork tile vs mask: pushes the generated rim/corners outside the clip
SHADOW_OFFSET = 12  # px down
SHADOW_BLUR = 22
SHADOW_OPACITY = 70  # of 255
SUPERSAMPLE = 4     # for a smooth tile edge

source, destination = sys.argv[1], sys.argv[2]

art = Image.open(source).convert("RGBA")
# Crop to the tile body: rows/columns that are mostly opaque. Stray specks outside the
# tile (the generated source has a few above it) would otherwise widen a plain bbox.
alpha = np.asarray(art.getchannel("A")) > 128
rows = np.flatnonzero(alpha.sum(axis=1) > alpha.shape[1] * 0.25)
cols = np.flatnonzero(alpha.sum(axis=0) > alpha.shape[0] * 0.25)
art = art.crop((int(cols[0]), int(rows[0]), int(cols[-1]) + 1, int(rows[-1]) + 1))
size = round(TILE * FILL)
art = art.resize((size, size), Image.LANCZOS)

offset = (CANVAS - TILE) // 2
big = Image.new("L", (CANVAS * SUPERSAMPLE,) * 2, 0)
ImageDraw.Draw(big).rounded_rectangle(
    [offset * SUPERSAMPLE, offset * SUPERSAMPLE,
     (offset + TILE) * SUPERSAMPLE - 1, (offset + TILE) * SUPERSAMPLE - 1],
    radius=RADIUS * SUPERSAMPLE, fill=255)
tile_mask = big.resize((CANVAS, CANVAS), Image.LANCZOS)

icon = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))

shadow_alpha = (ImageChops.offset(tile_mask, 0, SHADOW_OFFSET)
                .filter(ImageFilter.GaussianBlur(SHADOW_BLUR))
                .point(lambda v: v * SHADOW_OPACITY // 255))
shadow = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 255))
shadow.putalpha(shadow_alpha)
icon.alpha_composite(shadow)

layer = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
layer.alpha_composite(art, ((CANVAS - size) // 2, (CANVAS - size) // 2))
# The mask decides the shape; inside it the artwork must be fully opaque
art_alpha = np.asarray(layer.getchannel("A"))
mask = np.asarray(tile_mask)
uncovered = int(((mask > 250) & (art_alpha < 250)).sum())
layer.putalpha(tile_mask)
icon.alpha_composite(layer)
icon.save(destination)

corner = icon.getpixel((offset + 2, offset + 2))[3]
center = icon.getpixel((CANVAS // 2, CANVAS // 2))[3]
print(f"artwork {size} px clipped to a {TILE} px tile (radius {RADIUS}); "
      f"corner alpha {corner}, center alpha {center}, uncovered tile pixels {uncovered}")
if center != 255 or uncovered > 0:
    sys.exit("artwork does not cover the tile: raise FILL")
