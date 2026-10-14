#!/usr/bin/env -S uv run --with pillow --quiet python
"""Draws the DMG window background: a hint arrow and one line of instruction.

Run this only when the design changes; the generated .tiff is committed so a
release build needs no Python. Output is a multi-resolution TIFF so the window
stays crisp on Retina -- Finder does not scale a DMG background, it draws it
1:1, so a plain 2x PNG would show only its top-left quarter.
"""
from PIL import Image, ImageDraw, ImageFont
import subprocess, pathlib

W, H = 660, 420
HERE = pathlib.Path(__file__).parent

def draw(scale: int) -> Image.Image:
    w, h = W * scale, H * scale
    img = Image.new("RGB", (w, h), "#f6f6f8")
    d = ImageDraw.Draw(img)

    # Arrow between the two icon slots (160 pt icons at x=170 and x=490, y=190).
    y = 190 * scale
    x0, x1 = 275 * scale, 385 * scale
    color = "#b8b8bf"
    d.line([(x0, y), (x1 - 10 * scale, y)], fill=color, width=3 * scale)
    head = 11 * scale
    d.polygon(
        [(x1, y), (x1 - head, y - head * 0.62), (x1 - head, y + head * 0.62)],
        fill=color,
    )

    text = "Drag Wombat into your Applications folder"
    size = 13 * scale
    try:
        font = ImageFont.truetype("/System/Library/Fonts/SFNS.ttf", size)
    except OSError:
        font = ImageFont.load_default()
    box = d.textbbox((0, 0), text, font=font)
    d.text(
        ((w - (box[2] - box[0])) / 2, 340 * scale),
        text, fill="#86868b", font=font,
    )
    return img

one, two = HERE / "bg-1x.png", HERE / "bg-2x.png"
draw(1).save(one)
draw(2).save(two)
subprocess.run(
    ["tiffutil", "-cathidpicheck", str(one), str(two),
     "-out", str(HERE / "background.tiff")], check=True)
one.unlink(); two.unlink()
print("wrote", HERE / "background.tiff")
