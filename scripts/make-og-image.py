#!/usr/bin/env -S uv run --with pillow --quiet python
"""Draws the link-preview card (Open Graph image) for wombat.vpetkov.net: what iMessage, Slack,
X and others show when someone pastes the link. 1200x630, the size they all crop well.

    scripts/make-og-image.py      # -> site/og.png (committed; published by publish-site.sh)

Inputs: docs/images/icon.png and the dark overview screenshot (build/screenshots/raw/, made by
scripts/dev/screenshots.sh). Re-run after the screenshots or the icon change.
"""
import pathlib

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = pathlib.Path(__file__).resolve().parent.parent
W, H = 1200, 630
BG, INK, MUTED, RED = (18, 13, 14), (246, 238, 238), (183, 163, 165), (226, 90, 97)


def font(size: int, weight: str) -> ImageFont.FreeTypeFont:
    f = ImageFont.truetype("/System/Library/Fonts/SFNS.ttf", size)
    try:
        f.set_variation_by_name(weight)
    except (OSError, ValueError):
        pass
    return f


card = Image.new("RGB", (W, H), BG)

# A soft red glow behind the text, like the site's header.
glow = Image.new("L", (W, H), 0)
ImageDraw.Draw(glow).ellipse((-260, -220, 620, 560), fill=90)
glow = glow.filter(ImageFilter.GaussianBlur(140))
card.paste(Image.new("RGB", (W, H), (120, 22, 28)), (0, 0), glow)

# The app window on the right, running off the edge.
shot = Image.open(ROOT / "build/screenshots/raw/overview-dark.png").convert("RGBA")
shot_w = 760
shot = shot.resize((shot_w, round(shot.height * shot_w / shot.width)), Image.LANCZOS)
card.paste(shot, (590, 120), shot)

# Icon, name, tagline.
icon = Image.open(ROOT / "docs/images/icon.png").convert("RGBA").resize((128, 128), Image.LANCZOS)
card.paste(icon, (64, 92), icon)
d = ImageDraw.Draw(card)
d.text((64, 250), "Wombat", font=font(92, "Bold"), fill=INK)
d.text((66, 362), "The modern WireGuard", font=font(38, "Semibold"), fill=INK)
d.text((66, 408), "client for Mac", font=font(38, "Semibold"), fill=INK)
d.text((66, 484), "Native · Free · Open source", font=font(26, "Medium"), fill=MUTED)
d.text((66, 522), "Security first", font=font(26, "Semibold"), fill=RED)

out = ROOT / "site/og.png"
card.save(out, optimize=True)
print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
