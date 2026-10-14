#!/usr/bin/env python3
"""Render a captured knell session into a terminal-looking PNG.

The text is real tool output: this script only draws it, colouring lines by the
state words knell itself prints, so a screenshot cannot disagree with the binary.
"""

import argparse
import os
import re
import sys
from PIL import Image, ImageDraw, ImageFont

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

BG = (13, 17, 23)
BAR = (24, 29, 37)
FG = (214, 222, 233)
DIM = (132, 144, 160)
GREEN = (126, 217, 147)
AMBER = (235, 183, 94)
RED = (250, 128, 122)
CYAN = (140, 200, 235)
PROMPT = (98, 200, 160)


def classify(line):
    low = line.lower()
    if line.startswith("$ "):
        return PROMPT
    if re.match(r"^\s*silent\b", low) or "forged" in low or "cannot be explained" in low or "rejected" in low:
        return RED
    if re.match(r"^\s*late\b", low) or " is not healthy" in low:
        return AMBER
    if re.match(r"^\s*ok\b", low) or "no silence" in low or "every beacon is explained" in low or "accepted" in low or "added " in low or "is up" in low:
        return GREEN
    if low.startswith("knell:") or "warning" in low:
        return AMBER
    if line.startswith("#") or low.startswith("state:") or "signing key" in low or "cron entry" in low:
        return DIM
    return FG


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("out")
    ap.add_argument("--title", default="knell")
    ap.add_argument("--size", type=int, default=15)
    ap.add_argument("--pad", type=int, default=26)
    args = ap.parse_args()

    with open(args.src, encoding="utf-8") as fh:
        lines = [ln.rstrip("\n").rstrip() for ln in fh.read().splitlines()]
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()

    font = ImageFont.truetype(FONT, args.size)
    bold = ImageFont.truetype(FONT_BOLD, args.size)
    ascent, descent = font.getmetrics()
    lh = ascent + descent + 5
    bar = 40
    measure = ImageDraw.Draw(Image.new("RGB", (10, 10)))
    widest = max(measure.textlength(ln, font=font) for ln in lines) if lines else 0
    title_w = measure.textlength(args.title, font=bold)

    width = int(max(widest, title_w + 60) + 2 * args.pad)
    height = bar + int(lh * len(lines)) + 2 * args.pad + 8

    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, width, bar], fill=BAR)
    for i, c in enumerate([(240, 100, 95), (242, 195, 80), (98, 200, 95)]):
        x = args.pad + i * 24
        d.ellipse([x, bar // 2 - 6, x + 12, bar // 2 + 6], fill=c)
    d.text((width // 2 - title_w // 2, bar // 2 - ascent // 2), args.title, font=bold, fill=DIM)

    y = bar + args.pad
    for ln in lines:
        color = classify(ln)
        if ln.startswith("$ "):
            d.text((args.pad, y), "$ ", font=bold, fill=color)
            off = measure.textlength("$ ", font=bold)
            d.text((args.pad + off, y), ln[2:], font=bold, fill=FG)
        else:
            d.text((args.pad, y), ln, font=font, fill=color)
        y += lh

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    img.save(args.out)
    print(f"wrote {args.out} ({width}x{height}, {len(lines)} lines)")


if __name__ == "__main__":
    sys.exit(main())
