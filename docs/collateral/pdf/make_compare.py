#!/usr/bin/env python3
"""Render original and new PDFs at 110 dpi and write old | new side-by-side PNGs to compare/.

Usage:  python3 make_compare.py "/path/to/folder/with/original/PDFs"
Needs poppler's pdftoppm on PATH and Pillow (python3 -m pip install pillow).
"""
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent
NAMES = {
    "leave_behind": "Zero Trust Networking - Customer Leave-Behind.pdf",
    "cosell_one_pager": "Zero Trust Networking - Internal Co-Sell One-Pager.pdf",
    "one_incident_one_pager": "Zero Trust Networking - One Incident End to End - One-Pager.pdf",
}


def raster(pdf: Path, tmp: Path, stem: str) -> Image.Image:
    subprocess.run(["pdftoppm", "-r", "110", "-png", "-singlefile", str(pdf), str(tmp / stem)],
                   check=True, stderr=subprocess.DEVNULL)
    return Image.open(tmp / f"{stem}.png").convert("RGB")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    orig_dir = Path(sys.argv[1]).expanduser()
    (HERE / "compare").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        for key, pdf_name in NAMES.items():
            if not (HERE / "out" / pdf_name).exists():
                print(f"skip {key}: out/{pdf_name} not rendered yet")
                continue
            old = raster(orig_dir / pdf_name, tmp, key + "_old")
            new = raster(HERE / "out" / pdf_name, tmp, key + "_new")
            gap, band = 24, 28
            w, h = old.width + new.width + gap, max(old.height, new.height) + band
            sheet = Image.new("RGB", (w, h), (255, 255, 255))
            sheet.paste(old, (0, band))
            sheet.paste(new, (old.width + gap, band))
            d = ImageDraw.Draw(sheet)
            d.text((8, 8), "OLD (current PDF)", fill=(0, 0, 0))
            d.text((old.width + gap + 8, 8), "NEW (rebuilt from HTML)", fill=(0, 0, 0))
            dst = HERE / "compare" / f"{key}_old_vs_new.png"
            sheet.save(dst)
            print(dst.relative_to(HERE))


if __name__ == "__main__":
    main()
