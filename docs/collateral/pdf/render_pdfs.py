#!/usr/bin/env python3
"""Print the three collateral HTML pages to PDF with headless Google Chrome.

Usage:  python3 render_pdfs.py            # render all three
        python3 render_pdfs.py leave      # render only pages whose HTML name contains "leave"

Output goes to out/<original PDF filename>. Standard library only.
"""
import subprocess
import sys
from pathlib import Path

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
HERE = Path(__file__).resolve().parent
OUT = HERE / "out"

PAGES = {
    "leave_behind.html": "Zero Trust Networking - Customer Leave-Behind.pdf",
    "cosell_one_pager.html": "Zero Trust Networking - Internal Co-Sell One-Pager.pdf",
    "one_incident_one_pager.html": "Zero Trust Networking - One Incident End to End - One-Pager.pdf",
}


def render(html_name: str, pdf_name: str) -> Path:
    src = HERE / html_name
    dst = OUT / pdf_name
    cmd = [
        CHROME,
        "--headless=new",
        "--disable-gpu",
        "--no-pdf-header-footer",
        "--run-all-compositor-stages-before-draw",
        "--virtual-time-budget=10000",  # let the Google Fonts stylesheets and files load
        f"--print-to-pdf={dst}",
        src.as_uri(),
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not dst.exists() or dst.stat().st_size == 0:
        raise SystemExit(f"Chrome did not write {dst}")
    return dst


def main() -> None:
    OUT.mkdir(exist_ok=True)
    wanted = sys.argv[1:]
    for html_name, pdf_name in PAGES.items():
        if wanted and not any(w in html_name for w in wanted):
            continue
        print(f"{html_name} -> {render(html_name, pdf_name).relative_to(HERE)}")


if __name__ == "__main__":
    main()
