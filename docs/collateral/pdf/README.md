# Collateral PDFs: HTML sources

HTML sources for the three one-page PDFs in the Zero Trust Networking sales-play folder. Each page is edited as HTML and printed to PDF with headless Google Chrome.

| Source | Prints to `out/` | Page |
|---|---|---|
| `leave_behind.html` | `Zero Trust Networking - Customer Leave-Behind.pdf` | Letter landscape, customer-facing |
| `one_incident_one_pager.html` | `Zero Trust Networking - One Incident End to End - One-Pager.pdf` | Letter landscape, customer-facing |
| `cosell_one_pager.html` | `Zero Trust Networking - Internal Co-Sell One-Pager.pdf` | Letter portrait, internal |

Other files:

- `render_pdfs.py`: prints the HTML to `out/` (standard library only).
- `make_compare.py`: writes old | new side-by-side PNGs to `compare/` (needs Pillow and poppler).
- `ref/`: 110 dpi renders and `pdftotext -layout` text of the original PDFs, kept for reference.
- `compare/`: side-by-side PNGs and `text_diffs.txt`, the word-level text diff against the originals.

## Edit

1. Open the HTML file and change the text in place. Bold runs are `<b>`. On the co-sell page the cyan closing sentence is `<span class="gap">`.
2. Colours are CSS variables at the top of each file (`--magenta`, `--cyan`, `--ink`, `--body`, `--muted`, `--card`, `--line`). All sizes are CSS px; 96 px = 1 inch, so a landscape page is 1056 × 816 and a portrait page is 816 × 1056.
3. The `splunk>` wordmarks and the leave-behind icons (eye, shield-check, bar chart) are inline SVG. The wordmark is SVG `<text>`, so it stays selectable text in the PDF.
4. **Journey grid** (One Incident page): cards sit in a CSS grid, with `grid-row` for the lane (1 to 6) and `grid-column` for the step plus one (2 to 6). Connectors are SVG paths in the journey's own coordinates: lanes start at y = 28 and are 55 px tall, step columns are 162 px wide from x = 160, and a card is 143 × 46 px, inset 9.67 px from its column and 4 px from its lane. If you move a card, move its connector paths too.
5. Keep `24x7` with a plain `x`. Inter's contextual alternates draw it as `24×7`, as in the original, and text extraction stays `24x7`, the same as the original PDF.

## Render

```sh
cd ~/zt-incident-demo/docs/collateral/pdf
python3 render_pdfs.py              # all three
python3 render_pdfs.py cosell       # only files whose name contains "cosell"
```

Chrome loads Inter and IBM Plex Mono from Google Fonts, so rendering needs internet access. The default Google Fonts subsets leave out the `→` arrow, so pages that use it load a second Google Fonts stylesheet with `&text=%E2%86%92`, which adds the arrow from the same families. Without that stylesheet, Chrome falls back to Lucida Grande or Menlo for the arrow.

## Check

```sh
cd out
for f in *.pdf; do pdfinfo "$f" | grep -E 'Pages|Page size'; pdffonts "$f"; done   # Pages: 1, letter; only Inter and IBM Plex Mono
diff <(pdftotext -raw "<original>.pdf" - | tr -s ' \n' '\n') <(pdftotext -raw "<new>.pdf" - | tr -s ' \n' '\n')
cd .. && python3 make_compare.py "/Users/myeack/Library/CloudStorage/OneDrive-Cisco/Projects/Sales Plays/Zero Trust Networking"
```

Every page must print to exactly one page. The co-sell page has no spare room. If a longer edit pushes the four moves into the footer, tighten in this order: section gaps (`.sec.*`, `.para + .para`), then `.para` line-height, and last the body font size, by no more than 0.5 pt.

After you review the PDFs, copy `out/*.pdf` into the OneDrive sales-play folder yourself. Nothing in this folder writes there.

## Changes from the originals

- **Leave-behind:** new "Built on" line and new GET STARTED text.
- **One Incident:** new third line in GETTING DATA IN and a new Splunk Security Content line in DETECT · INVESTIGATE · ENFORCE. Both bottom boxes are the same height, 92 px. To make room, the gaps above and below the WHAT IT'S WORTH row went from 10 to 8 px, and the box line pitch went from about 13.3 to 12.8 px. Font sizes are unchanged.
- **Co-sell:** new integration paragraph, new co-sell roles wording, a new closing sentence in the competitive frame, and new 03 PROVE IT text. To keep one page, section and paragraph gaps are 0.5 to 3 px smaller, the question cards are 2 px shorter, the case card is 2 px shorter, and the paragraph line-height went from 14.22 to 13.7 px. Font sizes are unchanged.
