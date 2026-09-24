#!/usr/bin/env python3
"""Render a Markdown file to a self-contained HTML sibling (inline CSS, no external assets). Usage: md2html.py FILE.md [...]"""
import html
import os
import sys

CSS = """body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#1f2937;background:#fff}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.92em}pre{background:#f3f4f6;padding:.75rem;overflow-x:auto;border-radius:6px}code{background:#f3f4f6;padding:.1em .3em;border-radius:4px}pre code{background:none;padding:0}
table{border-collapse:collapse;margin:1rem 0;width:100%}th,td{border:1px solid #d1d5db;padding:.4rem .6rem;text-align:left;vertical-align:top}th{background:#f9fafb}h1,h2,h3{line-height:1.25}a{color:#0b5cad}
@media (prefers-color-scheme: dark){body{background:#0f172a;color:#e5e7eb}pre,code{background:#1e293b}th{background:#1e293b}th,td{border-color:#334155}a{color:#7dd3fc}}"""


def render(md_path):
    try:
        import markdown
        body = markdown.markdown(open(md_path).read(), extensions=["tables", "fenced_code", "toc", "sane_lists"])
    except ImportError:
        body = "<pre>%s</pre>" % html.escape(open(md_path).read())
    title = os.path.basename(md_path).rsplit(".", 1)[0].replace("_", " ")
    out = "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>%s</title><style>%s</style></head><body>%s</body></html>\n" % (html.escape(title), CSS, body)
    html_path = md_path[:-3] + ".html"
    open(html_path, "w").write(out)
    return html_path


if __name__ == "__main__":
    for p in sys.argv[1:]:
        print("rendered", render(p))
