#!/usr/bin/env python3
"""Convert mermaid <foreignObject> labels into real SVG <text> elements.

Why this exists. Mermaid with `htmlLabels: true` puts every diagram label inside an
SVG <foreignObject> containing HTML. Browsers render that correctly, so the diagram
looks right in a browser and in mermaid.live. Almost nothing else implements
foreignObject: rsvg-convert, ImageMagick and most SVG-to-PNG paths drop the element
entirely, without an error. The result is a PNG of correctly laid-out but completely
empty boxes -- which is what reached figures 2.1, 2.2 and 4.1 before this was caught.

The right fix is to render with `htmlLabels: false` so mermaid emits <text> directly,
and scripts/render_figures.sh now does that. This script exists for the case where the
SVG already exists and mermaid-cli is not installed: the label text is present in the
file, just wrapped in HTML, so it can be lifted out and re-emitted as SVG text at the
same position.

Each foreignObject carries its own width and height and sits at the origin of its
parent <g>, so centring the replacement text at (width/2, height/2) reproduces
mermaid's own placement.

Usage: svg_inline_labels.py <file.svg> [...]
"""

import html
import pathlib
import re
import sys

FOREIGN = re.compile(
    r'<foreignObject\s+width="(?P<w>[\d.]+)"\s+height="(?P<h>[\d.]+)"\s*>'
    r'(?P<body>.*?)</foreignObject>',
    re.S,
)
PARA = re.compile(r"<p[^>]*>(.*?)</p>", re.S)
TAG = re.compile(r"<[^>]+>")

FONT = "Helvetica, Arial, sans-serif"
SIZE = 14
LINE = 17


def lines_of(body: str) -> list[str]:
    """Label text, one entry per rendered line."""
    paras = PARA.findall(body)
    if not paras:
        paras = [body]
    out = []
    for p in paras:
        # <br> inside a paragraph is a line break in the rendered label.
        for chunk in re.split(r"<br\s*/?>", p):
            text = html.unescape(TAG.sub("", chunk)).strip()
            if text:
                out.append(text)
    return out


def replace(m: re.Match) -> str:
    w, h = float(m.group("w")), float(m.group("h"))
    lines = lines_of(m.group("body"))
    if not lines:
        return ""

    cx = w / 2
    # Vertically centre the block of lines on the box's midpoint.
    top = h / 2 - (len(lines) - 1) * LINE / 2
    spans = "".join(
        f'<tspan x="{cx:.2f}" y="{top + i * LINE:.2f}">'
        f"{html.escape(t)}</tspan>"
        for i, t in enumerate(lines)
    )
    return (
        f'<text text-anchor="middle" dominant-baseline="central" '
        f'font-family="{FONT}" font-size="{SIZE}" fill="#333">{spans}</text>'
    )


def convert(path: pathlib.Path) -> int:
    svg = path.read_text()
    before = len(FOREIGN.findall(svg))
    if before == 0:
        print(f"  {path.name}: no foreignObject labels, nothing to do")
        return 0
    svg = FOREIGN.sub(replace, svg)
    path.write_text(svg)
    after = len(re.findall(r"<text", svg))
    print(f"  {path.name}: {before} foreignObject -> {after} <text>")
    return before


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    total = 0
    for arg in sys.argv[1:]:
        p = pathlib.Path(arg)
        if not p.is_file():
            print(f"error: {p} not found", file=sys.stderr)
            return 1
        total += convert(p)
    print(f"\nconverted {total} label(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
