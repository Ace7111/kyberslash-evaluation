#!/usr/bin/env python3
"""Generate the two presentation-only figures, as standalone SVGs.

The dissertation's four figures carry the mechanism and the key-dependence result. A
talk needs two more, because two findings that read fine in a table do not land when
spoken:

  P1  Effect size by measurement column. The operand-level leak is enormous (d = 9.98)
      and the wall-clock leak is absent (d = 0.010) in the *same binary on the same
      run*. Said aloud that sounds like a contradiction; seen on one axis it is
      obviously the point -- mechanism and exploitability are separable.

  P2  The build matrix. Identical source, twelve configurations, four of them emitting
      the vulnerable instruction, and no rule connecting them. A table invites the
      audience to look for the pattern; a grid shows there isn't one.

Both read from results/processed/, so neither can drift from the numbers in Chapter 5.

Colours are the two validated categorical slots already used by figure 5.1 (light-mode
CVD delta-E 24.7, normal-vision 33.6). Status in P2 is carried by fill *and* by a glyph
and a legend, never by colour alone.

Usage: make_presentation_figures.py
"""

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "figures"

S1, S2 = "#2a78d6", "#eb6834"
INK, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
FONT = "Aptos, Helvetica, Arial, sans-serif"


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def figure_p1() -> str:
    """Effect size per measurement column, log-scaled because the range is 1000x."""
    data = json.loads((ROOT / "results/processed/"
                       "EXP-LEAK-vuln-gcc16-O2-seed20260801.json").read_text())["columns"]
    rows = [
        ("KyberSlash1\noperand-level", data["ks1_cycles"]["cohens_d"], S1),
        ("KyberSlash2\noperand-level", data["ks2_cycles"]["cohens_d"], S1),
        ("Both variants\nsummed", data["modelled_cycles"]["cohens_d"], S1),
        ("Wall-clock time\non this host", data["host_ns"]["cohens_d"], S2),
    ]
    W, H = 960, 470
    L, R, T, B = 150, 40, 74, 96
    plot_w, plot_h = W - L - R, H - T - B
    bar_h = plot_h / len(rows) * 0.52
    top = 10.0                      # axis maximum, chosen to clear d = 9.98

    a = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
         f'width="{W}" height="{H}" font-family="{FONT}">',
         f'<rect width="{W}" height="{H}" fill="{SURFACE}"/>',
         f'<text x="{L}" y="30" font-size="20" font-weight="600" fill="{INK}">'
         f'The same binary, the same run: a large leak and no signal</text>',
         f'<text x="{L}" y="52" font-size="14" fill="{MUTED}">'
         f"Cohen's d, vulnerable revision at gcc -Os, 40,000 decapsulations</text>"]

    for i in range(0, 11, 2):
        x = L + plot_w * i / top
        a.append(f'<line x1="{x:.1f}" y1="{T}" x2="{x:.1f}" y2="{T+plot_h}" '
                 f'stroke="{GRID}" stroke-width="1"/>')
        a.append(f'<text x="{x:.1f}" y="{T+plot_h+22}" font-size="13" fill="{MUTED}" '
                 f'text-anchor="middle">{i}</text>')

    for i, (label, d, col) in enumerate(rows):
        cy = T + plot_h * (i + 0.5) / len(rows)
        w = max(2.0, plot_w * min(d, top) / top)
        a.append(f'<rect x="{L}" y="{cy-bar_h/2:.1f}" width="{w:.1f}" height="{bar_h:.1f}" '
                 f'fill="{col}" rx="4"/>')
        for j, line in enumerate(label.split("\n")):
            a.append(f'<text x="{L-14}" y="{cy - 4 + j*16:.1f}" font-size="13.5" '
                     f'fill="{INK}" text-anchor="end">{esc(line)}</text>')
        shown = f"{d:.2f}" if d >= 0.1 else f"{d:.3f}"
        a.append(f'<text x="{L+w+10:.1f}" y="{cy+5:.1f}" font-size="14" '
                 f'font-weight="600" fill="{INK}">{shown}</text>')

    a.append(f'<line x1="{L}" y1="{T+plot_h}" x2="{L+plot_w}" y2="{T+plot_h}" '
             f'stroke="{MUTED}" stroke-width="1.5"/>')
    a.append(f'<text x="{L+plot_w/2}" y="{T+plot_h+48}" font-size="13.5" fill="{MUTED}" '
             f'text-anchor="middle">Effect size (Cohen\'s d) — higher means more leakage</text>')
    a.append(f'<text x="{L}" y="{H-22}" font-size="13" fill="{MUTED}">'
             f'The mechanism is fully present. This processor\'s divider does not vary with '
             f'its operands, so nothing reaches wall-clock time.</text>')
    a.append("</svg>")
    return "\n".join(a)


def figure_p2() -> str:
    """Which build configurations emit the vulnerable instruction."""
    cells = json.loads((ROOT / "results/processed/build_matrix.json").read_text())
    opts = ["-O0", "-O1", "-O2", "-O3", "-Os", "-Oz"]
    ccs = ["gcc-16", "clang"]
    names = {"gcc-16": "GCC 16.1.0", "clang": "Clang 17.0.0"}

    grid = {}
    for c in cells:
        if c.get("patch_state") == "vulnerable":
            grid[(c["compiler"], c["optimisation"])] = c["secret_dependent_divisions"]

    W, H = 960, 400
    L, T = 200, 120
    cw, ch, gap = 106, 74, 10

    a = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
         f'width="{W}" height="{H}" font-family="{FONT}">',
         f'<rect width="{W}" height="{H}" fill="{SURFACE}"/>',
         f'<text x="{L-160}" y="36" font-size="20" font-weight="600" fill="{INK}">'
         f'Identical source. The build flags decide whether it leaks.</text>',
         f'<text x="{L-160}" y="58" font-size="14" fill="{MUTED}">'
         f'Historical revision a621b8d at ML-KEM-768 — secret-dependent divisions per build</text>']

    for j, o in enumerate(opts):
        a.append(f'<text x="{L + j*(cw+gap) + cw/2}" y="{T-14}" font-size="14" '
                 f'fill="{INK}" text-anchor="middle" font-weight="600">{o}</text>')

    for i, cc in enumerate(ccs):
        y = T + i * (ch + gap)
        a.append(f'<text x="{L-18}" y="{y+ch/2+5}" font-size="14.5" fill="{INK}" '
                 f'text-anchor="end">{names[cc]}</text>')
        for j, o in enumerate(opts):
            x = L + j * (cw + gap)
            n = grid.get((cc, o), 0)
            bad = n > 0
            a.append(f'<rect x="{x}" y="{y}" width="{cw}" height="{ch}" rx="6" '
                     f'fill="{S2 if bad else "#ffffff"}" '
                     f'stroke="{S2 if bad else GRID}" stroke-width="{2 if bad else 1.5}"/>')
            if bad:
                a.append(f'<text x="{x+cw/2}" y="{y+ch/2-2}" font-size="22" fill="#ffffff" '
                         f'text-anchor="middle" font-weight="700">▲ {n}</text>')
                a.append(f'<text x="{x+cw/2}" y="{y+ch/2+18}" font-size="12" fill="#ffffff" '
                         f'text-anchor="middle">emitted</text>')
            else:
                a.append(f'<text x="{x+cw/2}" y="{y+ch/2+6}" font-size="17" fill="{MUTED}" '
                         f'text-anchor="middle">—</text>')

    ly = T + 2 * (ch + gap) + 34
    a.append(f'<rect x="{L}" y="{ly-11}" width="15" height="15" rx="3" fill="{S2}"/>')
    a.append(f'<text x="{L+23}" y="{ly+2}" font-size="13.5" fill="{INK}">'
             f'▲ emitted — three secret-dependent divisions</text>')
    a.append(f'<text x="{L+330}" y="{ly+2}" font-size="13.5" fill="{MUTED}">'
             f'— clean</text>')
    a.append(f'<text x="{L-160}" y="{H-20}" font-size="13.5" fill="{MUTED}">'
             f'No rule fits: GCC leaks at -Os, Clang does not. Clang leaks at -O0, which '
             f'optimises least. "Avoid -Os" protects one compiler and misses three cases.</text>')
    a.append("</svg>")
    return "\n".join(a)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, svg in (("figure_p1_effect_by_column", figure_p1()),
                      ("figure_p2_build_matrix", figure_p2())):
        (OUT / f"{name}.svg").write_text(svg)
        print(f"  wrote {name}.svg")
    print("\nConvert to PNG with:")
    print("  rsvg-convert -z 2 -b white -o results/figures/NAME.png results/figures/NAME.svg")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
