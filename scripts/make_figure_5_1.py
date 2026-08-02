#!/usr/bin/env python3
"""Generate Figure 5.1 as a standalone SVG: per-variant effect size across keys.

The figure's job is to make one contrast immediate — KyberSlash1's effect is large
and stable across every key, while KyberSlash2's crosses zero — because that is the
finding a reader is most likely to take on trust from a table and misremember.

Form: grouped bars anchored to a zero baseline, since the sign change *is* the
result and a zero baseline is what makes a sign change legible. Not a line chart:
seeds are unordered identities, not a sequence.

Colours are the validated categorical slots 1 and 2 from the design system, checked
with scripts/validate_palette.js in both modes (light: CVD ΔE 24.7, normal-vision
33.6; dark: 26.8 / 31.8 — all above threshold). Identity is carried by a legend and
by position within each pair, never by colour alone.

Output is a self-contained SVG suitable for insertion into Word. Add the caption and
alternative text in Word rather than baking them into the image.

Usage: make_figure_5_1.py [--json results/processed/seed_sweep_vulnerable.json]
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Design-system categorical slots 1 and 2, validated in both modes.
LIGHT = {"s1": "#2a78d6", "s2": "#eb6834", "surface": "#fcfcfb",
         "ink": "#0b0b0b", "muted": "#52514e", "grid": "#e4e3df"}

W, H = 960, 480
PAD_L, PAD_R, PAD_T, PAD_B = 74, 30, 66, 104


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def build(rows) -> str:
    seeds = [r["seed"] for r in rows]
    ks1 = [r["ks1_cycles"]["cohens_d"] for r in rows]
    ks2 = [r["ks2_cycles"]["cohens_d"] for r in rows]

    lo = min(0.0, min(ks2), min(ks1))
    hi = max(ks1 + ks2)
    # Round outward to whole units so gridlines land on readable values.
    y_lo, y_hi = float(int(lo) - 1), float(int(hi) + 1)

    plot_w = W - PAD_L - PAD_R
    plot_h = H - PAD_T - PAD_B

    def y(v):
        return PAD_T + plot_h * (y_hi - v) / (y_hi - y_lo)

    zero_y = y(0.0)
    group_w = plot_w / len(seeds)
    bar_w = group_w * 0.32
    gap = 2.0  # 2px surface gap between adjacent fills

    out = []
    a = out.append
    a(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
      f'width="{W}" height="{H}" font-family="Inter, Helvetica, Arial, sans-serif" '
      f'role="img" aria-labelledby="fig51title fig51desc">')
    a(f'<title id="fig51title">Per-variant effect size across ten independent keys</title>')
    a(f'<desc id="fig51desc">Grouped bar chart. KyberSlash1 effect size is positive '
      f'and between 7.97 and 12.76 for all ten keys. KyberSlash2 ranges from minus '
      f'1.14 to plus 2.13 and is negative for four of the ten keys.</desc>')
    a(f'<rect width="{W}" height="{H}" fill="{LIGHT["surface"]}"/>')

    # Title
    a(f'<text x="{PAD_L}" y="28" font-size="16" font-weight="600" '
      f'fill="{LIGHT["ink"]}">Effect size by KyberSlash variant, across ten independent keys</text>')
    a(f'<text x="{PAD_L}" y="48" font-size="12.5" fill="{LIGHT["muted"]}">'
      f'KyberSlash1 is large and stable; KyberSlash2 changes sign with the key</text>')

    # Gridlines (recessive) at whole units
    v = y_lo
    while v <= y_hi + 1e-9:
        gy = y(v)
        if abs(v) > 1e-9:
            a(f'<line x1="{PAD_L}" y1="{gy:.1f}" x2="{W-PAD_R}" y2="{gy:.1f}" '
              f'stroke="{LIGHT["grid"]}" stroke-width="1"/>')
        a(f'<text x="{PAD_L-10}" y="{gy+4:.1f}" font-size="11.5" text-anchor="end" '
          f'fill="{LIGHT["muted"]}">{v:.0f}</text>')
        v += 2.0

    # Bars
    for i, s in enumerate(seeds):
        gx = PAD_L + i * group_w
        cx = gx + group_w / 2
        for val, colour in ((ks1[i], LIGHT["s1"]), (ks2[i], LIGHT["s2"])):
            bx = cx - bar_w - gap / 2 if colour == LIGHT["s1"] else cx + gap / 2
            top = y(max(val, 0.0))
            height = abs(y(val) - zero_y)
            if height < 0.6:
                height = 0.6
            # 4px rounded data-end, square at the baseline
            r = min(4.0, bar_w / 2, height)
            if val >= 0:
                d = (f'M{bx:.1f},{zero_y:.1f} V{top+r:.1f} Q{bx:.1f},{top:.1f} '
                     f'{bx+r:.1f},{top:.1f} H{bx+bar_w-r:.1f} '
                     f'Q{bx+bar_w:.1f},{top:.1f} {bx+bar_w:.1f},{top+r:.1f} '
                     f'V{zero_y:.1f} Z')
            else:
                bot = zero_y + height
                d = (f'M{bx:.1f},{zero_y:.1f} V{bot-r:.1f} Q{bx:.1f},{bot:.1f} '
                     f'{bx+r:.1f},{bot:.1f} H{bx+bar_w-r:.1f} '
                     f'Q{bx+bar_w:.1f},{bot:.1f} {bx+bar_w:.1f},{bot-r:.1f} '
                     f'V{zero_y:.1f} Z')
            a(f'<path d="{d}" fill="{colour}"/>')

        # Seed label
        a(f'<text x="{cx:.1f}" y="{H-PAD_B+22:.0f}" font-size="11.5" '
          f'text-anchor="middle" fill="{LIGHT["muted"]}">{esc(s)}</text>')

    # Zero baseline, drawn last so it sits above the fills
    a(f'<line x1="{PAD_L}" y1="{zero_y:.1f}" x2="{W-PAD_R}" y2="{zero_y:.1f}" '
      f'stroke="{LIGHT["ink"]}" stroke-width="1.5"/>')

    # Axis titles
    a(f'<text x="{PAD_L + plot_w/2:.0f}" y="{H-PAD_B+46:.0f}" font-size="12" '
      f'text-anchor="middle" fill="{LIGHT["muted"]}">Seed (independent keypair)</text>')
    a(f'<text transform="translate(20,{PAD_T+plot_h/2:.0f}) rotate(-90)" '
      f'font-size="12" text-anchor="middle" fill="{LIGHT["muted"]}">'
      f"Cohen's d</text>")

    # Legend
    ly = H - 18
    a(f'<rect x="{PAD_L}" y="{ly-9}" width="11" height="11" rx="2" fill="{LIGHT["s1"]}"/>')
    a(f'<text x="{PAD_L+18}" y="{ly}" font-size="12.5" fill="{LIGHT["ink"]}">'
      f'KyberSlash1 (poly_tomsg)</text>')
    a(f'<rect x="{PAD_L+210}" y="{ly-9}" width="11" height="11" rx="2" fill="{LIGHT["s2"]}"/>')
    a(f'<text x="{PAD_L+228}" y="{ly}" font-size="12.5" fill="{LIGHT["ink"]}">'
      f'KyberSlash2 (compression)</text>')
    a('</svg>')
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", type=Path,
                    default=ROOT / "results" / "processed" / "seed_sweep_vulnerable.json")
    ap.add_argument("--out", type=Path,
                    default=ROOT / "results" / "figures" / "figure_5_1_effect_by_key.svg")
    args = ap.parse_args()

    if not args.json.is_file():
        print(f"error: {args.json} not found - run seed_sweep.py first", file=sys.stderr)
        return 2

    data = json.loads(args.json.read_text())
    rows = data["results"]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build(rows))

    neg = sum(1 for r in rows if r["ks2_cycles"]["difference"] < 0)
    print(f"Wrote {args.out}")
    print(f"  {len(rows)} keys; KyberSlash2 negative in {neg}")
    print(f"  ks1 d range {min(r['ks1_cycles']['cohens_d'] for r in rows):.2f} "
          f"to {max(r['ks1_cycles']['cohens_d'] for r in rows):.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
