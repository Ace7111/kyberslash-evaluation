#!/usr/bin/env bash
# Render the Mermaid figure sources in dissertation/figures.md to SVG.
#
# Extracts each ```mermaid block, renders it with mermaid-cli, and writes the result
# to results/figures/. Figure 5.1 is NOT produced here -- it is generated from the
# measurement data by make_figure_5_1.py, so that it cannot drift from the numbers
# it depicts.
#
# Requires Node. mermaid-cli is fetched on demand rather than vendored, since it
# pulls a headless browser and has no place in a reproducibility artefact's
# dependency set.
#
# Usage: render_figures.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIGURES_MD="$ROOT/../dissertation/figures.md"
OUT_DIR="$ROOT/results/figures"
mkdir -p "$OUT_DIR"

if [ ! -f "$FIGURES_MD" ]; then
  echo "error: $FIGURES_MD not found" >&2
  exit 1
fi

# Resolve mmdc explicitly. "npx --no-install" searches node_modules relative to the
# current directory, not PATH, so it fails whenever this is run from anywhere other
# than the install root.
MMDC="${MMDC:-}"
if [ -z "$MMDC" ]; then
  if command -v mmdc >/dev/null 2>&1; then
    MMDC="$(command -v mmdc)"
  elif [ -x /tmp/node_modules/.bin/mmdc ]; then
    MMDC=/tmp/node_modules/.bin/mmdc
  else
    echo "error: mmdc not found. Install with:" >&2
    echo "  npm install -g @mermaid-js/mermaid-cli" >&2
    echo "then rerun, or set MMDC=/path/to/mmdc" >&2
    exit 1
  fi
fi
echo "Using $MMDC"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Mermaid needs a wider default canvas than the diagrams assume, and a white
# background so the SVG does not inherit a transparent one when placed in Word.
#
# htmlLabels MUST be false. With htmlLabels true, mermaid emits every label inside
# an SVG <foreignObject> holding HTML. Browsers render that; almost nothing else
# does -- rsvg-convert, and therefore the SVG-to-PNG step, silently drops it and
# produces a diagram of empty boxes with no error. That is exactly what happened to
# figures 2.1, 2.2 and 4.1 in an earlier run. With htmlLabels false the labels are
# real SVG <text> elements and survive any converter.
#
# Check after rendering: `grep -c "<text" figure_2_1.svg` must be greater than zero.
cat > "$WORK/config.json" <<'JSON'
{ "theme": "default", "flowchart": { "useMaxWidth": false, "htmlLabels": false } }
JSON

python3 - "$FIGURES_MD" "$WORK" <<'PY'
import re, sys, pathlib
md, work = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
text = md.read_text()

# Pair each ```mermaid block with the "## Figure N.N — title" heading above it.
blocks = []
for m in re.finditer(r"```mermaid\n(.*?)```", text, re.S):
    heading = None
    for h in re.finditer(r"^## Figure ([\d.]+) — (.+)$", text[:m.start()], re.M):
        heading = h
    if heading:
        blocks.append((heading.group(1).replace(".", "_"), m.group(1)))

for num, body in blocks:
    (work / f"figure_{num}.mmd").write_text(body)
print("\n".join(f"figure_{n}" for n, _ in blocks))
PY

count=0
for f in "$WORK"/figure_*.mmd; do
  [ -e "$f" ] || continue
  base="$(basename "$f" .mmd)"
  out="$OUT_DIR/${base}.svg"
  if "$MMDC" -i "$f" -o "$out" -c "$WORK/config.json" \
       -b white --quiet 2>"$WORK/err.log"; then
    echo "  rendered $base.svg"
    count=$((count + 1))
  else
    echo "  FAILED   $base" >&2
    tail -5 "$WORK/err.log" >&2
  fi
done

# The dissertation embeds PNGs, so convert here rather than leaving it to a manual
# step that can silently lose the labels.
if command -v rsvg-convert >/dev/null 2>&1; then
  for svg in "$OUT_DIR"/figure_2_*.svg "$OUT_DIR"/figure_4_*.svg; do
    [ -e "$svg" ] || continue
    base="$(basename "$svg" .svg)"
    if [ "$(grep -c "<text" "$svg")" -eq 0 ]; then
      echo "  ERROR: $base.svg contains no <text> elements -- labels would be lost." >&2
      echo "         Check that htmlLabels is false in the mermaid config." >&2
      exit 1
    fi
    rsvg-convert -z 2 -b white -o "$OUT_DIR/${base}.png" "$svg"
    echo "  wrote $base.png"
  done
else
  echo "  note: rsvg-convert not found; SVGs written but PNGs not regenerated" >&2
fi

echo
echo "Rendered $count figure(s) to $OUT_DIR"
echo "Figure 5.1 is generated separately: python3 scripts/make_figure_5_1.py"
