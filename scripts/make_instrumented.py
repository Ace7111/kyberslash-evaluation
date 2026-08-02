#!/usr/bin/env python3
"""Instrument the runtime divisions by KYBER_Q in a Kyber source tree.

Each site is routed through a variant-specific wrapper so KyberSlash1 and
KyberSlash2 are counted separately, as the upstream analysis treats them as
distinct mechanisms reached by different call paths:

  KyberSlash1 - poly_tomsg,        reached from indcpa_dec (PKE decryption)
  KyberSlash2 - poly_compress and  reached from indcpa_enc (PKE re-encryption)
                polyvec_compress

Two traps this replaces a sed one-liner to avoid:

1. Whitespace after the slash is optional upstream. The KYBER_K*320 branch of
   polyvec_compress -- the branch ML-KEM-512 and ML-KEM-768 actually compile --
   is written "/ KYBER_Q" with a space. A pattern requiring "/KYBER_Q" silently
   instruments the inactive KYBER_K*352 branch instead and drops polyvec_compress
   from the measurement.
2. Patched revisions keep the original division in a comment beside its
   replacement. Commented sites must never be rewritten or counted.

Usage: make_instrumented.py <src-ref-dir> <dest-dir>
"""

import re
import shutil
import sys
from pathlib import Path

# Enclosing function -> KyberSlash variant.
VARIANT_OF_FUNCTION = {
    "poly_tomsg": 1,
    "poly_compress": 2,
    "polyvec_compress": 2,
}

# ((<EXPR> + KYBER_Q/2)/ KYBER_Q)  with optional space after the slash.
DIVISION = re.compile(r"\(\((?P<expr>.*) \+ KYBER_Q/2\)/ ?KYBER_Q\)")

# A C function definition at top level, e.g. "void poly_tomsg(uint8_t msg[...]".
FUNC_DEF = re.compile(r"^[A-Za-z_][A-Za-z0-9_ *]*\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")

COMMENT = re.compile(r"^\s*(//|/\*|\*)")


def instrument(path: Path) -> list:
    lines = path.read_text().splitlines(keepends=True)
    current_function = None
    applied = []

    for i, line in enumerate(lines):
        match = FUNC_DEF.match(line)
        if match and "=" not in line.split("(")[0]:
            current_function = match.group("name")

        if COMMENT.match(line):
            continue
        if not DIVISION.search(line):
            continue

        variant = VARIANT_OF_FUNCTION.get(current_function)
        if variant is None:
            print(f"  WARNING: division in unmapped function "
                  f"{current_function!r} at {path.name}:{i+1} - left untouched",
                  file=sys.stderr)
            continue

        lines[i] = DIVISION.sub(
            rf"(ks_div{variant}(\g<expr> + KYBER_Q/2, KYBER_Q))", line
        )
        applied.append((i + 1, current_function, variant))

    if applied:
        text = "".join(lines)
        if "ks_instrument.h" not in text:
            text = '#include "ks_instrument.h"\n' + text
        path.write_text(text)
    return applied


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, dest = Path(sys.argv[1]), Path(sys.argv[2])
    harness = Path(__file__).resolve().parent.parent / "harness"

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for pattern in ("*.c", "*.h"):
        for f in src.glob(pattern):
            shutil.copy2(f, dest)
    shutil.copy2(harness / "ks_instrument.h", dest)

    total = {1: 0, 2: 0}
    for name in ("poly.c", "polyvec.c"):
        target = dest / name
        if not target.is_file():
            continue
        for line_no, function, variant in instrument(target):
            total[variant] += 1
            print(f"  {name}:{line_no:<4} {function:<18} -> KyberSlash{variant}")

    # Anything left is a division this tool failed to rewrite.
    missed = []
    for name in ("poly.c", "polyvec.c"):
        target = dest / name
        if not target.is_file():
            continue
        for i, line in enumerate(target.read_text().splitlines()):
            if COMMENT.match(line):
                continue
            if re.search(r"\)/ ?KYBER_Q\)", line):
                missed.append(f"{name}:{i+1}")

    print(f"\nInstrumented {total[1]} KyberSlash1 site(s), "
          f"{total[2]} KyberSlash2 site(s) in {dest}")
    if missed:
        print(f"ERROR: untransformed divisions remain: {', '.join(missed)}",
              file=sys.stderr)
        return 1
    print("No untransformed runtime divisions remain.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
