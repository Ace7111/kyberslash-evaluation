#!/usr/bin/env python3
"""Disassemble a built target and attribute variable-latency division instructions
to their containing functions, classifying each as KyberSlash-relevant or incidental.

Emits JSON so results feed the statistical/reporting stages without manual transcription.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Divisions in these functions carry secret-dependent operands (the KyberSlash mechanism).
# Anything else is incidental: Keccak buffer arithmetic, rejection-sampling counters, etc.
#
# Matching is by regex on the symbol rather than by exact name, because every project
# namespaces its symbols differently and some split compression per output width:
#   pq-crystals   _pqcrystals_kyber768_ref_poly_tomsg
#   mlkem-native  _PQCP_MLKEM_NATIVE_MLKEM768_poly_tomsg
#                 _PQCP_MLKEM_NATIVE_MLKEM768_poly_compress_d4
#                 _PQCP_MLKEM_NATIVE_MLKEM768_polyvec_compress_du
# An exact-name table silently classifies all of the above as incidental, which would
# turn a real finding into a clean verdict. The patterns are anchored at the end so
# "poly_decompress_d4" -- decompression, which takes public input -- cannot match.
SECRET_DEPENDENT_PATTERNS = [
    # C implementations (pq-crystals, mlkem-native and derivatives)
    (re.compile(r"(^|_)poly_tomsg$"), "KyberSlash1"),
    (re.compile(r"(^|_)poly_compress(_d\d+|_du|_dv)?$"), "KyberSlash2"),
    (re.compile(r"(^|_)polyvec_compress(_d\d+|_du|_dv)?$"), "KyberSlash2"),
    # Go implementations (CIRCL). Method symbols carry a receiver, e.g.
    # "github.com/cloudflare/circl/pke/kyber/internal/common.(*Poly).CompressTo".
    # CompressMessageTo is Compress_q(p, 1), the message decoding that corresponds
    # to poly_tomsg; CompressTo(d) is the polynomial/vector compression.
    (re.compile(r"\.CompressMessageTo$"), "KyberSlash1"),
    (re.compile(r"\.CompressTo$"), "KyberSlash2"),
]


def classify(symbol: str):
    """Return the KyberSlash variant for a symbol, or None if incidental."""
    name = symbol.lstrip("_")
    for pattern, variant in SECRET_DEPENDENT_PATTERNS:
        if pattern.search(name):
            return variant
    return None

DIV_MNEMONICS = {
    "aarch64": ("udiv", "sdiv"),
    "arm64": ("udiv", "sdiv"),
    "x86_64": ("div", "idiv", "divl", "divq", "idivl", "idivq"),
}

FUNC_HEADER = re.compile(r"^[0-9a-f]+\s+<(?P<name>.+)>:\s*$")

# Extract the mnemonic from a disassembly line, tolerating both objdump layouts:
#
#   LLVM (macOS):  "       0: 1ac10800     \tudiv\tw0, w0, w1"
#                  address and bytes share field 0, mnemonic is field 1
#   GNU (Linux):   "   0:\tf7 f1                \tdiv    %ecx"
#                  address is field 0, BYTES are field 1, mnemonic is field 2
#
# Indexing a fixed field therefore works on one platform and silently fails on the
# other -- on x86-64 it read the hex bytes as the mnemonic, matched nothing, and
# reported every binary clean. Matching the structure instead is layout-independent.
MNEMONIC = re.compile(r"^\s*[0-9a-f]+:\s*(?:[0-9a-f]{2,8}\s+)*([a-z][a-z0-9._]*)")


def detect_arch() -> str:
    import platform

    machine = platform.machine().lower()
    return "aarch64" if machine in ("arm64", "aarch64") else "x86_64"


def disassemble(binary: Path, objdump: str) -> str:
    result = subprocess.run(
        [objdump, "-d", str(binary)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def normalise(symbol: str) -> str:
    """Strip Mach-O leading underscore and the pqcrystals_kyber<K>_<backend>_ namespace."""
    name = symbol.lstrip("_")
    name = re.sub(r"^pqcrystals_kyber(?:\d+)?_(?:ref_|avx2_|fips202_ref_)?", "", name)
    return name


def analyse(disasm: str, mnemonics: tuple) -> list:
    pattern = re.compile(r"\b(" + "|".join(mnemonics) + r")\b")
    current = "<unknown>"
    hits = {}

    for line in disasm.splitlines():
        header = FUNC_HEADER.match(line)
        if header:
            current = header.group("name")
            continue
        # Match only the mnemonic so register names and operands never false-positive.
        m = MNEMONIC.match(line)
        if m and pattern.fullmatch(m.group(1)):
            hits[current] = hits.get(current, 0) + 1

    findings = []
    for symbol, count in sorted(hits.items(), key=lambda kv: -kv[1]):
        variant = classify(symbol)
        findings.append(
            {
                "symbol": symbol,
                "function": normalise(symbol),
                "division_count": count,
                "classification": "vulnerable" if variant else "incidental",
                "kyberslash_variant": variant,
            }
        )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--experiment-id", default=None)
    parser.add_argument("--arch", default=None, choices=sorted(DIV_MNEMONICS))
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()

    if not args.binary.is_file():
        print(f"error: {args.binary} not found", file=sys.stderr)
        return 2
    if shutil.which(args.objdump) is None:
        print(f"error: {args.objdump} not on PATH", file=sys.stderr)
        return 2

    arch = args.arch or detect_arch()
    findings = analyse(disassemble(args.binary, args.objdump), DIV_MNEMONICS[arch])
    vulnerable = [f for f in findings if f["classification"] == "vulnerable"]

    report = {
        "experiment_id": args.experiment_id,
        "binary": str(args.binary),
        "binary_sha256": subprocess.run(
            ["shasum", "-a", "256", str(args.binary)],
            capture_output=True, text=True, check=True,
        ).stdout.split()[0],
        "arch": arch,
        "mnemonics_searched": list(DIV_MNEMONICS[arch]),
        "total_divisions": sum(f["division_count"] for f in findings),
        "secret_dependent_divisions": sum(f["division_count"] for f in vulnerable),
        "verdict": "VULNERABLE" if vulnerable else "NO_SECRET_DEPENDENT_DIV",
        "findings": findings,
    }

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n")

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
