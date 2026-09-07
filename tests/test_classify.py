#!/usr/bin/env python3
"""Regression tests for the division classifier.

The classifier decides whether a division is a KyberSlash finding or incidental, so a
silent misclassification turns a real vulnerability into a clean verdict. These cases
pin the behaviour that matters:

  - every project namespaces symbols differently, and matching must survive that;
  - mlkem-native splits compression per output width (_d4, _d10, _du);
  - decompression takes public input and must never be flagged;
  - Keccak and rejection-sampling divisions are incidental and must stay that way.

Run: python3 tests/test_classify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from inspect_binary import DIV_MNEMONICS, analyse, classify  # noqa: E402

CASES = [
    # pq-crystals reference naming
    ("_pqcrystals_kyber768_ref_poly_tomsg", "KyberSlash1"),
    ("_pqcrystals_kyber512_ref_poly_tomsg", "KyberSlash1"),
    ("_pqcrystals_kyber768_ref_poly_compress", "KyberSlash2"),
    ("_pqcrystals_kyber768_ref_polyvec_compress", "KyberSlash2"),
    ("_pqcrystals_kyber768_avx2_poly_compress", "KyberSlash2"),
    # mlkem-native naming, including per-width compression variants
    ("_PQCP_MLKEM_NATIVE_MLKEM768_poly_tomsg", "KyberSlash1"),
    ("_PQCP_MLKEM_NATIVE_MLKEM768_poly_compress_d4", "KyberSlash2"),
    ("_PQCP_MLKEM_NATIVE_MLKEM768_poly_compress_d10", "KyberSlash2"),
    ("_PQCP_MLKEM_NATIVE_MLKEM768_polyvec_compress_du", "KyberSlash2"),
    ("_mlk_poly_tomsg", "KyberSlash1"),
    # wolfSSL naming
    ("_mlkem_to_msg", "KyberSlash1"),
    ("_mlkem_compress_4", "KyberSlash2"),
    ("_mlkem_compress_5", "KyberSlash2"),
    ("_mlkem_vec_compress_10", "KyberSlash2"),
    ("_mlkem_vec_compress_11", "KyberSlash2"),
    # wolfSSL decompression must NOT match: "compress" there follows "de", not "_"
    ("_mlkem_decompress_4", None),
    ("_mlkem_vec_decompress_10", None),
    ("_mlkem_from_msg", None),
    # Decompression is the inverse operation on public data - must not be flagged
    ("_PQCP_MLKEM_NATIVE_MLKEM768_poly_decompress_d4", None),
    ("_PQCP_MLKEM_NATIVE_MLKEM768_polyvec_decompress_du", None),
    ("_pqcrystals_kyber768_ref_poly_decompress", None),
    ("_pqcrystals_kyber768_ref_polyvec_decompress", None),
    # Incidental divisions observed in real builds
    ("_pqcrystals_kyber_fips202_ref_shake128", None),
    ("_pqcrystals_kyber_fips202_ref_shake256", None),
    ("_pqcrystals_kyber768_ref_gen_matrix", None),
    ("_keccak_absorb_once", None),
    ("_main", None),
    ("_test_invalid_ciphertext", None),
    # Near-misses that must not match
    ("_poly_frommsg", None),
    ("_poly_tomsg_helper", None),
    ("_compress", None),
]


# Disassembly-parsing cases. objdump's line layout differs by platform, and indexing a
# fixed field works on one and silently fails on the other -- which made every x86-64
# audit report clean. These pin both layouts.
#
#   LLVM (macOS):  address and bytes share field 0, mnemonic in field 1
#   GNU (Linux):   address in field 0, BYTES in field 1, mnemonic in field 2
DISASM_CASES = [
    (
        "aarch64 / LLVM objdump",
        "aarch64",
        "00000001000024c0 <_pqcrystals_kyber768_ref_poly_tomsg>:\n"
        "     de4: 1ac10800     \tudiv\tw0, w0, w1\n"
        "     de8: d10683ff     \tsub\tsp, sp, #0x1a0\n",
        1,
    ),
    (
        "x86-64 / GNU objdump",
        "x86_64",
        "0000000000001180 <pqcrystals_kyber768_ref_poly_tomsg>:\n"
        "    1180:\t55                   \tpush   %rbp\n"
        "    1185:\tf7 f1                \tdiv    %ecx\n"
        "    1187:\t48 f7 f6             \tdiv    %rsi\n",
        2,
    ),
    (
        "x86-64 / GNU objdump, idiv",
        "x86_64",
        "0000000000001180 <pqcrystals_kyber768_ref_poly_compress>:\n"
        "    1185:\tf7 fe                \tidiv   %esi\n",
        1,
    ),
    (
        "operands must not false-positive",
        "aarch64",
        "0000000100002000 <_some_function>:\n"
        "     100: aa0103f3     \tmov\tx19, x1\n"
        "     104: 91008029     \tadd\tx9, x1, #0x20\n",
        0,
    ),
]


def check_disassembly() -> list:
    failures = []
    for name, arch, disasm, expected in DISASM_CASES:
        findings = analyse(disasm, DIV_MNEMONICS[arch])
        total = sum(f["division_count"] for f in findings)
        if total != expected:
            failures.append(f"{name}: expected {expected} division(s), found {total}")
    return failures


def main() -> int:
    failures = []
    for symbol, expected in CASES:
        actual = classify(symbol)
        if actual != expected:
            failures.append((symbol, expected, actual))

    for symbol, expected, actual in failures:
        print(f"FAIL {symbol}: expected {expected}, got {actual}", file=sys.stderr)
    print(f"{len(CASES) - len(failures)}/{len(CASES)} classifier cases passed")

    disasm_failures = check_disassembly()
    for f in disasm_failures:
        print(f"FAIL {f}", file=sys.stderr)
    print(f"{len(DISASM_CASES) - len(disasm_failures)}/{len(DISASM_CASES)} "
          f"disassembly-parsing cases passed")

    return 1 if (failures or disasm_failures) else 0


if __name__ == "__main__":
    sys.exit(main())
