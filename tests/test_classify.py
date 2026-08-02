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
from inspect_binary import classify  # noqa: E402

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


def main() -> int:
    failures = []
    for symbol, expected in CASES:
        actual = classify(symbol)
        if actual != expected:
            failures.append((symbol, expected, actual))

    for symbol, expected, actual in failures:
        print(f"FAIL {symbol}: expected {expected}, got {actual}", file=sys.stderr)

    print(f"{len(CASES) - len(failures)}/{len(CASES)} classifier cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
