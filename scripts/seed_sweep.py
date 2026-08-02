#!/usr/bin/env python3
"""Run the leakage screen across independent keys and summarise per-variant effects.

Motivation: a single key gives a misleading picture. KyberSlash1's effect is stable
in sign across keys, but KyberSlash2's is not -- its direction depends on the fixed
ciphertext, which depends on the key. Reporting either variant from one key, or
reporting only their sum, understates what is present.

Requires a harness binary built from an instrumented tree (see make_instrumented.py).
Each seed produces an independent keypair because the harness's randombytes() is
seeded deterministically.

Usage: seed_sweep.py <harness-binary> [--samples N] [--seeds 1 2 3 ...]
"""

import argparse
import csv
import json
import math
import statistics as st
import subprocess
import sys
from pathlib import Path

DEFAULT_SEEDS = [1, 2, 3, 7, 42, 99, 555, 12345, 31337, 20260801]
COLUMNS = ["ks1_cycles", "ks2_cycles", "modelled_cycles", "host_ns"]


def effect(rows, column):
    a = [float(r[column]) for r in rows if r["class"] == "0"]
    b = [float(r[column]) for r in rows if r["class"] == "1"]
    if len(a) < 2 or len(b) < 2:
        return None
    diff = st.mean(a) - st.mean(b)
    va, vb = st.variance(a), st.variance(b)
    denom = math.sqrt(va / len(a) + vb / len(b))
    t = diff / denom if denom else (math.inf if diff else 0.0)
    pooled = ((len(a) - 1) * va + (len(b) - 1) * vb) / (len(a) + len(b) - 2)
    d = diff / math.sqrt(pooled) if pooled > 0 else (math.inf if diff else 0.0)
    return {"difference": diff, "welch_t": t, "cohens_d": d}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("harness", type=Path)
    ap.add_argument("--samples", type=int, default=20000)
    ap.add_argument("--warmup", type=int, default=1000)
    ap.add_argument("--seeds", type=int, nargs="+", default=DEFAULT_SEEDS)
    ap.add_argument("--json-out", type=Path, default=None)
    args = ap.parse_args()

    if not args.harness.is_file():
        print(f"error: {args.harness} not found", file=sys.stderr)
        return 2

    results = []
    for seed in args.seeds:
        proc = subprocess.run(
            [str(args.harness), str(args.samples), str(args.warmup), str(seed)],
            capture_output=True, text=True, check=True,
        )
        rows = list(csv.DictReader(proc.stdout.splitlines()))
        entry = {"seed": seed, "samples": len(rows)}
        for column in COLUMNS:
            if rows and column in rows[0]:
                entry[column] = effect(rows, column)
        results.append(entry)

    header = f"{'seed':>10} {'ks1 diff':>10} {'ks1 d':>8} {'ks2 diff':>10} {'ks2 d':>8} {'sum diff':>10} {'sum d':>8}"
    print(header)
    print("-" * len(header))
    for e in results:
        print(f"{e['seed']:>10} "
              f"{e['ks1_cycles']['difference']:>10.2f} {e['ks1_cycles']['cohens_d']:>8.3f} "
              f"{e['ks2_cycles']['difference']:>10.2f} {e['ks2_cycles']['cohens_d']:>8.3f} "
              f"{e['modelled_cycles']['difference']:>10.2f} {e['modelled_cycles']['cohens_d']:>8.3f}")

    ks1 = [e["ks1_cycles"] for e in results]
    ks2 = [e["ks2_cycles"] for e in results]
    total = [e["modelled_cycles"] for e in results]

    ks2_negative = sum(1 for e in ks2 if e["difference"] < 0)
    # Worst-case understatement: how much smaller the aggregate effect is than the
    # larger of the two individual effects, for the key where that gap is widest.
    ratios = [abs(ks1[i]["cohens_d"]) / abs(total[i]["cohens_d"])
              for i in range(len(results)) if total[i]["cohens_d"]]
    summary = {
        "n_keys": len(results),
        "ks1_sign_consistent": all(e["difference"] > 0 for e in ks1),
        "ks1_d_range": [min(e["cohens_d"] for e in ks1), max(e["cohens_d"] for e in ks1)],
        "ks2_sign_consistent": all(e["difference"] > 0 for e in ks2)
                               or all(e["difference"] < 0 for e in ks2),
        "ks2_negative_count": ks2_negative,
        "ks2_d_range": [min(e["cohens_d"] for e in ks2), max(e["cohens_d"] for e in ks2)],
        "aggregate_d_range": [min(e["cohens_d"] for e in total),
                              max(e["cohens_d"] for e in total)],
        "ks1_over_aggregate_d_ratio_max": max(ratios) if ratios else None,
    }

    print()
    print(f"KyberSlash1 sign consistent across keys : {summary['ks1_sign_consistent']}")
    print(f"KyberSlash1 |d| range                   : "
          f"{summary['ks1_d_range'][0]:.2f} to {summary['ks1_d_range'][1]:.2f}")
    print(f"KyberSlash2 sign consistent across keys : {summary['ks2_sign_consistent']}"
          f"  ({ks2_negative}/{len(results)} negative)")
    print(f"KyberSlash2 d range                     : "
          f"{summary['ks2_d_range'][0]:.2f} to {summary['ks2_d_range'][1]:.2f}")
    print(f"Aggregate d range                       : "
          f"{summary['aggregate_d_range'][0]:.2f} to {summary['aggregate_d_range'][1]:.2f}")
    print(f"Worst ks1-vs-aggregate d ratio          : "
          f"{summary['ks1_over_aggregate_d_ratio_max']:.1f}x understatement")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(
            {"samples_per_seed": args.samples, "results": results, "summary": summary},
            indent=2) + "\n")
        print(f"\nWrote {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
