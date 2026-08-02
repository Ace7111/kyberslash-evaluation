#!/usr/bin/env python3
"""Leakage analysis for the fixed-vs-random screening harness.

Reports, per measurement column, Welch's t, the raw difference in means, Cohen's d
and a bootstrap CI for the difference. Both the modelled-divider column and the
host-time column are analysed, so the divergence between them is quantified rather
than asserted.

Decision threshold (declared before data collection): |t| > 4.5.

Provenance of the threshold, because it is widely misattributed: 4.5 is the Test
Vector Leakage Assessment (TVLA) threshold associated with Goodwill, Jun, Jaffe and
Rohatgi (NIST non-invasive attack testing workshop, 2011). It is NOT dudect's own
default -- dudect defines t_threshold_moderate as 10, with the source comment
"Pankaj likes 4.5 but let's be more lenient", and t_threshold_bananas as 500.

Both are reported so a reader can apply either. Either way it is a screening
boundary, not a proof boundary, and a non-detection is bounded by the sample size
and resolution actually achieved.
"""

import argparse
import csv
import json
import math
import random
import statistics as stats
import sys
from pathlib import Path

T_THRESHOLD = 4.5           # TVLA (Goodwill et al. 2011)
T_THRESHOLD_DUDECT = 10.0   # dudect t_threshold_moderate
T_THRESHOLD_BANANAS = 500.0 # dudect t_threshold_bananas
BOOTSTRAP_RESAMPLES = 10000


def welch_t(a, b):
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return None
    va, vb = stats.variance(a), stats.variance(b)
    denom = math.sqrt(va / na + vb / nb)
    if denom == 0.0:
        return math.inf if stats.mean(a) != stats.mean(b) else 0.0
    return (stats.mean(a) - stats.mean(b)) / denom


def cohens_d(a, b):
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return None
    va, vb = stats.variance(a), stats.variance(b)
    pooled = ((na - 1) * va + (nb - 1) * vb) / (na + nb - 2)
    if pooled <= 0.0:
        return math.inf if stats.mean(a) != stats.mean(b) else 0.0
    return (stats.mean(a) - stats.mean(b)) / math.sqrt(pooled)


def welch_ci(a, b, z=1.959963985):
    """Analytic 95% CI for the difference in means (Welch, normal approximation).

    At the sample sizes used here (>=20,000 per class) the normal approximation and
    the percentile bootstrap agree to well within the reporting precision, and this
    costs microseconds rather than minutes. Use --bootstrap to compute the
    percentile bootstrap instead when a distribution-free interval is wanted.
    """
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return None, None
    diff = stats.mean(a) - stats.mean(b)
    se = math.sqrt(stats.variance(a) / na + stats.variance(b) / nb)
    return diff - z * se, diff + z * se


def bootstrap_ci(a, b, resamples=BOOTSTRAP_RESAMPLES, seed=12345):
    """Percentile bootstrap CI for the difference in means.

    random.choices is C-implemented, so resampling is done in one call per class
    rather than per observation.
    """
    rng = random.Random(seed)
    na, nb = len(a), len(b)
    diffs = []
    for _ in range(resamples):
        ra = rng.choices(a, k=na)
        rb = rng.choices(b, k=nb)
        diffs.append(sum(ra) / na - sum(rb) / nb)
    diffs.sort()
    return diffs[int(0.025 * len(diffs))], diffs[int(0.975 * len(diffs)) - 1]


def describe(values):
    return {
        "n": len(values),
        "mean": stats.mean(values) if values else None,
        "median": stats.median(values) if values else None,
        "stdev": stats.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values) if values else None,
        "max": max(values) if values else None,
        "distinct_values": len(set(values)),
    }


def analyse_column(rows, column, use_bootstrap=False):
    fixed = [float(r[column]) for r in rows if r["class"] == "0"]
    random_ = [float(r[column]) for r in rows if r["class"] == "1"]
    if not fixed or not random_:
        return None

    t = welch_t(fixed, random_)
    d = cohens_d(fixed, random_)
    if use_bootstrap:
        lo, hi = bootstrap_ci(fixed, random_)
        ci_method = f"percentile bootstrap ({BOOTSTRAP_RESAMPLES} resamples)"
    else:
        lo, hi = welch_ci(fixed, random_)
        ci_method = "Welch normal approximation"
    diff = stats.mean(fixed) - stats.mean(random_)

    detected = t is not None and abs(t) > T_THRESHOLD
    degenerate = stats.stdev(fixed) == 0.0 or stats.stdev(random_) == 0.0

    return {
        "column": column,
        "fixed_class": describe(fixed),
        "random_class": describe(random_),
        "difference_in_means": diff,
        "welch_t": t,
        "cohens_d": d,
        "ci95_difference": [lo, hi],
        "ci_method": ci_method,
        "threshold_tvla": T_THRESHOLD,
        "threshold_dudect_moderate": T_THRESHOLD_DUDECT,
        "threshold_dudect_bananas": T_THRESHOLD_BANANAS,
        "exceeds_dudect_moderate": t is not None and abs(t) > T_THRESHOLD_DUDECT,
        "exceeds_dudect_bananas": t is not None and abs(t) > T_THRESHOLD_BANANAS,
        "leakage_detected": detected,
        "degenerate_variance": degenerate,
        "note": (
            "One class has zero variance: the model is deterministic, so this is a "
            "noise-free signal magnitude rather than a hardware measurement."
            if degenerate else None
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_file", type=Path)
    parser.add_argument("--experiment-id", default=None)
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--bootstrap", action="store_true",
                        help="use percentile bootstrap CI instead of the Welch approximation")
    args = parser.parse_args()

    with args.csv_file.open() as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        print("error: no rows", file=sys.stderr)
        return 2

    report = {
        "experiment_id": args.experiment_id,
        "source": str(args.csv_file),
        "total_samples": len(rows),
        "columns": {},
    }
    for column in ("ks1_cycles", "ks2_cycles", "modelled_cycles", "host_ns"):
        if column in rows[0]:
            result = analyse_column(rows, column, use_bootstrap=args.bootstrap)
            if result:
                report["columns"][column] = result

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n")

    # Human-readable summary
    print(f"samples: {report['total_samples']}")
    for column, r in report["columns"].items():
        print(f"\n--- {column} ---")
        print(f"  fixed  : n={r['fixed_class']['n']:6d} "
              f"mean={r['fixed_class']['mean']:.3f} "
              f"sd={r['fixed_class']['stdev']:.3f} "
              f"distinct={r['fixed_class']['distinct_values']}")
        print(f"  random : n={r['random_class']['n']:6d} "
              f"mean={r['random_class']['mean']:.3f} "
              f"sd={r['random_class']['stdev']:.3f} "
              f"distinct={r['random_class']['distinct_values']}")
        print(f"  diff in means : {r['difference_in_means']:+.4f}")
        print(f"  95% CI        : [{r['ci95_difference'][0]:+.4f}, "
              f"{r['ci95_difference'][1]:+.4f}]  ({r['ci_method']})")
        t = r["welch_t"]
        print(f"  Welch t       : {t:.3f}" if math.isfinite(t) else "  Welch t       : inf")
        print(f"  Cohen's d     : {r['cohens_d']:.4f}" if r["cohens_d"] is not None
              and math.isfinite(r["cohens_d"]) else "  Cohen's d     : n/a")
        print(f"  DECISION      : "
              f"{'LEAKAGE DETECTED' if r['leakage_detected'] else 'no leakage detected'} "
              f"(|t| {'>' if r['leakage_detected'] else '<='} {T_THRESHOLD} TVLA)")
        print(f"  also vs dudect: moderate(10) "
              f"{'exceeded' if r['exceeds_dudect_moderate'] else 'not exceeded'}; "
              f"bananas(500) "
              f"{'exceeded' if r['exceeds_dudect_bananas'] else 'not exceeded'}")
        if r["note"]:
            print(f"  note          : {r['note']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
