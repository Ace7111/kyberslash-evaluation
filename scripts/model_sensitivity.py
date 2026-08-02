#!/usr/bin/env python3
"""Sensitivity analysis over the divider-latency model.

The modelled leakage figures depend on an assumed divider model (Cortex-M4: 2-12
cycles, ~1 quotient bit per cycle after setup). If the conclusions held only for
that exact parameterisation they would be an artefact of the assumption rather
than a property of the operands.

Each model is applied by REBUILDING the harness with different -D constants and
re-measuring. Re-costing already-collected totals would be invalid: the clamp is
non-linear and KyberSlash2 divisions do reach it (numerators up to ~2^22 over a
12-bit divisor give roughly 10 quotient bits, so cost sits at or near the 12-cycle
bound). Applying a clamp to a mean is not the mean of the clamped values.

Models:
  m4-default  min=2  max=12  per_bit=1   the model used throughout
  m4-wide     min=2  max=20  per_bit=1   clamp lifted above the operand range
  m4-narrow   min=2  max=6   per_bit=1   clamp biting hard
  m3-slow     min=2  max=24  per_bit=2   slower per-bit retirement, clamp lifted
  a7-like     min=3  max=20  per_bit=1   deeper setup cost
  flat        min=1  max=1   per_bit=0   every division costs 1 -- a CONTROL:
                                         division count is constant per
                                         decapsulation, so a non-zero effect here
                                         would indicate a counting bug, not leakage

Usage: model_sensitivity.py <instrumented-src-dir> [--samples N] [--seeds ...]
"""

import argparse
import csv
import json
import math
import statistics as st
import subprocess
import sys
from pathlib import Path

MODELS = {
    "m4-default": (2, 12, 1),
    "m4-wide":    (2, 20, 1),
    "m4-narrow":  (2, 6,  1),
    "m3-slow":    (2, 24, 2),
    "a7-like":    (3, 20, 1),
    "flat":       (1, 1,  0),
}

SOURCES = ["kem.c", "indcpa.c", "polyvec.c", "poly.c", "ntt.c", "cbd.c", "reduce.c",
           "verify.c", "fips202.c", "symmetric-shake.c", "timing_harness.c"]


def build(src: Path, model, cc: str, param: str) -> Path:
    lo, hi, per_bit = model
    out = src / f"th_{lo}_{hi}_{per_bit}"
    cmd = [cc, "-w", "-O2", f"-DKYBER_K={param}", "-I.",
           f"-DKS_M4_DIV_MIN_CYCLES={lo}u",
           f"-DKS_M4_DIV_MAX_CYCLES={hi}u",
           f"-DKS_M4_DIV_CYCLES_PER_BIT={per_bit}u",
           *SOURCES, "-o", str(out)]
    r = subprocess.run(cmd, cwd=src, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"build failed for {model}: {r.stderr[-400:]}")
    return out


def effect(a, b):
    if len(a) < 2 or len(b) < 2:
        return None
    diff = st.mean(a) - st.mean(b)
    va, vb = st.variance(a), st.variance(b)
    den = math.sqrt(va / len(a) + vb / len(b))
    t = diff / den if den else (math.inf if diff else 0.0)
    pooled = ((len(a) - 1) * va + (len(b) - 1) * vb) / (len(a) + len(b) - 2)
    d = diff / math.sqrt(pooled) if pooled > 0 else (math.inf if diff else 0.0)
    return {"difference": diff, "welch_t": t, "cohens_d": d}


def measure(binary: Path, samples: int, seed: int):
    r = subprocess.run([str(binary), str(samples), "1000", str(seed)],
                       capture_output=True, text=True, check=True)
    rows = list(csv.DictReader(r.stdout.splitlines()))
    out = {}
    for variant, col in (("ks1", "ks1_cycles"), ("ks2", "ks2_cycles")):
        a = [float(x[col]) for x in rows if x["class"] == "0"]
        b = [float(x[col]) for x in rows if x["class"] == "1"]
        out[variant] = effect(a, b)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("src", type=Path, help="instrumented source dir with timing_harness.c")
    ap.add_argument("--samples", type=int, default=20000)
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 42, 99, 20260801])
    ap.add_argument("--cc", default="gcc-16")
    ap.add_argument("--param-set", default="3")
    ap.add_argument("--json-out", type=Path, default=None)
    args = ap.parse_args()

    if not (args.src / "timing_harness.c").is_file():
        print(f"error: {args.src}/timing_harness.c not found", file=sys.stderr)
        return 2

    results = []
    for name, model in MODELS.items():
        binary = build(args.src, model, args.cc, args.param_set)
        for seed in args.seeds:
            m = measure(binary, args.samples, seed)
            results.append({"model": name, "params": {
                "min": model[0], "max": model[1], "per_bit": model[2]},
                "seed": seed, "ks1": m["ks1"], "ks2": m["ks2"]})

    hdr = f"{'model':>12} {'seed':>10} {'ks1 d':>9} {'ks1 t':>10} {'ks2 d':>9} {'ks2 t':>10}"
    print(hdr)
    print("-" * len(hdr))
    for e in results:
        print(f"{e['model']:>12} {e['seed']:>10} "
              f"{e['ks1']['cohens_d']:>9.3f} {e['ks1']['welch_t']:>10.1f} "
              f"{e['ks2']['cohens_d']:>9.3f} {e['ks2']['welch_t']:>10.1f}")

    real = [e for e in results if e["model"] != "flat"]
    flat = [e for e in results if e["model"] == "flat"]

    ks1_pos = all(e["ks1"]["difference"] > 0 for e in real)
    ks1_det = all(abs(e["ks1"]["welch_t"]) > 4.5 for e in real)
    by_seed = {}
    for e in real:
        by_seed.setdefault(e["seed"], []).append(e["ks2"]["difference"] > 0)
    ks2_sign_stable = all(len(set(v)) == 1 for v in by_seed.values())
    flat_null = all(abs(e["ks1"]["welch_t"]) < 4.5 and abs(e["ks2"]["welch_t"]) < 4.5
                    for e in flat)

    print()
    print(f"KyberSlash1 positive under every non-flat model : {ks1_pos}")
    print(f"KyberSlash1 detected (|t|>4.5) in every cell    : {ks1_det}")
    print(f"KyberSlash2 sign preserved across models        : {ks2_sign_stable}")
    print(f"flat control shows no effect (expected)         : {flat_null}")

    summary = {
        "ks1_positive_all_models": ks1_pos,
        "ks1_detected_all_models": ks1_det,
        "ks2_sign_stable_across_models": ks2_sign_stable,
        "flat_control_null": flat_null,
    }
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(
            {"samples": args.samples, "models": {k: {"min": v[0], "max": v[1],
             "per_bit": v[2]} for k, v in MODELS.items()},
             "results": results, "summary": summary}, indent=2) + "\n")
        print(f"\nWrote {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
