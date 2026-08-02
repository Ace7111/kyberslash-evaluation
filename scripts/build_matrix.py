#!/usr/bin/env python3
"""Build each (target x compiler x optimisation) cell, run its functional test, then
audit the binary for secret-dependent division.

Enforces the evidence gate from the methodology: a cell that fails to build or fails
its functional test yields no security verdict at all, rather than a silent pass.
Writes one manifest row per cell to results/processed/build_matrix.json.
"""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from inspect_binary import DIV_MNEMONICS, analyse, detect_arch, disassemble  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT / "targets" / "pq-crystals-kyber"
WORKTREES = ROOT / "worktrees"
BUILDS = ROOT / "results" / "builds"

KYBER_K = {"512": 1, "768": 3, "1024": 4}

SOURCES = [
    "kem.c", "indcpa.c", "polyvec.c", "poly.c", "ntt.c", "cbd.c",
    "reduce.c", "verify.c", "fips202.c", "symmetric-shake.c",
]


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def ensure_worktree(name: str, commit: str) -> Path:
    path = WORKTREES / name
    if not path.exists():
        WORKTREES.mkdir(parents=True, exist_ok=True)
        result = sh(["git", "worktree", "add", str(path), commit], cwd=REPO)
        if result.returncode != 0:
            raise RuntimeError(f"worktree add failed for {name}: {result.stderr}")
    return path


def build_cell(src_dir: Path, cc: str, opt: str, param: str, out: Path) -> tuple:
    """Compile the functional test binary. Returns (ok, command, stderr)."""
    out.parent.mkdir(parents=True, exist_ok=True)
    # kex.c exists only in pre-restructure revisions; include it when present.
    sources = list(SOURCES)
    if (src_dir / "kex.c").is_file():
        sources.insert(0, "kex.c")
    for extra in ("randombytes.c", "test_kyber.c"):
        if (src_dir / extra).is_file():
            sources.append(extra)
        elif (src_dir / "test" / extra).is_file():
            sources.append(f"test/{extra}")

    cmd = [cc, "-w", opt, "-fomit-frame-pointer", f"-DKYBER_K={KYBER_K[param]}",
           *sources, "-o", str(out)]
    result = sh(cmd, cwd=src_dir)
    return result.returncode == 0 and out.is_file(), " ".join(cmd), result.stderr


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", nargs="+",
                        default=["kyber-vulnerable", "kyber-patched"])
    parser.add_argument("--compilers", nargs="+", default=["gcc-16", "clang"])
    # Values here begin with "-", which argparse treats as a flag unless passed as
    # --opt-levels=-Os. Accepting bare names ("Os") as well removes the trap.
    parser.add_argument("--opt-levels", nargs="+",
                        default=["-O0", "-O1", "-O2", "-O3", "-Os", "-Oz"],
                        help="e.g. --opt-levels=-Os -O2, or --opt-levels Os O2")
    parser.add_argument("--param-set", default="768", choices=sorted(KYBER_K))
    parser.add_argument("--out", type=Path,
                        default=ROOT / "results" / "processed" / "build_matrix.json")
    args = parser.parse_args()

    # Normalise "Os" -> "-Os" so both spellings work.
    args.opt_levels = [o if o.startswith("-") else f"-{o}" for o in args.opt_levels]

    commits = json.loads((ROOT / "configs" / "commits.json").read_text())
    arch = detect_arch()
    rows = []

    for target in args.targets:
        if target not in commits:
            print(f"skip: {target} not in configs/commits.json", file=sys.stderr)
            continue
        src_dir = ensure_worktree(target, commits[target]["commit"]) / commits[target]["build_dir"]

        for cc in args.compilers:
            for opt in args.opt_levels:
                cell = f"{target}_{cc}_{opt.lstrip('-')}_{args.param_set}"
                binary = BUILDS / cell / "test_kyber"
                row = {
                    "experiment_id": f"EXP-{cell}",
                    "target": target,
                    "commit": commits[target]["commit"],
                    "patch_state": commits[target]["patch_state"],
                    "compiler": cc,
                    "optimisation": opt,
                    "param_set": args.param_set,
                    "arch": arch,
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }

                built, cmd, err = build_cell(src_dir, cc, opt, args.param_set, binary)
                row["build_command"] = cmd
                row["build_ok"] = built
                if not built:
                    # Gate: no functional or security verdict for a cell that did not build.
                    row["gate_failed_at"] = "build"
                    row["build_error"] = err.strip()[-400:]
                    rows.append(row)
                    print(f"[BUILD FAIL] {cell}")
                    continue

                row["binary_sha256"] = sha256(binary)
                functional = sh([str(binary)])
                row["functional_ok"] = functional.returncode == 0
                if not row["functional_ok"]:
                    row["gate_failed_at"] = "functional"
                    rows.append(row)
                    print(f"[FUNC FAIL]  {cell}")
                    continue

                findings = analyse(disassemble(binary, "objdump"), DIV_MNEMONICS[arch])
                vulnerable = [f for f in findings if f["classification"] == "vulnerable"]
                row["total_divisions"] = sum(f["division_count"] for f in findings)
                row["secret_dependent_divisions"] = sum(f["division_count"] for f in vulnerable)
                row["vulnerable_functions"] = [f["function"] for f in vulnerable]
                row["kyberslash_variants"] = sorted(
                    {f["kyberslash_variant"] for f in vulnerable}
                )
                row["verdict"] = "VULNERABLE" if vulnerable else "NO_SECRET_DEPENDENT_DIV"
                rows.append(row)
                print(f"[{row['verdict']:24}] {cell}  "
                      f"secret_div={row['secret_dependent_divisions']} "
                      f"total_div={row['total_divisions']}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(rows, indent=2) + "\n")
    print(f"\nWrote {len(rows)} cells to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
