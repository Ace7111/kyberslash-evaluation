#!/usr/bin/env python3
"""Build and audit the RQ1/RQ3 targets, one archived record per cell.

Why this exists. The kyber lineage goes through build_matrix.py, which writes one
manifest row per (target x compiler x optimisation) cell. The RQ1 and RQ3 targets --
mlkem-native, CIRCL, liboqs, wolfSSL -- were audited by hand following
docs/reproduction_guide.md section 6, and only a summary row per project was archived
in results/processed/corpus_rq1_rq3.json. The procedure was reproducible but the
per-cell evidence was not retained, so the claim "clean in 12 of 12 configurations"
rested on a single archived record.

This script performs the same twelve builds the guide documents and writes one row per
cell, so the archive matches the claim.

Note on how the optimisation level is set. This is subtle and got it wrong once already.

test/mk/config.mk builds its own CFLAGS with `-O3` hard-coded, ending with `$(CFLAGS)`:

    CFLAGS := -Wall ... -O3 -fomit-frame-pointer -std=c99 ... $(CFLAGS)

Three consequences:

  * Passing CFLAGS on the MAKE COMMAND LINE overrides the whole assignment, discarding
    the required flags, and every build fails with a missing mlkem_native_config.h.
  * Putting the flag inside CC (`CC="gcc-16 -O0 -w"`) compiles as `gcc-16 -O0 -O3`.
    The last -O wins, so every build is -O3 no matter what was asked for. This produces
    twelve byte-identical binaries and the appearance of a twelve-configuration sweep
    that never varied anything.
  * Passing CFLAGS through the ENVIRONMENT expands into the trailing `$(CFLAGS)`, so it
    lands after `-O3` and wins. That is what this script does.

Verify with `CFLAGS=-O0 make func CC="gcc-16 -w" -n`: the compile line should end -O3 -O0.

Run: python3 scripts/audit_rq1_rq3.py
"""

import datetime
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "targets" / "mlkem-native"
BIN = SRC / "test" / "build" / "mlkem768" / "bin" / "test_mlkem768"
OUT = ROOT / "results" / "processed" / "build_matrix_mlkem_native.json"

COMPILERS = ["gcc-16", "clang"]
OPT_LEVELS = ["-O0", "-O1", "-O2", "-O3", "-Os", "-Oz"]
COMMIT = "61c831345d8fec5b2ba9d727dddb486b7cce512a"

sys.path.insert(0, str(ROOT / "scripts"))
from inspect_binary import (DIV_MNEMONICS, analyse, detect_arch,  # noqa: E402
                            disassemble)


def run(argv, **kw):
    """Run a command as an argument list, never through a shell.

    Every other script in this artefact invokes subprocess with a list, so no shell
    metacharacter in a compiler name, flag or path can be interpreted. This one briefly
    did not, and passing shell=True with an interpolated command string is precisely the
    pattern a constant-time audit tool should not contain.
    """
    return subprocess.run(argv, cwd=SRC, capture_output=True, text=True, **kw)


def main() -> int:
    if not SRC.exists():
        print(f"error: {SRC} not checked out; see docs/reproduction_guide.md §6",
              file=sys.stderr)
        return 2

    cells = []
    for cc in COMPILERS:
        for opt in OPT_LEVELS:
            run(["make", "clean"])
            # make accepts VAR=value as a positional argument, so CC needs no shell.
            build = run(["make", "func", f"CC={cc} -w"],
                        env={**os.environ, "CFLAGS": opt})
            built = build.returncode == 0 and BIN.exists()

            cell = {
                "experiment_id": f"EXP-mlkem-native_{cc}_{opt.lstrip('-')}_768",
                "target": "mlkem-native",
                "project": "pq-code-package/mlkem-native",
                "commit": COMMIT,
                "language": "C90",
                "arch": "aarch64",
                "compiler": cc,
                "optimisation": opt,
                "param_set": "768",
                "build_command": f'CFLAGS="{opt}" make func CC="{cc} -w"',
                "build_ok": built,
                "timestamp_utc": datetime.datetime.now(
                    datetime.timezone.utc).isoformat(timespec="seconds"),
            }

            if not built:
                # The evidence gate: a cell that fails to build yields no verdict.
                cell["gate_failed_at"] = "build"
                cell["build_stderr_tail"] = build.stderr.strip()[-400:]
                cells.append(cell)
                print(f"  {cc:<7} {opt:<4} BUILD FAILED")
                continue

            cell["binary_sha256"] = subprocess.run(
                ["shasum", "-a", "256", str(BIN)],
                capture_output=True, text=True, check=True).stdout.split()[0]

            func = subprocess.run([str(BIN)], capture_output=True, text=True)
            cell["functional_ok"] = func.returncode == 0
            if func.returncode != 0:
                cell["gate_failed_at"] = "functional_test"
                cells.append(cell)
                print(f"  {cc:<7} {opt:<4} FUNCTIONAL TEST FAILED")
                continue

            arch = detect_arch()
            findings = analyse(disassemble(BIN, "objdump"), DIV_MNEMONICS[arch])
            vulnerable = [f for f in findings if f["classification"] == "vulnerable"]
            cell["arch"] = arch
            cell["total_divisions"] = len(findings)
            cell["secret_dependent_divisions"] = len(vulnerable)
            cell["vulnerable_functions"] = sorted({f["function"] for f in vulnerable})
            cell["kyberslash_variants"] = sorted({f["variant"] for f in vulnerable
                                                  if f.get("variant")})
            cell["verdict"] = "vulnerable" if vulnerable else "clean"
            cell["findings"] = findings
            cells.append(cell)
            print(f"  {cc:<7} {opt:<4} ok   divisions={len(findings):<3} "
                  f"secret-dependent={len(vulnerable)}")

    OUT.write_text(json.dumps(cells, indent=1) + "\n")

    ok = sum(1 for c in cells if c.get("functional_ok"))
    clean = sum(1 for c in cells if c.get("secret_dependent_divisions") == 0)
    zero = sum(1 for c in cells if c.get("total_divisions") == 0)
    print(f"\n{len(cells)} cells -> {OUT.relative_to(ROOT)}")
    print(f"  built and passed functional test : {ok}/{len(cells)}")
    print(f"  zero secret-dependent divisions  : {clean}/{len(cells)}")
    print(f"  zero divisions of any kind       : {zero}/{len(cells)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
