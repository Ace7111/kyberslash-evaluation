#!/usr/bin/env python3
"""Consolidate the per-cell branch-screen records from the compiler-version matrix.

The workflow uploads one JSON record and one disassembly per cell. This collapses them into a
single machine-readable file keyed by (revision, compiler release, target, flags), which is
what the dissertation's table is generated from, and prints the summary for checking.

The two questions the consolidated record is meant to answer, and nothing more:

  Is the Clangover mechanism reproducible on x86-64 under the configurations the proof of
  concept reports, as a secret-dependent branch rather than merely a changed branch count?

  With the compiler release, source revision, parameter set and flags all held fixed, does
  the outcome change with the target architecture?

Usage:
    python3 scripts/consolidate_clangover.py <artefact_dir> \
        --json-out results/processed/clangover_compiler_matrix.json
"""
import argparse, json, pathlib, re, sys

REV = {"prefix": "272125f6acc8e8b6850fd68ceb901a660ff48196",
       "postfix": "9b8d30698a3e7449aeb34e62339d4176f11e3c6c"}


def release(compiler_string):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", compiler_string or "")
    return m.group(0) if m else "unknown"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("artefact_dir")
    ap.add_argument("--json-out", type=pathlib.Path)
    a = ap.parse_args()

    cells = []
    for p in sorted(pathlib.Path(a.artefact_dir).rglob("*.json")):
        try:
            d = json.loads(p.read_text())
        except Exception:
            continue
        if d.get("function") != "poly_frommsg":
            continue
        lbl = d.get("label", "")
        rev = lbl.split()[0] if lbl else "?"
        cells.append({
            "revision": rev,
            "revision_commit": d.get("revision_commit") or REV.get(rev, ""),
            "compiler": d.get("compiler", ""),
            "clang_release": release(d.get("compiler", "")),
            "target_arch": d.get("target_triple_arch") or d.get("arch"),
            "flags": d.get("flags", ""),
            "param_set": d.get("param_set", ""),
            "object_sha256": d.get("object_sha256", ""),
            "conditional_branches": d.get("conditional_branches"),
            "secret_dependent_branches": d.get("secret_dependent_branches"),
            "verdict": d.get("verdict"),
            "evidence_file": p.name.replace(".json", ".dis"),
            "secret_dependent_detail": [b for b in d.get("branches", [])
                                        if b.get("secret_dependent")],
        })
    if not cells:
        print("no branch-screen records found", file=sys.stderr)
        return 2

    rels = sorted({c["clang_release"] for c in cells})
    tgts = sorted({c["target_arch"] for c in cells})
    flags = sorted({c["flags"] for c in cells})

    def hits(rev, tgt, fl):
        m = [c for c in cells if c["revision"] == rev and c["target_arch"] == tgt
             and c["flags"] == fl]
        return m

    rec = {
        "experiment": "controlled compiler-version and architecture matrix for the "
                      "Clangover class",
        "method": "poly_frommsg is screened for a conditional branch whose flags derive from "
                  "memory addressed through the secret message pointer, or from a register "
                  "tainted by such a load. Branch counts are not treated as findings. The "
                  "screen carries its own positive control (tests/test_branches.py) and "
                  "reproduces the manual classification in Section 5.5 on the archived "
                  "aarch64 disassemblies.",
        "controls": {"architecture": "fixed per cell; aarch64 reached by cross-compiling with "
                                     "the same clang binary",
                     "source_revision": "pinned", "parameter_set": "ML-KEM-512 (KYBER_K=2)",
                     "varied": ["clang release", "optimisation flags", "target architecture"]},
        "clang_releases": rels, "target_architectures": tgts, "flag_settings": flags,
        "cell_count": len(cells), "cells": cells,
    }

    # invariance summary: does the verdict depend on the clang release?
    inv = {}
    for rev in sorted({c["revision"] for c in cells}):
        for tgt in tgts:
            for fl in flags:
                m = hits(rev, tgt, fl)
                if not m:
                    continue
                verdicts = {c["verdict"] for c in m}
                inv[f"{rev}|{tgt}|{fl}"] = {
                    "releases_tested": sorted({c["clang_release"] for c in m}),
                    "verdict_identical_across_releases": len(verdicts) == 1,
                    "verdict": sorted(verdicts),
                    "secret_dependent_branch_counts": sorted({c["secret_dependent_branches"]
                                                              for c in m})}
    rec["release_invariance"] = inv

    print(f"cells: {len(cells)}   releases: {rels}   targets: {tgts}\n")
    print(f"  {'revision':<9}{'target':<9}{'flags':<22}{'releases':<10}"
          f"{'branches':>9}{'secret':>8}  verdict")
    print("  " + "-" * 82)
    for rev in sorted({c['revision'] for c in cells}, reverse=True):
        for tgt in tgts:
            for fl in flags:
                m = hits(rev, tgt, fl)
                if not m:
                    continue
                br = sorted({c["conditional_branches"] for c in m})
                sd = sorted({c["secret_dependent_branches"] for c in m})
                vd = sorted({c["verdict"] for c in m})
                mark = "*" if len(vd) > 1 else " "
                print(f"  {rev:<9}{tgt:<9}{fl:<22}{len(m):<10}"
                      f"{','.join(map(str,br)):>9}{','.join(map(str,sd)):>8}{mark} {'/'.join(vd)}")
    disagree = [k for k, v in inv.items() if not v["verdict_identical_across_releases"]]
    print(f"\n  configurations whose verdict differs across clang releases: "
          f"{len(disagree)}{' -> ' + str(disagree) if disagree else ''}")
    if a.json_out:
        a.json_out.parent.mkdir(parents=True, exist_ok=True)
        a.json_out.write_text(json.dumps(rec, indent=1) + "\n")
        print(f"  wrote {a.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
