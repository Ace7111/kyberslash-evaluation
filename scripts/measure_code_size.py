#!/usr/bin/env python3
"""Code-size comparison between the vulnerable and patched reference revisions.

Why this exists. Section 3.12 splits mitigation evaluation into security effectiveness
against the evaluated mechanism and complete implementation-cost characterisation. The
performance half was measured with the leakage screen; this script supplies the code-size
half, which was previously outstanding.

The question is narrow and deliberately so: does removing the KyberSlash division
mechanism impose a material code-size cost under the tested build conditions? It is not a
claim about every build, workload or target.

What is measured, and the distinction that matters. Two levels are reported separately and
never mixed:

  object      poly.o and polyvec.o compiled from the two revisions. These are the two
              translation units the patch actually changes, so an object-level difference
              localises the cost to the modified code.
  executable  the linked test_kyber binary. This is what a deployment would ship, and it
              includes Keccak, the NTT and the test driver, none of which the patch touches.

Sections. On ELF the measured sections are .text and .rodata. On Mach-O the directly
equivalent sections are (__TEXT,__text) and (__TEXT,__const); both names are recorded in
the output so a reader can see which platform produced which figure. Nothing is renamed to
look like the other platform.

Both revisions are compiled with the same compiler, the same optimisation level and the
same flag list, differing only in the checked-out source. Every command line, the toolchain
version and the SHA-256 of every artefact measured are recorded.

Usage:
    python3 scripts/measure_code_size.py                      # gcc-16, -O2 -Os -Oz
    python3 scripts/measure_code_size.py --cc gcc-16 --opt -O2
    python3 scripts/measure_code_size.py --json-out results/processed/code_size.json
"""
import argparse, hashlib, json, pathlib, platform, re, shutil, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCES = ("kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c "
           "fips202.c symmetric-shake.c randombytes.c").split()
# The two translation units the KyberSlash patch modifies.
PATCHED_UNITS = ("poly.c", "polyvec.c")
REVISIONS = {"vulnerable": "kyber-vulnerable", "patched": "kyber-patched"}


def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def sections(path):
    """Return {logical_name: (platform_section_name, bytes)} for text and rodata."""
    out = {}
    if sys.platform == "darwin":
        rc, so, _ = run(["size", "-m", str(path)])
        if rc != 0:
            return out, so
        # Object files print "Section (__SEG, __sec): N"; linked images print
        # "Segment __SEG:" followed by "Section __sec: N". Handle both.
        seg = None
        for line in so.splitlines():
            mseg = re.match(r"\s*Segment (__\w+):", line)
            if mseg:
                seg = mseg.group(1); continue
            m2 = re.match(r"\s*Section \((__\w+), (__\w+)\): (\d+)", line)
            if m2:
                s_, sec, n = m2.group(1), m2.group(2), int(m2.group(3))
            else:
                m3 = re.match(r"\s*Section (__\w+): (\d+)", line)
                if not m3:
                    continue
                s_, sec, n = seg, m3.group(1), int(m3.group(2))
            if (s_, sec) == ("__TEXT", "__text"):
                out["text"] = (f"({s_},{sec})", n)
            elif (s_, sec) == ("__TEXT", "__const"):
                out["rodata"] = (f"({s_},{sec})", n)
        raw = so
    else:
        rc, so, _ = run(["size", "-A", str(path)])
        if rc != 0:
            return out, so
        for line in so.splitlines():
            f = line.split()
            if len(f) >= 2 and f[0] in (".text", ".rodata"):
                out[f[0].lstrip(".")] = (f[0], int(f[1]))
        raw = so
    out.setdefault("text", ("(absent)", 0))
    out.setdefault("rodata", ("(absent)", 0))
    return out, raw


def build(rev_dir, cc, opt, workdir, link):
    """Compile the corpus; return (objects, executable_or_None, commands, log)."""
    cmds, log, objs = [], [], {}
    flags = ["-w", opt, "-fomit-frame-pointer", "-DKYBER_K=3"]
    for src in SOURCES:
        obj = workdir / (src.replace(".c", ".o"))
        cmd = [cc, *flags, "-c", src, "-o", str(obj)]
        rc, so, se = run(cmd, cwd=rev_dir)
        cmds.append(" ".join(cmd))
        log.append(f"$ cd {rev_dir}\n$ {' '.join(cmd)}\nrc={rc}\n{so}{se}")
        if rc != 0:
            return None, None, cmds, "\n".join(log)
        objs[src] = obj
    exe = None
    if link:
        exe = workdir / "test_kyber"
        test_src = "test/test_kyber.c" if (rev_dir / "test" / "test_kyber.c").exists() else "test_kyber.c"
        cmd = [cc, *flags, *[str(o) for o in objs.values()], test_src, "-o", str(exe)]
        rc, so, se = run(cmd, cwd=rev_dir)
        cmds.append(" ".join(cmd))
        log.append(f"$ {' '.join(cmd)}\nrc={rc}\n{so}{se}")
        if rc != 0:
            exe = None
    return objs, exe, cmds, "\n".join(log)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cc", default="gcc-16")
    ap.add_argument("--opt", action="append", metavar="LEVEL",
                    help="repeatable, e.g. --opt=-O2 --opt=-Os (note the =)")
    ap.add_argument("--json-out", type=pathlib.Path)
    ap.add_argument("--raw-out", type=pathlib.Path)
    ap.add_argument("--no-link", action="store_true",
                    help="measure objects only, skipping the linked executable")
    args = ap.parse_args()
    if not args.opt:
        args.opt = ["-O2", "-Os", "-Oz"]

    rc, ver, se = run([args.cc, "--version"])
    toolchain = (ver or se).splitlines()[0] if (ver or se) else args.cc
    rc, sv, _ = run(["size", "--version"])

    record = {
        "question": "Does removal of the KyberSlash division mechanism impose a material "
                    "code-size cost under the tested build conditions?",
        "scope_note": "Bounded to the revisions, compiler, optimisation levels and platform "
                      "recorded here. Not a general code-size claim.",
        "host": {"platform": sys.platform, "machine": platform.machine(),
                 "release": platform.release(),
                 "object_format": "Mach-O" if sys.platform == "darwin" else "ELF"},
        "toolchain": {"cc": args.cc, "cc_version": toolchain,
                      "size_tool": (sv or "").splitlines()[0] if sv else "size"},
        "revisions": {}, "cells": [],
    }
    for label, name in REVISIONS.items():
        wt = ROOT / "worktrees" / name
        rc, h, _ = run(["git", "-C", str(wt), "rev-parse", "HEAD"])
        record["revisions"][label] = {"worktree": name, "commit": h.strip()}

    raw_log = []
    for opt in args.opt:
        built = {}
        for label, name in REVISIONS.items():
            rev_dir = ROOT / "worktrees" / name / "ref"
            wd = pathlib.Path(tempfile.mkdtemp(prefix=f"cs_{label}_{opt.lstrip('-')}_"))
            objs, exe, cmds, log = build(rev_dir, args.cc, opt, wd, not args.no_link)
            raw_log.append(f"\n{'='*78}\n{label} {opt}\n{'='*78}\n{log}")
            if objs is None:
                record["cells"].append({"optimisation": opt, "revision": label,
                                        "build_ok": False, "commands": cmds})
                built[label] = None
                continue
            entry = {"build_ok": True, "commands": cmds, "objects": {}, "executable": None}
            for unit in PATCHED_UNITS:
                secs, rawsz = sections(objs[unit])
                raw_log.append(f"\n--- size: {label} {opt} {unit} ---\n{rawsz}")
                entry["objects"][unit] = {
                    "path_measured": objs[unit].name, "sha256": sha256(objs[unit]),
                    "text_section": secs["text"][0], "text_bytes": secs["text"][1],
                    "rodata_section": secs["rodata"][0], "rodata_bytes": secs["rodata"][1]}
            if exe and exe.exists():
                secs, rawsz = sections(exe)
                raw_log.append(f"\n--- size: {label} {opt} test_kyber (linked) ---\n{rawsz}")
                entry["executable"] = {
                    "path_measured": "test_kyber", "sha256": sha256(exe),
                    "text_section": secs["text"][0], "text_bytes": secs["text"][1],
                    "rodata_section": secs["rodata"][0], "rodata_bytes": secs["rodata"][1]}
            built[label] = entry
            record["cells"].append({"optimisation": opt, "revision": label, **entry})
            shutil.rmtree(wd, ignore_errors=True)

        v, p = built.get("vulnerable"), built.get("patched")
        if v and p:
            cmp_ = {"optimisation": opt, "level": {}}
            for unit in PATCHED_UNITS:
                a, b = v["objects"][unit], p["objects"][unit]
                cmp_["level"][f"object:{unit}"] = {
                    "section_names": [a["text_section"], a["rodata_section"]],
                    "vulnerable": {"text": a["text_bytes"], "rodata": a["rodata_bytes"]},
                    "patched": {"text": b["text_bytes"], "rodata": b["rodata_bytes"]},
                    "delta_text": b["text_bytes"] - a["text_bytes"],
                    "delta_rodata": b["rodata_bytes"] - a["rodata_bytes"]}
            if v["executable"] and p["executable"]:
                a, b = v["executable"], p["executable"]
                cmp_["level"]["executable:test_kyber"] = {
                    "section_names": [a["text_section"], a["rodata_section"]],
                    "vulnerable": {"text": a["text_bytes"], "rodata": a["rodata_bytes"]},
                    "patched": {"text": b["text_bytes"], "rodata": b["rodata_bytes"]},
                    "delta_text": b["text_bytes"] - a["text_bytes"],
                    "delta_rodata": b["rodata_bytes"] - a["rodata_bytes"]}
            record.setdefault("comparisons", []).append(cmp_)

    print(f"host            : {record['host']['machine']} {record['host']['object_format']}")
    print(f"compiler        : {record['toolchain']['cc_version']}")
    print(f"vulnerable      : {record['revisions']['vulnerable']['commit'][:12]}")
    print(f"patched         : {record['revisions']['patched']['commit'][:12]}\n")
    for cmp_ in record.get("comparisons", []):
        print(f"{cmp_['optimisation']}")
        for lvl, d in cmp_["level"].items():
            print(f"  {lvl:<26} text {d['vulnerable']['text']:>7} -> {d['patched']['text']:>7}"
                  f"  ({d['delta_text']:+d})   rodata {d['vulnerable']['rodata']:>6} -> "
                  f"{d['patched']['rodata']:>6}  ({d['delta_rodata']:+d})")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(record, indent=1) + "\n")
        print(f"\nwrote {args.json_out}")
    if args.raw_out:
        args.raw_out.parent.mkdir(parents=True, exist_ok=True)
        args.raw_out.write_text("\n".join(raw_log) + "\n")
        print(f"wrote {args.raw_out}")


if __name__ == "__main__":
    main()
