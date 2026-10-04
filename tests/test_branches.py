#!/usr/bin/env python3
"""Regression tests for scripts/inspect_branches.py.

Three kinds of case, in the order that matters:

1. Positive controls. A screen that cannot detect a known secret-dependent branch cannot
   support a negative finding. These compile a guarded side effect the optimiser cannot
   flatten into a conditional move, and require the screen to flag it.
2. Negative controls. The branchless mask the KyberSlash patch intends must come back clean.
3. Archived ground truth. The three disassemblies under results/disassembly/ were classified
   by hand in Section 5.5. The screen must agree with that manual classification, including
   the vectoriser pointer-alias check and the loop counters.

Case 4 is a parser regression. An earlier revision accepted an AArch64 instruction encoding
word such as "f100811f" as a mnemonic, because it begins with a letter. Every `cmp` so
encoded became invisible as a flag source, a stale flag source survived across a branch, and
the pre-fix aarch64 build was reported as carrying a secret-dependent branch -- contradicting
the correct manual result. That is the same field-layout error as defect D6, and it is pinned
here so it cannot return silently.
"""
import pathlib, shutil, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_branches as ib

CONTROLS = r'''
#include <stdint.h>
extern void sink(int16_t);
int  _lead(void) { return 0; }
void secret_guard(int16_t *out, const uint8_t *msg) {
    for (int i = 0; i < 32; i++)
        if ((msg[i] >> 0) & 1) sink(1665);
}
void mask_ok(int16_t *out, const uint8_t *msg) {
    for (int i = 0; i < 32; i++) {
        int16_t m = -(int16_t)((msg[i] >> 0) & 1);
        out[i] = m & 1665;
    }
}
'''

# (file, function, expected conditional branches, expected secret-dependent)
GROUND_TRUTH = [
    ("poly_frommsg_272125f_clang17_O2_aarch64.txt", "poly_frommsg", 3, 0),
    ("poly_frommsg_9b8d306_clang17_O2_aarch64.txt", "poly_frommsg", 1, 0),
    ("poly_frommsg_da52c4d_clang17_Oz_aarch64.txt", "poly_frommsg", 3, 0),
]


def screen_file(path, func, arch=None):
    raw = pathlib.Path(path).read_text()
    a = arch or ("x86_64" if "%r" in raw else "aarch64")
    body = ib.extract(raw.splitlines(), func)
    if not body:
        return None
    instrs = ib.parse(body, a)
    return ib.screen(instrs, a, set(ib.SECRET_ARG[a]))


def main():
    passed = failed = 0

    def check(name, cond, detail=""):
        nonlocal passed, failed
        if cond:
            passed += 1
        else:
            failed += 1
            print(f"  FAIL {name} {detail}")

    # --- 1 and 2: controls, compiled with whatever is available
    ccs = [c for c in ("gcc-16", "gcc", "clang") if shutil.which(c)]
    if not ccs:
        print("  SKIP controls: no C compiler found")
    else:
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="brtest_"))
        src = tmp / "controls.c"
        src.write_text(CONTROLS)
        for cc in ccs[:2]:
            for opt in ("-O1", "-O2", "-Os"):
                obj, dis = tmp / "c.o", tmp / "c.dis"
                if subprocess.run([cc, "-w", opt, "-c", str(src), "-o", str(obj)],
                                  capture_output=True).returncode != 0:
                    continue
                d = subprocess.run(["objdump", "-d", str(obj)], capture_output=True, text=True)
                dis.write_text(d.stdout)
                r = screen_file(dis, "secret_guard")
                check(f"positive control {cc} {opt}", r is not None and len(r[1]) >= 1,
                      "guarded secret branch not detected")
                r = screen_file(dis, "mask_ok")
                check(f"negative control {cc} {opt}", r is not None and len(r[1]) == 0,
                      "branchless mask wrongly flagged")
        shutil.rmtree(tmp, ignore_errors=True)

    # --- 3: archived ground truth from Section 5.5
    for fname, func, n_br, n_sec in GROUND_TRUTH:
        p = ROOT / "results" / "disassembly" / fname
        if not p.exists():
            print(f"  SKIP ground truth {fname}: not present")
            continue
        r = screen_file(p, func, "aarch64")
        check(f"ground truth {fname} branch count", r is not None and len(r[0]) == n_br,
              f"expected {n_br}, got {len(r[0]) if r else 'none'}")
        check(f"ground truth {fname} secret-dependent", r is not None and len(r[1]) == n_sec,
              f"expected {n_sec}, got {len(r[1]) if r else 'none'}")

    # --- 4: parser must never accept an encoding word as a mnemonic
    arm = ["    12ec: f100811f     \tcmp\tx8, #0x20",
           "    12f0: 54fffba1     \tb.ne\t0x1264 <f+0x480>"]
    got = ib.parse(arm, "aarch64")
    check("parser: ARM encoding word is not a mnemonic",
          [g[1] for g in got] == ["cmp", "b.ne"], f"got {[g[1] for g in got]}")
    x86 = ["  401136:\t0f b6 04 06          \tmovzbl (%rsi,%rax,1),%eax",
           "  40113a:\ta8 01                \ttest   $0x1,%al",
           "  40113c:\t74 08                \tje     401146 <f+0x20>"]
    got = ib.parse(x86, "x86_64")
    check("parser: x86 byte column is not a mnemonic",
          [g[1] for g in got] == ["movzbl", "test", "je"], f"got {[g[1] for g in got]}")
    # taint must begin at a load through the secret pointer, not at the pointer itself
    br, sec = ib.screen(ib.parse(x86, "x86_64"), "x86_64", {"rsi"})
    check("x86 taint: load through secret pointer then test is flagged", len(sec) == 1)
    ptr_only = ["  401100:\t48 39 f0             \tcmp    %rsi,%rax",
                "  401103:\t77 05                \tja     40110a <f+0xa>"]
    br2, sec2 = ib.screen(ib.parse(ptr_only, "x86_64"), "x86_64", {"rsi"})
    check("x86 taint: pointer-vs-pointer compare is not secret-dependent", len(sec2) == 0)

    total = passed + failed
    print(f"{passed}/{total} branch-screen cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
