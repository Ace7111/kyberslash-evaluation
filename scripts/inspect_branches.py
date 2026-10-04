#!/usr/bin/env python3
"""Screen a disassembled function for *secret-dependent* conditional branches.

Why this exists. Section 5.5 establishes that a branch count is not a security finding:
the pre-fix poly_frommsg carries three conditional branches at Clang -O2 on aarch64, and
all three proved benign on inspection (one vectoriser pointer-alias check, two loop
counters). Any controlled Clangover experiment therefore needs to decide whether an emitted
branch depends on secret data, not merely that one exists.

What this does. It distinguishes two things that a naive taint model conflates. The secret
pointer argument holds an *address*, which is not itself secret; the bytes it points at are.
The screen therefore tracks a set of registers known to hold the secret pointer, and taints a
register only when it is loaded from memory addressed through one of them. Taint then
propagates through arithmetic and moves. A conditional branch is reported as secret-dependent
when the instruction that last set the flags it tests read a tainted register.

Keeping the two sets apart matters in practice: the vectoriser alias check in the pre-fix
aarch64 build compares the message pointer against another address (`ccmp x8, x1`). Treating
the pointer as secret data reports that comparison as a vulnerability, which it is not.

What this is not. This is a screening tool, not a proof. It is deliberately conservative in
one direction only: it reports candidates for inspection. Every run archives the
disassembly it analysed so a reader can confirm or reject each classification by hand, which
is how the aarch64 result in Section 5.5 was established. A clean screen is evidence of
absence only to the extent that the archived disassembly supports it.

Argument registers follow the platform ABI: on x86-64 SysV the second pointer argument of
poly_frommsg(poly *r, const uint8_t *msg) arrives in %rsi; on AArch64 AAPCS it arrives in x1.

Usage:
    objdump -d poly.o | python3 scripts/inspect_branches.py --function poly_frommsg
    python3 scripts/inspect_branches.py --function poly_frommsg --file dis.txt --json-out b.json
"""
import argparse, json, re, sys

X86_COND = re.compile(r"^j(?!mp)(n?[a-z]{1,3})$")
ARM_COND = re.compile(r"^(b\.[a-z]{2,3}|cbn?z|tbn?z)$")
# Instructions that set flags from their operands.
X86_FLAGSET = {"cmp", "cmpl", "cmpq", "cmpb", "cmpw", "test", "testb", "testl", "testq",
               "and", "andl", "andq", "andb", "or", "sub", "add", "shr", "sar", "shl"}
ARM_FLAGSET = {"cmp", "cmn", "tst", "subs", "adds", "ands", "ccmp"}

SECRET_ARG = {"x86_64": {"rsi", "esi", "sil"}, "aarch64": {"x1", "w1"}}


def norm_reg(r, arch):
    """Collapse register aliases to a canonical 64-bit-ish name."""
    r = r.strip().lstrip("%").lower()
    if arch == "x86_64":
        m = {"eax":"rax","ax":"rax","al":"rax","ebx":"rbx","bl":"rbx","ecx":"rcx","cl":"rcx",
             "edx":"rdx","dl":"rdx","esi":"rsi","sil":"rsi","edi":"rdi","dil":"rdi",
             "esp":"rsp","ebp":"rbp"}
        if r in m: return m[r]
        m2 = re.match(r"^r(\d+)[dwb]$", r)
        if m2: return "r"+m2.group(1)
        return r
    m3 = re.match(r"^w(\d+|zr)$", r)
    if m3: return "x"+m3.group(1)
    return r


# Byte column then mnemonic. The separator matters: objdump puts a tab (or two or more
# spaces) between the encoding and the mnemonic, and single spaces inside the encoding.
#
# Getting this wrong is not hypothetical. An earlier revision of this parser allowed the
# encoding to be read as the mnemonic, because an AArch64 instruction word such as
# "f100811f" begins with a letter. Every `cmp` so encoded was then invisible as a flag
# source, a stale flag source survived across a branch, and the pre-fix aarch64 build was
# reported as carrying a secret-dependent branch -- contradicting the manual inspection in
# Section 5.5, which is correct. The same field-layout mistake produced defect D6.
_ARM_WORD = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})(?:\t|\s{2,})\s*([a-z][a-z0-9._]*)\s*(.*)$")
_X86_BYTES = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)(?:\t|\s{2,})\s*([a-z][a-z0-9._]*)\s*(.*)$")


def parse(lines, arch):
    """Yield (addr, mnemonic, operand_string) for disassembly lines."""
    out = []
    for ln in lines:
        m = _ARM_WORD.match(ln) or _X86_BYTES.match(ln)
        if not m:
            continue
        mn = m.group(3)
        if re.fullmatch(r"[0-9a-f]{8}", mn):      # never accept an encoding word as a mnemonic
            continue
        out.append((m.group(1), mn, m.group(4).split("//")[0].split(";")[0].strip()))
    return out


def extract(lines, func):
    """Slice the disassembly of one function out of objdump output."""
    body, inside = [], False
    for ln in lines:
        if re.search(rf"<[^>]*{re.escape(func)}[^>]*>:\s*$", ln):
            inside = True; body.append(ln); continue
        if inside:
            if re.search(r"^[0-9a-f]+\s+<[^>]+>:\s*$", ln.strip()):
                break
            body.append(ln)
    return body


def regs_in(ops, arch):
    if arch == "x86_64":
        return {norm_reg(r, arch) for r in re.findall(r"%([a-z0-9]+)", ops)}
    return {norm_reg(r, arch) for r in re.findall(r"\b([wx]\d+|[wx]zr)\b", ops)}


def screen(instrs, arch, secret_regs):
    ptrs = set(secret_regs)   # registers holding the secret *address* (not secret data)
    tainted = set()           # registers holding secret *data*
    flags_src = None          # (mnemonic, operands, tainted?, regs)
    findings, branches = [], []
    for addr, mn, ops in instrs:
        base = mn.rstrip("bwlq") if arch == "x86_64" else mn
        used = regs_in(ops, arch)

        is_cond = bool(X86_COND.match(mn)) if arch == "x86_64" else bool(ARM_COND.match(mn))
        if is_cond:
            if arch == "aarch64" and (mn.startswith("cb") or mn.startswith("tb")):
                dep = bool(used & tainted)
                why = f"{mn} tests {sorted(used & tainted)}" if dep else f"{mn} tests {sorted(used)}"
            else:
                dep = bool(flags_src and flags_src[2])
                if not flags_src:
                    why = "no flag source seen"
                elif dep:
                    reg = sorted(flags_src[3] & tainted)
                    src = (f"on tainted register(s) {reg}" if reg
                           else "on memory addressed through the secret pointer")
                    why = f"flags from `{flags_src[0]} {flags_src[1]}` {src}"
                else:
                    why = f"flags from `{flags_src[0]} {flags_src[1]}`"
            branches.append({"addr": addr, "insn": f"{mn} {ops}".strip(),
                             "secret_dependent": dep, "reason": why})
            if dep:
                findings.append(branches[-1])
            continue

        fs = X86_FLAGSET if arch == "x86_64" else ARM_FLAGSET
        if base in fs or mn in fs:
            # On x86 a flag-setting instruction can carry a memory operand, so
            # `testb $0x1,(%rbx,%r14)` both loads the secret and sets the flags. Checking
            # register taint alone misses it entirely.
            mem_secret = False
            if arch == "x86_64":
                for mpart in re.findall(r"[^,]*\([^)]*\)", ops):
                    if any(norm_reg(r, arch) in ptrs or norm_reg(r, arch) in tainted
                           for r in re.findall(r"%([a-z0-9]+)", mpart)):
                        mem_secret = True
            flags_src = (mn, ops, bool(used & tainted) or mem_secret, used)

        # taint propagation: destination is last operand on x86 (AT&T), first on ARM
        if arch == "x86_64":
            parts = [p.strip() for p in ops.split(",")] if ops else []
            dst = parts[-1] if parts else None
            srcs = parts[:-1] if len(parts) > 1 else []
            mem_srcs = [p for p in srcs if "(" in p]
            # `lea` computes an address and never dereferences it, so a memory-form source
            # means pointer arithmetic, not a load. Treating it as a load taints the result
            # and turns the vectoriser's `cmpq %rcx,%rdi` alias check into a false positive.
            is_lea = base == "lea"
            loads_secret = (not is_lea) and any(
                norm_reg(r, arch) in ptrs for p in mem_srcs
                for r in re.findall(r"%([a-z0-9]+)", p))
            lea_from_ptr = is_lea and any(
                norm_reg(r, arch) in ptrs for p in mem_srcs
                for r in re.findall(r"%([a-z0-9]+)", p))
            src_tainted = any(norm_reg(r, arch) in tainted for p in srcs
                              for r in re.findall(r"%([a-z0-9]+)", p))
            src_ptr = any(norm_reg(r, arch) in ptrs for p in srcs
                          for r in re.findall(r"%([a-z0-9]+)", p) if "(" not in p)
            if dst and dst.startswith("%") and "(" not in dst:
                d = norm_reg(dst, arch)
                if loads_secret or src_tainted:
                    tainted.add(d); ptrs.discard(d)
                elif lea_from_ptr or (src_ptr and base in ("mov", "lea", "add")):
                    ptrs.add(d); tainted.discard(d)   # pointer arithmetic stays a pointer
                elif base in ("mov", "movz", "movs", "lea", "xor"):
                    tainted.discard(d); ptrs.discard(d)
        else:
            parts = [p.strip() for p in ops.split(",")] if ops else []
            if parts:
                d = norm_reg(parts[0], arch)
                rest = ",".join(parts[1:])
                rest_regs = {norm_reg(r, arch) for r in re.findall(r"\b([wx]\d+)\b", rest)}
                is_load = mn.startswith(("ldr", "ldur", "ldp"))
                addr_regs = {norm_reg(r, arch)
                             for r in re.findall(r"\[([wx]\d+)", rest)} | \
                            {norm_reg(r, arch) for r in re.findall(r"\[[wx]\d+,\s*([wx]\d+)", rest)}
                if is_load and (addr_regs & ptrs):
                    tainted.add(d); ptrs.discard(d)
                elif rest_regs & tainted:
                    tainted.add(d); ptrs.discard(d)
                elif (rest_regs & ptrs) and mn in ("mov", "add", "sub", "orr"):
                    ptrs.add(d); tainted.discard(d)
                elif mn in ("mov", "movz", "movk", "adrp", "add", "sub", "ldr", "ldrb",
                            "ldrsb", "ldrh", "ldur", "csel", "and", "orr", "eor", "lsl",
                            "lsr", "asr", "sbfx", "ubfx"):
                    tainted.discard(d); ptrs.discard(d)
    return branches, findings


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--function", required=True)
    ap.add_argument("--file", help="disassembly file; default stdin")
    ap.add_argument("--arch", choices=["x86_64", "aarch64"])
    ap.add_argument("--secret-reg", action="append",
                    help="override the register holding the secret pointer")
    ap.add_argument("--json-out")
    ap.add_argument("--label", default="")
    a = ap.parse_args()

    raw = open(a.file).read() if a.file else sys.stdin.read()
    lines = raw.splitlines()
    arch = a.arch or ("x86_64" if re.search(r"%r[a-z0-9]+", raw) else "aarch64")
    body = extract(lines, a.function)
    if not body:
        print(f"function {a.function} not found in disassembly", file=sys.stderr)
        sys.exit(2)
    instrs = parse(body, arch)
    secret = set(a.secret_reg or SECRET_ARG[arch])
    branches, findings = screen(instrs, arch, secret)

    rec = {"label": a.label, "function": a.function, "arch": arch,
           "secret_pointer_regs": sorted(secret),
           "model": "pointer registers tracked separately from secret data; taint begins at a load through a secret pointer", "instructions": len(instrs),
           "conditional_branches": len(branches),
           "secret_dependent_branches": len(findings),
           "verdict": "SECRET_DEPENDENT_BRANCH" if findings else "NO_SECRET_DEPENDENT_BRANCH",
           "branches": branches,
           "note": "Screening result. The archived disassembly is the evidence of record; "
                   "each classification is intended to be confirmable by inspection."}
    print(f"{a.label or a.function}: {rec['verdict']}  "
          f"({len(branches)} conditional branch(es), {len(findings)} secret-dependent)")
    for b in branches:
        print(f"   {'SECRET' if b['secret_dependent'] else 'benign'}  {b['addr']}: "
              f"{b['insn']:<34} {b['reason']}")
    if a.json_out:
        import pathlib
        pathlib.Path(a.json_out).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.json_out).write_text(json.dumps(rec, indent=1) + "\n")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
