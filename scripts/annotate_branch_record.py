#!/usr/bin/env python3
"""Add build provenance to a branch-screen JSON record.

Kept as a script rather than inlined in the workflow so that the provenance fields are
version-controlled and testable alongside everything else.

Usage: annotate_branch_record.py <record.json> <object_sha256> <flags> <cc> <src_dir> <param_set>
"""
import json, pathlib, subprocess, sys


def main():
    rec_path, sha, flags, cc, src_dir, param = sys.argv[1:7]
    p = pathlib.Path(rec_path)
    d = json.loads(p.read_text())

    def cap(cmd):
        r = subprocess.run(cmd, capture_output=True, text=True)
        return (r.stdout or r.stderr).strip()

    d["object_sha256"] = sha
    d["flags"] = flags
    d["compiler"] = cap([cc, "--version"]).splitlines()[0] if cap([cc, "--version"]) else cc
    d["revision_commit"] = cap(["git", "-C", src_dir, "rev-parse", "HEAD"])
    d["param_set"] = param
    d["objdump"] = cap(["objdump", "--version"]).splitlines()[0]
    p.write_text(json.dumps(d, indent=1) + "\n")
    print(f'{d["label"]}: {d["verdict"]} '
          f'({d["conditional_branches"]} branch(es), '
          f'{d["secret_dependent_branches"]} secret-dependent)')


if __name__ == "__main__":
    main()
