# KyberSlash Reproducibility and Mitigation Evaluation Harness

Digital artefact for the MSc dissertation *Reproducibility and Mitigation Effectiveness of
KyberSlash-Class Timing Side-Channel Vulnerabilities in Open-Source ML-KEM Implementations*.

The harness acquires pinned ML-KEM/Kyber revisions, builds them across a compiler and
optimisation matrix, runs functional tests, and audits each binary for secret-dependent
variable-latency division — the KyberSlash mechanism.

## Status

Nine findings established (F1–F9 in `docs/findings.md`), covering all three research
questions, alongside seven instrument defects (D1–D7) recorded in the same file:

- Vulnerable revision emits secret-dependent division in 4 of 12 build configurations;
  patched revision in 0 of 12. GCC and Clang disagree about which optimisation levels are
  unsafe.
- mlkem-native v1.2.0 (FIPS 203) has zero secret-dependent divisions in 12 of 12
  configurations (RQ1). Four of those cells contain incidental divisions, in Keccak,
  rejection sampling and the test driver; per-function attribution is what separates them.
- CIRCL (Go) and wolfSSL (C) are both clean as shipped, by techniques distinct from the
  reference patch and from each other (RQ3). wolfSSL's documented `CONV_WITH_DIV` option
  at `-Os` restores 48 secret-dependent divisions (F9).
- liboqs is clean but vendors mlkem-native, so it is not independent evidence. Four
  independent codebases were evaluated: pq-crystals, mlkem-native, CIRCL and wolfSSL.
- Apple M1's divider is constant-latency, so the mechanism can be present with no
  observable host-level signal.
- KyberSlash2's leakage *direction* depends on the key — negative in 4 of 10 keys tested —
  so aggregating the two variants understates KyberSlash1 by a key-dependent amount, up to
  11.6×. Measure them separately.
- The mechanism reproduces on x86-64 as well as aarch64 (F8). The overlapping GCC settings
  agree: `-Os` emits on both, `-O2` is clean on both.
- Clangover was not reproduced on aarch64; a bounded negative. CVE-2024-37880 identifies
  affected LLVM Clang versions and does not establish an architectural boundary; the
  published proof of concept reports reproduction on at least the x86 ISA. x86-64 was used
  here only for the supplementary KyberSlash binary audit — no controlled Clangover
  reproduction was attempted on it.

## Quick start

```sh
# 1. Record the host and toolchain state (do this per measurement session)
./environment/system_manifest.sh

# 2. Fetch the upstream corpus
git clone https://github.com/pq-crystals/kyber.git targets/pq-crystals-kyber

# 3. Run the build + functional + binary-audit matrix
python3 scripts/build_matrix.py

# 4. Audit a single binary
python3 scripts/inspect_binary.py results/builds/<cell>/test_kyber
```

## Layout

| Path | Contents |
| --- | --- |
| `configs/targets.yaml` | Pinned corpus with provenance, vulnerable sites, planned additions |
| `configs/commits.json` | Machine-readable commit pins consumed by `build_matrix.py` |
| `environment/system_manifest.sh` | Host, CPU and toolchain capture |
| `scripts/inspect_binary.py` | Disassembles a binary, attributes divisions to functions, classifies them |
| `scripts/build_matrix.py` | Drives worktree → build → functional test → binary audit per cell |
| `scripts/make_instrumented.py` | Routes runtime divisions through per-variant counting wrappers |
| `scripts/analyse_results.py` | Welch t, Cohen's d, confidence intervals |
| `scripts/seed_sweep.py` | Repeats the leakage screen across independent keys |
| `scripts/model_sensitivity.py` | Rebuilds under six divider models and re-measures |
| `scripts/make_figure_5_1.py` | Generates Figure 5.1 from the archived sweep |
| `scripts/audit_rq1_rq3.py` | Per-cell build and audit for the mlkem-native matrix |
| `scripts/render_figures.sh`, `svg_inline_labels.py` | Mermaid rendering with a text-presence guard |
| `scripts/make_presentation_figures.py` | Two presentation-only charts from `results/processed/` |
| `scripts/udiv_latency.c`, `udiv_ecore.c` | Host divider characterisation |
| `harness/` | Divider model and fixed-vs-random timing harness |
| `tests/test_classify.py` | 31 classifier cases and 4 disassembly-parsing cases |
| `.github/workflows/` | CI binary audit, with the vulnerable revision as a positive control |
| `results/raw/` | Original observations with SHA-256 checksums |
| `results/processed/` | Per-cell manifests and analyses as JSON |
| `results/figures/` | Dissertation figures 2.1, 2.2, 4.1 and 5.1, plus two talk-only charts |
| `results/disassembly/` | Archived disassembly for the Clangover check |
| `results/logs/` | System manifests; x86-64 CI toolchain provenance; wolfSSL procedure validation |
| `docs/findings.md` | Experimental findings F1–F9 and instrument defects D1–D7 |
| `docs/reproduction_guide.md` | Clean host to published tables |
| `LICENSE`, `CITATION.cff` | MIT, with third-party notes; citation metadata |

## Continuous integration

`.github/workflows/constant-time-audit.yml` runs the binary audit on every push, on pull
requests, and weekly — the schedule matters because a toolchain update can change code
generation without the source moving.

It is built so that a passing run means something:

- the classifier regression tests gate every other job, since an auditor not shown to
  detect a known positive has not been shown to work;
- the known-vulnerable revision runs as a **positive control**, and the job fails if it is
  ever reported clean;
- incidental divisions do not fail the build, because a check that rejected correctly
  patched binaries would be switched off rather than fixed.

## Evidence gates

A cell yields a security verdict only if it clears the preceding gates. A build failure or
functional failure produces `gate_failed_at` and **no** leakage verdict, rather than a
silent pass. This mirrors the methodology's requirement that no security or performance
conclusion be drawn from a cell that failed correctness.

## Classification rule

Divisions are only reported as KyberSlash findings when they occur in functions whose
operands are secret-dependent:

| Function | Variant |
| --- | --- |
| `poly_tomsg` / `CompressMessageTo` | KyberSlash1 (message decoding in PKE decryption) |
| `poly_compress` / `CompressTo` | KyberSlash2 (compression during re-encryption) |
| `polyvec_compress` | KyberSlash2 |

Matching is by anchored regex, not exact name, so it works across pq-crystals,
mlkem-native (`_PQCP_MLKEM_NATIVE_MLKEM768_*`, plus `_d4`/`_d10`/`_du` width variants)
and CIRCL's Go method symbols. `decompress` is excluded: it operates on public input.

Divisions elsewhere — Keccak buffer arithmetic, rejection-sampling loop counters — are
classified `incidental` and must not be counted as leakage. The patched builds retain
incidental divisions while carrying zero secret-dependent ones; conflating the two would
misreport the patch as ineffective.

## Scope and safety

All experiments run on researcher-owned hardware using synthetic keys generated for the
experiment. No third-party or publicly reachable ML-KEM service is tested. Conducted under
Manchester Metropolitan University EthOS approval (number recorded in the dissertation).

## Interpreting negative results

`NO_SECRET_DEPENDENT_DIV` means no secret-dependent variable-latency division was found in
that binary by this method, on this architecture. It is a bounded empirical result, not a
proof of constant-time behaviour.
