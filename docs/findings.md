# Findings

All figures reproducible via `docs/reproduction_guide.md`. Raw data in `results/raw/`
with SHA-256 checksums.

---

## F1. Positive control: KyberSlash code generation reproduced

**Experiment.** 24 cells: 2 revisions of `pq-crystals/kyber` × {GCC 16.1.0, Apple Clang
17.0.0} × {-O0, -O1, -O2, -O3, -Os, -Oz}, ML-KEM-768, Apple M1 (aarch64, macOS 25.3.0).
All 24 built and passed the upstream functional test.

| Revision | Commit | State |
| --- | --- | --- |
| vulnerable | `a621b8dde405cc507cbcfc5f794570a4f98d69cc` | both `/KYBER_Q` sites present |
| patched | `272125f6acc8e8b6850fd68ceb901a660ff48196` | KyberSlash1 + 2 fixed |

**Result.** Secret-dependent `udiv` in 4 of 12 vulnerable cells, 0 of 12 patched.

| Compiler | -O0 | -O1 | -O2 | -O3 | -Os | -Oz |
| --- | --- | --- | --- | --- | --- | --- |
| GCC 16.1.0 (vulnerable) | – | – | – | – | **VULN** | **VULN** |
| Clang 17.0.0 (vulnerable) | **VULN** | – | – | – | – | **VULN** |
| GCC / Clang (patched) | – | – | – | – | – | – |

Divisions localise to exactly three functions: `poly_tomsg` (KyberSlash1),
`poly_compress` and `polyvec_compress` (KyberSlash2).

**Two observations.**

1. **The compilers disagree about which levels are unsafe.** GCC emits at `-Os`/`-Oz`;
   Clang at `-Oz`/`-O0` but not `-Os`. "Avoid `-Os`" would protect the GCC build and
   leave three configurations exposed. Direct RQ2 evidence.
2. **Patched builds still contain divisions** — 4 each at `-Os`/`-Oz`, in Keccak and
   `gen_matrix`. A "does the binary contain a division?" check reports a correctly
   patched build as vulnerable. Function-level attribution is load-bearing.

---

## F2. Apple M1 `udiv` is data-independent

**Experiment.** Serial dependent chain of 2,000,000 `udiv`, operands spanning the range
over which an early-terminating divider varies most. Best-of-five, repeated sessions,
both core types.

| Operands | Quotient width | Run 1 (ns) | Run 2 (ns) |
| --- | --- | --- | --- |
| `7 / 3` | 2 bits | 2.817 | 2.811 |
| `6656 / 3329` | 2 bits | 2.834 | 2.819 |
| `0xFFFFFFFF / 0xFFFF` | 16 bits | 2.969 | 2.969 |
| `0xFFFFFFFF / 1` | 32 bits | 2.819 | 2.812 |

Best case (2-bit quotient) and worst case (32-bit quotient) are indistinguishable —
under one cycle at ≈3.2 GHz. Identical on efficiency cores.

**Consequence.** The M1 is valid for build, binary audit and functional testing, but
cannot host timing-based attack reproduction. Compare the KyberSlash FAQ's documented
variable dividers (AMD Zen 2, SiFive U74).

---

## F3. Leakage measured on commodity hardware; KyberSlash2's direction is key-dependent

The operands reaching the division are secret-dependent regardless of host divider speed.
The harness therefore records a modelled Cortex-M4 divider cost *and* real host time per
decapsulation, counting the two variants separately. Key generation is deterministic from
the seed, so these figures reproduce exactly.

**Canonical run — vulnerable `a621b8d`, 40,000 samples, GCC 16.1.0 `-O2`, ML-KEM-768,
seed 20260801:**

| Column | Fixed mean | Random mean | Difference | 95% CI | Welch t | Cohen's d | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ks1_cycles` | 736.29 | 677.83 | **+58.46** | [+58.35, +58.57] | **1005.97** | **9.98** | detected |
| `ks2_cycles` | 9563.71 | 9541.77 | **+21.95** | [+21.33, +22.56] | **70.05** | **0.70** | detected |
| `modelled_cycles` | 10300.00 | 10219.59 | +80.41 | [+79.78, +81.03] | 252.86 | 2.51 | detected |
| `host_ns` | 50816.86 | 50792.87 | +23.99 | [−21.91, +69.90] | 1.02 | 0.010 | **not detected** |

**Patched `272125f`, same seed:** exactly zero on all three modelled columns; `host_ns`
t = 0.27, not detected.

Call counts: 256 KyberSlash1 and 1024 KyberSlash2 divisions per decapsulation
(vulnerable); zero (patched).

### The single-key result is misleading — sweep across 10 independent keys

`scripts/seed_sweep.py`, 20,000 samples per key:

| Seed | ks1 diff | ks1 d | ks2 diff | ks2 d | sum diff | sum d |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | +63.48 | 10.83 | +52.37 | 1.67 | +115.85 | 3.62 |
| 2 | +53.58 | 9.09 | +45.40 | 1.47 | +98.98 | 3.14 |
| 3 | +51.51 | 8.86 | +66.16 | 2.13 | +117.66 | 3.72 |
| 7 | +46.56 | 7.97 | +25.61 | 0.82 | +72.17 | 2.26 |
| 42 | +70.57 | 11.97 | **−6.25** | −0.20 | +64.33 | 2.02 |
| 99 | +66.58 | 11.34 | **−35.60** | −1.14 | +30.97 | **0.98** |
| 555 | +74.38 | 12.76 | +11.39 | 0.36 | +85.77 | 2.69 |
| 12345 | +74.60 | 12.74 | **−18.23** | −0.58 | +56.37 | 1.76 |
| 31337 | +69.50 | 11.84 | **−12.60** | −0.40 | +56.90 | 1.79 |
| 20260801 | +58.46 | 9.98 | +21.73 | 0.69 | +80.19 | 2.51 |

**Findings.**

1. **KyberSlash1 is stable and large.** Positive in all 10 keys, |d| between 7.97 and
   12.76. It is detected overwhelmingly regardless of key.
2. **KyberSlash2's *direction* depends on the key** — negative in 4 of 10, with d ranging
   from −1.14 to +2.13. Mechanistically this is expected: class 0 is one *valid*
   ciphertext whose re-encryption reproduces it, while class 1 is random bytes that
   almost always take the implicit-rejection path, so which class compresses larger
   values depends on the particular valid ciphertext, hence on the key.
3. **Aggregating the two understates the leak, sometimes severely.** Because the sum
   mixes a stable large effect with a variable one, aggregate d ranges only 0.98 to 3.72.
   In the worst key observed (seed 99) KyberSlash1 alone gives d = 11.34 while the
   aggregate gives d = 0.98 — an **11.6× understatement**.

**Consequence for leakage-test design.** A fixed-versus-random test over whole-operation
timing still detects the leak here, but at a small fraction of the available sensitivity,
and how small depends on the key it happens to use. Where the leaking sites are known,
instrument them separately; where they are not, vary the key and report the distribution
rather than a single run.

**Correction.** An earlier version of this document reported that the two variants "leak
in opposite directions" based on a single key. That was an over-generalisation: the
opposition occurs for some keys and not others. The superseded figures (+54.60 / −37.05,
d = 9.37 / −1.19) came from a non-deterministic run and should not be cited.

**Status of the modelled column.** A simulation under a declared model
(`harness/ks_instrument.h`), not a hardware measurement, and labelled as such everywhere.

---

## F3b. Sensitivity to the divider model

The modelled figures depend on an assumed divider. If the conclusions held only for one
parameterisation they would be an artefact of the assumption. `scripts/model_sensitivity.py`
rebuilds the harness under six models and re-measures — re-costing collected totals would
be invalid, because the clamp is non-linear.

| Model | min | max | cycles/bit | Purpose |
| --- | --- | --- | --- | --- |
| `m4-default` | 2 | 12 | 1 | the model used throughout |
| `m4-wide` | 2 | 20 | 1 | clamp lifted above the operand range |
| `m4-narrow` | 2 | 6 | 1 | clamp biting hard |
| `m3-slow` | 2 | 24 | 2 | slower per-bit retirement |
| `a7-like` | 3 | 20 | 1 | deeper setup cost |
| `flat` | 1 | 1 | 0 | **control** — every division costs 1 |

**Results** (20,000 samples, 4 keys):

| Model | ks1 d range | ks2 d range | ks2 sign changes vs default |
| --- | --- | --- | --- |
| `m4-default` | 9.98 – 11.97 | −1.14 to +1.67 | — |
| `m4-wide` | 9.98 – 11.97 | −1.14 to +1.67 | none (identical) |
| `m3-slow` | 9.98 – 11.97 | −1.14 to +1.67 | none (identical) |
| `a7-like` | 9.98 – 11.97 | −1.14 to +1.67 | none (identical) |
| `m4-narrow` | 9.98 – 11.97 | −0.12 to +1.95 | **2 of 4 keys flip sign** |
| `flat` | 0.00 | 0.00 | n/a (control) |

**Findings.**

1. **KyberSlash1 is model-independent.** Positive and detected (|t| 710–850) under every
   non-control model and every key. Its conclusion does not rest on the model choice.
2. **The 12-cycle clamp never binds under the defaults.** `m4-wide` (max 20) reproduces
   `m4-default` exactly, so no division exceeds 12 cycles. The widest case —
   `polyvec_compress` at d=10, a ~22-bit numerator over a 12-bit divisor — costs exactly
   12, reaching the bound without crossing it. `m3-slow` and `a7-like` are also identical
   because Cohen's d is scale-invariant and neither changes the ordering.
3. **KyberSlash2's sign is sensitive to a binding clamp.** Under `m4-narrow` (max 6) the
   clamp does bind, and two of four keys flip sign. KyberSlash2's direction therefore
   depends on both the key and the divider's saturation behaviour, reinforcing F3: it
   should not be reported from a single key or a single assumed model.
4. **The flat control is exactly zero**, as it must be — division *count* is constant per
   decapsulation (256 and 1024), so a non-zero result here would indicate a counting bug
   rather than leakage. It confirms the measured effect is latency-driven.

---

## F4. RQ1 — contemporary FIPS 203: mlkem-native clean in 12/12

mlkem-native v1.2.0 (`61c831345d8fec5b2ba9d727dddb486b7cce512a`), built across the same
matrix. All 12 cells built and passed functional tests. All contained **zero divisions of
any kind** — not merely zero secret-dependent ones.

Source is consistent: compression is computed by multiply-shift with documented magic
constants (`20159 == round(2^26 / MLKEM_Q)`), and every textual match for division by the
modulus is either a comment or a CBMC `ensures(...)` contract, i.e. specification rather
than executed code.

The project additionally documents CBMC memory/type-safety verification for its C and
HOL-Light functional-correctness proofs with verified secret-independent timing for its
AArch64 and x86_64 assembly. Those are project claims; this study independently verified
only binary-level absence of division.

---

## F5. RQ3 — CIRCL (Go) clean, via a *different* mitigation

CIRCL (`df9fbeabf921471216232de66f0392196dcdc37c`) built, passed an ML-KEM-768 round trip,
and contained **zero secret-dependent divisions**. Of its 43 divisions, 41 are in the Go
runtime and standard library (garbage collection, map and string handling) and 2 are in
`crypto/internal/fips140/aes.expandKeyGeneric` — Go's AES key expansion, not ML-KEM code.
None is in CIRCL's ML-KEM implementation.
The compression symbols survive in the binary (`(*Poly).CompressTo`, `(*Vec).CompressTo`),
so the null result reflects their contents rather than inlining.

Notably CIRCL does not copy the reference fix:

- `CompressTo` — multiply-shift, `(x·315)>>20` for d ∈ {4,5}, 20642679/2³⁶ for
  d ∈ {10,11}. The source documents that the former is deliberately inexact but close
  enough to give the correct compressed output.
- `CompressMessageTo` — a branchless sign-bit range test exploiting that Compress_q(x,1)
  is 1 exactly on {833,…,2496}. No multiply-shift at all.

Three implementations, three technically distinct solutions. Agreement is convergent
evidence, not shared ancestry.

---

## F6. RQ2 — Clangover does not reproduce on aarch64 (bounded negative)

Pre-fix `272125f` versus fixed `9b8d306` (the commit named in CVE-2024-37880), Clang
17.0.0, ML-KEM-512, `poly_frommsg` disassembly compared.

| Flags | Pre-fix branches | Post-fix branches |
| --- | --- | --- |
| -O0 / -O1 / -Os | 2 | 2 |
| -O2 | 3 | 1 |
| -O3 | 2 | 1 |

The `-O2`/`-O3` gap looks like a regression and is not. Inspecting every branch: one
`b.hi` guarding a vectoriser pointer-alias check (`cmp x9, x0` / `ccmp x8, x1` — comparing
addresses) and two `b.ne` loop counters (`cmp x8, #0x20`). The scalar path keeps the
intended branchless mask:

```asm
ldrb  w11, [x1, x8]        ; load message byte
sbfx  w11, w11, #0, #1     ; sign-extend bit 0 -> mask
and   w11, w11, w10        ; mask & 1665
```

CVE-2024-37880 specifies the **x86 ISA** with Clang 15–18. This is a bounded negative on a
platform the CVE does not claim to affect; it neither confirms nor challenges it.
Disassemblies archived in `results/disassembly/`.

**Methodological note:** had the branch count been reported without inspecting each
branch, this would have been a false positive. A differential metric is not a finding
until the mechanism is identified.

---

## F6b. liboqs vendors mlkem-native — not independent evidence

liboqs (`9d20051143544daa348bc0bbdcef5ef121e385d3`, 2026-07-28) was built at ML-KEM-768
with GCC 16.1.0, passed a functional round trip, and contains **zero divisions of any
kind**.

The null result is real but carries no independent weight. liboqs does not implement
ML-KEM itself — it vendors mlkem-native in nine directories:

```
src/kem/ml_kem/mlkem-native_ml-kem-{512,768,1024}_{ref,aarch64,x86_64}/
```

referenced directly from `src/kem/ml_kem/CMakeLists.txt`. The only textual match for
division by the modulus in the vendored code is a compile-time constant expression in
`sampling.c` (a buffer-size calculation), not a runtime division.

**Why it matters.** The planning documents list liboqs as an "essential" RQ1 target and
the approved Terms of Reference treat it as *the* reference implementation. Both
assumptions are wrong in the same way: auditing liboqs measures mlkem-native. Reporting
both as clean would be reporting one implementation twice, which is exactly the
overcounting the provenance rule exists to prevent.

The practical consequence is that the ML-KEM implementation ecosystem is more concentrated
than its project list suggests. Counting projects that appear unaffected overstates the
breadth of the evidence.

**Build note.** Configure with `-DOQS_USE_OPENSSL=OFF` for a standalone static link;
otherwise `liboqs.a` requires libcrypto and the probe fails at link time on `_CRYPTO_free`.

---

## F7. The *current* reference implementation is clean (RQ2, as worded)

F1 and F6 both concern historical revisions. RQ2 asks about the **current** reference
implementation, so `da52c4d60a73d745cabdf70829eb1e6a64ccce2f` (HEAD of `main`, 2026-07-28)
was audited on the same matrix.

**Division:** 0 secret-dependent divisions in 12 of 12 configurations. All four `/KYBER_Q`
sites survive only as comments beside their multiply-shift replacements. Incidental
divisions remain (3 at GCC `-Os`/`-Oz`, 19 at Clang `-O0`) in Keccak and `gen_matrix`.

**Clangover:** `poly_frommsg` retains the `cmov_int16` fix. Branch counts under Clang 17
are 1–3 depending on level, and `-Oz` was inspected in full because 3 is the highest
observed: all three are loop control (`cmp x21, #0x20` / `b.eq`, plus `cbz`/`cbnz` on the
inner counter), and the disassembly shows `bl` to `cmov_int16` — the conditional move is
**called, not inlined**, which is exactly what the fix intends. No secret-dependent branch
is present. Disassembly archived.

This is the result RQ2 actually asks for. The compiler-sensitivity finding in F1 remains
important, but it is a statement about a *2023 pre-patch* revision, not about what a user
compiling the reference implementation today would get.

**What is still untested:** RQ2 says "compiler *version* or optimisation level". Only one
version of each compiler was used (GCC 16.1.0, Apple Clang 17.0.0), so the
optimisation-level half is answered and the version half is not. CVE-2024-37880 names
Clang 15–18 on x86, none of which was available here.

---

## Instrument defects found during this work

Recorded because an instrument whose failure modes are undisclosed cannot be assessed.
Each would have produced a plausible, publishable-looking number.

**D1 — instrumentation missed `polyvec_compress` entirely.** The active branch for
ML-KEM-512/768 is `KYBER_K * 320`, written `/ KYBER_Q` *with a space*. The sed pattern
required `/KYBER_Q`, so it instrumented the inactive `KYBER_K * 352` branch instead.
Symptom: `div_calls = 512` where the algorithm implies 1280. Superseded figures: an
earlier reported +81.88 cycles / d = 5.83 was computed without `polyvec_compress` and
must not be cited. Fixed by replacing sed with `make_instrumented.py`, which tracks the
enclosing function, tolerates the whitespace, skips comments, and fails loudly on any
untransformed division.

**D2 — symbol classifier was unsound across projects.** It matched exact function names,
so `_PQCP_MLKEM_NATIVE_MLKEM768_poly_tomsg` and CIRCL's `(*Poly).CompressMessageTo` would
both have been recorded as *incidental*. The RQ1 and RQ3 nulls are genuine (no divisions
exist at all), but the instrument would not have detected a positive. Fixed with anchored
regex covering C and Go naming and mlkem-native's per-width variants (`_d4`/`_d10`/`_du`),
excluding `decompress` which takes public input. `tests/test_classify.py` pins 23 cases.

**D3 — decision threshold misattributed.** 4.5 was described as "the conventional dudect
threshold". dudect defines `t_threshold_moderate` as 10 and `t_threshold_bananas` as 500,
its source noting "Pankaj likes 4.5 but let's be more lenient". 4.5 is the TVLA threshold
of Goodwill, Jun, Jaffe and Rohatgi — Rohatgi being that "Pankaj". All three are now
reported.

**D4 — sensitivity analysis was computed invalidly.** The first implementation re-costed
already-collected cycle totals under alternative divider models by inverting the mean
quotient width. That is wrong wherever the clamp is active, because applying a clamp to a
mean is not the mean of the clamped values; it produced spurious zero effects for
KyberSlash2 under a narrow clamp. Replaced by rebuilding the harness with different
`-D` constants and re-measuring, which is exact. The corrected analysis also overturned an
assumption made while fixing it: the 12-cycle bound is *reached* by `polyvec_compress` at
d=10 but never *exceeded*, so the clamp does not bind under the defaults — confirmed
empirically because raising it to 20 changes nothing.

**D5 — a finding was over-generalised from a single key.** With key generation
non-deterministic, one run showed KyberSlash1 and KyberSlash2 leaking in opposite
directions, and this was written up as though it were structural. Making key generation
deterministic and sweeping ten keys showed the opposition holds for only 4 of 10. The
corrected finding is stronger — aggregation understates the leak by a key-dependent amount,
up to 11.6× — but the original claim was not supported by the evidence behind it.

---

## Reproducibility of the leakage figures

`timing_harness.c` supplies its own deterministic `randombytes()` seeded from the CLI
seed, and the upstream `randombytes.c` is not linked. The keypair, the fixed ciphertext,
the class assignment and the random ciphertexts are therefore all derived from the seed,
and a rerun with the same seed reproduces every modelled figure exactly. Two independent
PRNG streams are used — one for key material, one for class assignment — so sample count
cannot perturb the key.

This is correct for a measurement harness and wrong anywhere else: never link
`timing_harness.c` into anything producing keys that protect real data.

Between-key variation is characterised separately by `scripts/seed_sweep.py` (F3), and
proved to be the dominant source of variation in the KyberSlash2 estimate.

## Open items

- **x86-64 Linux baseline** — highest value. Would allow `div`/`idiv` (operand-dependent
  on many cores) to be measured rather than modelled, and is the platform CVE-2024-37880
  actually concerns, enabling a proper Clangover test.
- Sensitivity analysis over the divider model constants.
- Independent repetitions of the leakage screen across sessions and days.
- Broader corpus: liboqs, OpenSSL, AWS-LC, wolfSSL, libcrux — recording provenance so
  wrappers are not counted as independent.
- Architecture-specific backends (AVX2, NEON); only portable C and Go were audited.
- Dynamic secret-flow analysis (TIMECOP-style) to establish secret dependency on executed
  paths independently of binary audit and statistical screening.
- Hardware reproduction on Cortex-A7 / Cortex-M4 for key recovery.
