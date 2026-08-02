/* Instrumented division for KyberSlash leakage measurement.
 *
 * The measurement host (Apple M1) has a constant-latency divider, so the
 * secret-dependent division present in the binary produces no observable timing
 * signal locally (see docs/findings.md, F2). This header lets the harness recover
 * the leakage that the *operands* carry, independently of host divider behaviour,
 * by accumulating a modelled cycle cost per division.
 *
 * Four counters are maintained per decapsulation, two per KyberSlash variant:
 *   ks1_cycles / ks2_cycles - modelled divider cycles
 *   ks1_calls  / ks2_calls  - number of runtime divisions executed
 *
 * The modelled result is a simulation, not a hardware measurement, and must be
 * reported as such.
 */
#ifndef KS_INSTRUMENT_H
#define KS_INSTRUMENT_H

#include <stdint.h>

/* Counters are kept per KyberSlash variant. The two are reached by different call
 * paths within one decapsulation -- KyberSlash1 from PKE decryption, KyberSlash2
 * from PKE re-encryption -- and their effects do not move together. KyberSlash2's
 * direction is key-dependent (negative for 4 of 10 keys measured), so summing the
 * two before analysis understates the leak by a key-dependent amount: up to 11.6x
 * in the worst key observed. Keep them separate. See docs/findings.md F3.
 */
extern uint64_t ks1_cycles;   /* poly_tomsg */
extern uint64_t ks2_cycles;   /* poly_compress, polyvec_compress */
extern uint64_t ks1_calls;
extern uint64_t ks2_calls;

/* Cortex-M4 UDIV/SDIV latency model.
 *
 * The Cortex-M4 divider is widely described as taking 2-12 cycles with early
 * termination, the iterative divider retiring roughly one quotient bit per cycle
 * after a fixed setup cost, so latency grows with the bit-length of the quotient.
 *
 * PROVENANCE: these constants are taken from secondary descriptions attributing
 * them to the Cortex-M4 Technical Reference Manual (ARM DDI 0439). The primary
 * timing table was NOT consulted directly. Treat the exact figures as unverified
 * and check them against the TRM before citing them as ARM's own. What the study
 * relies on is the SHAPE of the model -- monotonic in quotient width, saturating --
 * not the precise constants, and the sensitivity analysis in
 * scripts/model_sensitivity.py exists to show which conclusions survive varying
 * them.
 *
 *   quotient_bits ~= bitlen(numerator) - bitlen(denominator)
 *                  = clz(denominator) - clz(numerator)
 *
 * Latency is clamped to the [2, 12] range given above. The model is deliberately
 * simple and its parameters are declared here so results can be re-derived.
 */
/* Overridable at build time (-DKS_M4_DIV_MAX_CYCLES=20 etc.) so a sensitivity
 * analysis can vary the model and rebuild.
 *
 * Vary the model by REBUILDING, never by re-costing already-collected totals: the
 * clamp is non-linear, so applying it to a mean is not the mean of the clamped
 * values. Under these defaults the widest case is polyvec_compress at d=10, where
 * a ~22-bit numerator over a 12-bit divisor gives 10 quotient bits and a cost of
 * exactly 12 -- the bound is reached but never exceeded, so the clamp does not
 * bind. Raising the bound to 20 leaves every figure unchanged, which confirms
 * this empirically. Lowering it to 6 does bind, and changes the sign of the
 * KyberSlash2 effect for some keys.
 */
#ifndef KS_M4_DIV_MIN_CYCLES
#define KS_M4_DIV_MIN_CYCLES 2u
#endif
#ifndef KS_M4_DIV_MAX_CYCLES
#define KS_M4_DIV_MAX_CYCLES 12u
#endif
#ifndef KS_M4_DIV_CYCLES_PER_BIT
#define KS_M4_DIV_CYCLES_PER_BIT 1u
#endif

static inline unsigned ks_clz32(uint32_t x) {
    return x ? (unsigned)__builtin_clz(x) : 32u;
}

static inline unsigned ks_m4_div_cycles(uint32_t num, uint32_t den) {
    if (den == 0u) return KS_M4_DIV_MAX_CYCLES;
    int quotient_bits = (int)ks_clz32(den) - (int)ks_clz32(num);
    if (quotient_bits < 0) quotient_bits = 0;
    unsigned cycles = KS_M4_DIV_MIN_CYCLES
                    + KS_M4_DIV_CYCLES_PER_BIT * (unsigned)quotient_bits;
    if (cycles > KS_M4_DIV_MAX_CYCLES) cycles = KS_M4_DIV_MAX_CYCLES;
    return cycles;
}

/* Replace a runtime "/ KYBER_Q" in the instrumented sources.
 * ks_div1 - KyberSlash1 site (poly_tomsg)
 * ks_div2 - KyberSlash2 sites (poly_compress, polyvec_compress)
 * Both return the exact quotient, so instrumented builds stay functionally
 * identical to their uninstrumented counterparts.
 */
static inline uint32_t ks_div1(uint32_t num, uint32_t den) {
    ks1_cycles += ks_m4_div_cycles(num, den);
    ks1_calls++;
    return num / den;
}

static inline uint32_t ks_div2(uint32_t num, uint32_t den) {
    ks2_cycles += ks_m4_div_cycles(num, den);
    ks2_calls++;
    return num / den;
}

static inline void ks_reset(void) {
    ks1_cycles = 0;
    ks2_cycles = 0;
    ks1_calls = 0;
    ks2_calls = 0;
}

#endif /* KS_INSTRUMENT_H */
