/* KyberSlash leakage screening harness.
 *
 * Runs a dudect-style fixed-vs-random experiment over ML-KEM decapsulation and
 * records, per sample, both:
 *   - modelled_cycles : divider cost under the Cortex-M4 model in ks_instrument.h
 *   - host_ns         : real elapsed time on the measurement host
 *
 * Recording both is the point. On a host with a constant-latency divider the two
 * columns disagree: the modelled column shows the leak the operands carry, the
 * host column shows that this particular microarchitecture does not express it.
 *
 * Class 0 (fixed)  : one fixed ciphertext, decapsulated repeatedly
 * Class 1 (random) : freshly randomised ciphertexts
 * Class order is randomised per sample to avoid drift aligning with class.
 *
 * Output: CSV to stdout -
 *   sample,class,ks1_cycles,ks2_cycles,modelled_cycles,ks1_calls,ks2_calls,host_ns
 * KyberSlash1 and KyberSlash2 are reported separately as well as summed, because
 * their per-class contributions can move in opposite directions and partially
 * cancel in the aggregate.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "kem.h"
#include "params.h"
#include "randombytes.h"
#include "ks_instrument.h"

uint64_t ks1_cycles = 0;
uint64_t ks2_cycles = 0;
uint64_t ks1_calls = 0;
uint64_t ks2_calls = 0;

#ifdef __APPLE__
#include <mach/mach_time.h>
static double ns_scale(void) {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    return (double)tb.numer / (double)tb.denom;
}
static uint64_t now_raw(void) { return mach_absolute_time(); }
#else
static double ns_scale(void) { return 1.0; }
static uint64_t now_raw(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
#endif

/* xorshift64*. Two independent streams are kept so that the two things the seed
 * controls cannot perturb each other:
 *
 *   key_state   -> randombytes(), i.e. the keypair and the fixed ciphertext
 *   class_state -> class assignment and random-ciphertext bytes
 *
 * With one shared stream, changing --samples would change how much output the
 * class loop consumed and therefore change nothing about the key (keygen runs
 * first) but would still couple the two concerns unnecessarily. Separate streams
 * make "same seed, same key" true independently of sample count.
 */
static uint64_t key_state;
static uint64_t class_state;

static uint64_t xorshift(uint64_t *s) {
    *s ^= *s >> 12;
    *s ^= *s << 25;
    *s ^= *s >> 27;
    return *s * 2685821657736338717ull;
}

static uint64_t rnd(void) { return xorshift(&class_state); }

/* Deterministic replacement for the upstream randombytes().
 *
 * Linking this instead of the project's randombytes.c makes key generation and
 * encapsulation reproducible from the seed, so a rerun yields identical
 * measurements rather than merely the same qualitative pattern.
 *
 * This is a MEASUREMENT harness. Deterministic key material is correct here and
 * wrong everywhere else: never link this file into anything that produces keys
 * used to protect real data.
 */
void randombytes(uint8_t *out, size_t outlen) {
    while (outlen > 0) {
        uint64_t v = xorshift(&key_state);
        size_t n = outlen < sizeof(v) ? outlen : sizeof(v);
        for (size_t i = 0; i < n; i++) {
            out[i] = (uint8_t)(v >> (8 * i));
        }
        out += n;
        outlen -= n;
    }
}

int main(int argc, char **argv) {
    long samples   = (argc > 1) ? atol(argv[1]) : 20000;
    long warmup    = (argc > 2) ? atol(argv[2]) : 1000;
    uint64_t seed  = (argc > 3) ? strtoull(argv[3], NULL, 10) : 0x5eed1234u;

    /* Derive both streams from the one seed, with different constants so they
     * are not trivially correlated. */
    key_state   = seed ^ 0x9e3779b97f4a7c15ull;
    class_state = seed ^ 0xbf58476d1ce4e5b9ull;

    uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct_fixed[CRYPTO_CIPHERTEXTBYTES], ct_rand[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[CRYPTO_BYTES], ss_enc[CRYPTO_BYTES];

    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct_fixed, ss_enc, pk);

    const double scale = ns_scale();

    for (long i = 0; i < warmup; i++) {
        crypto_kem_dec(ss, ct_fixed, sk);
    }

    printf("sample,class,ks1_cycles,ks2_cycles,modelled_cycles,"
           "ks1_calls,ks2_calls,host_ns\n");

    for (long i = 0; i < samples; i++) {
        int cls = (int)(rnd() & 1ull);
        uint8_t *ct;

        if (cls == 0) {
            ct = ct_fixed;
        } else {
            /* Random ciphertext: decapsulation takes the implicit-rejection path,
             * and the re-encryption compression operates on different values. */
            for (size_t b = 0; b < CRYPTO_CIPHERTEXTBYTES; b++) {
                ct_rand[b] = (uint8_t)(rnd() & 0xff);
            }
            ct = ct_rand;
        }

        ks_reset();
        uint64_t t0 = now_raw();
        crypto_kem_dec(ss, ct, sk);
        uint64_t t1 = now_raw();

        printf("%ld,%d,%llu,%llu,%llu,%llu,%llu,%.1f\n", i, cls,
               (unsigned long long)ks1_cycles,
               (unsigned long long)ks2_cycles,
               (unsigned long long)(ks1_cycles + ks2_cycles),
               (unsigned long long)ks1_calls,
               (unsigned long long)ks2_calls,
               (double)(t1 - t0) * scale);
    }

    return 0;
}
