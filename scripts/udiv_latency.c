// Does aarch64 udiv latency depend on its operands on this core?
// Serial dependent chain so each udiv's latency is exposed, not pipelined away.
#include <stdio.h>
#include <stdint.h>
#include <mach/mach_time.h>

#define ITERS 2000000

static uint64_t bench(uint32_t num, uint32_t den) {
    volatile uint32_t sink = 0;
    uint32_t n = num;
    uint64_t start = mach_absolute_time();
    for (int i = 0; i < ITERS; i++) {
        // Dependent chain: next dividend derives from previous quotient.
        uint32_t q;
        __asm__ volatile("udiv %w0, %w1, %w2" : "=r"(q) : "r"(n), "r"(den));
        n = num + (q & 1);
        sink += q;
    }
    uint64_t end = mach_absolute_time();
    (void)sink;
    return end - start;
}

int main(void) {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);

    struct { const char *name; uint32_t num, den; } cases[] = {
        {"small/small   1/1",            1u, 1u},
        {"small/small   7/3",            7u, 3u},
        {"kyber-like    6656/3329",   6656u, 3329u},
        {"kyber-like  100000/3329", 100000u, 3329u},
        {"large/small   0xFFFFFFFF/1", 0xFFFFFFFFu, 1u},
        {"large/large   0xFFFFFFFF/0xFFFF", 0xFFFFFFFFu, 0xFFFFu},
    };

    printf("%-34s %12s %10s\n", "case", "ns/iter", "raw");
    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        bench(cases[i].num, cases[i].den); // warm up
        uint64_t best = ~0ull;
        for (int r = 0; r < 5; r++) {
            uint64_t t = bench(cases[i].num, cases[i].den);
            if (t < best) best = t;
        }
        double ns = (double)best * tb.numer / tb.denom / ITERS;
        printf("%-34s %12.4f %10llu\n", cases[i].name, ns, (unsigned long long)best);
    }
    return 0;
}
