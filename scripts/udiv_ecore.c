// Does udiv latency depend on operands on the M1 EFFICIENCY cores (Icestorm)?
// QOS_CLASS_BACKGROUND pins the thread to E-cores on Apple Silicon.
// P-cores (Firestorm) were already shown constant-latency; E-cores are smaller and
// may use an iterative early-terminating divider.
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <mach/mach_time.h>
#include <sys/qos.h>

#define ITERS 1000000

static uint64_t bench(uint32_t num, uint32_t den) {
    volatile uint32_t sink = 0;
    uint32_t n = num;
    uint64_t start = mach_absolute_time();
    for (int i = 0; i < ITERS; i++) {
        uint32_t q;
        __asm__ volatile("udiv %w0, %w1, %w2" : "=r"(q) : "r"(n), "r"(den));
        n = num + (q & 1);
        sink += q;
    }
    uint64_t end = mach_absolute_time();
    (void)sink;
    return end - start;
}

struct testcase { const char *name; uint32_t num, den; };

static struct testcase cases[] = {
    {"quotient  2-bit   6656/3329",      6656u, 3329u},
    {"quotient  2-bit      7/3",            7u, 3u},
    {"quotient 16-bit  0xFFFFFFFF/0xFFFF", 0xFFFFFFFFu, 0xFFFFu},
    {"quotient 32-bit  0xFFFFFFFF/1",    0xFFFFFFFFu, 1u},
};

static void *run(void *arg) {
    const char *label = (const char *)arg;
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);

    printf("\n=== %s ===\n", label);
    printf("%-36s %12s\n", "case", "ns/iter");
    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        bench(cases[i].num, cases[i].den);
        uint64_t best = ~0ull;
        for (int r = 0; r < 5; r++) {
            uint64_t t = bench(cases[i].num, cases[i].den);
            if (t < best) best = t;
        }
        double ns = (double)best * tb.numer / tb.denom / ITERS;
        printf("%-36s %12.4f\n", cases[i].name, ns);
    }
    return NULL;
}

int main(void) {
    pthread_t th;
    pthread_attr_t attr;

    // Efficiency cores
    pthread_attr_init(&attr);
    pthread_attr_set_qos_class_np(&attr, QOS_CLASS_BACKGROUND, 0);
    pthread_create(&th, &attr, run, "EFFICIENCY cores (QOS_CLASS_BACKGROUND)");
    pthread_join(th, NULL);

    // Performance cores, for direct comparison in the same process
    pthread_attr_init(&attr);
    pthread_attr_set_qos_class_np(&attr, QOS_CLASS_USER_INTERACTIVE, 0);
    pthread_create(&th, &attr, run, "PERFORMANCE cores (QOS_CLASS_USER_INTERACTIVE)");
    pthread_join(th, NULL);

    return 0;
}
