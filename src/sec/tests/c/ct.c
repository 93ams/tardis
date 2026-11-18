/*
 * C for the tracer tests (src/sec/tests/ctrace_test.zig), built with
 * -fsanitize-coverage=trace-pc,trace-cmp,trace-div,trace-loads,trace-stores.
 * Each leak has a
 * constant-time counterpart.
 */
#include <stddef.h>

/* Returns at the first differing byte: how long it runs depends on the
 * secret. */
int tag_equal_early_exit(const unsigned char *a, const unsigned char *b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

/* Looks at every byte whatever they hold. */
int tag_equal_constant_time(const unsigned char *a, const unsigned char *b, size_t n) {
    unsigned char d = 0;
    size_t i;
    for (i = 0; i < n; i++) d |= (unsigned char)(a[i] ^ b[i]);
    return (int)((1u & ((d - 1u) >> 8)));
}

/* The bucket of `x` for buckets of `m` values: a division whose latency
 * follows `m`'s width. (Clang's trace-div sees `/`, not `%`, and the
 * optimizer turns `x - (x / m) * m` into `%`.) */
unsigned bucket(unsigned x, unsigned m) {
    return x / m;
}

/* A small command parser, for the constants the tracer keeps. */
int command_code(const char *s, unsigned magic) {
    if (magic == 0x7A3D51C9u) return -1;
    switch (s[0]) {
    case 'G': return 1;
    case 'P': return 2;
    case 'D': return 3;
    default: return 0;
    }
}

/* A header check with a magic number: random 32-bit input never passes it
 * (1 in 2^32 a run). Returns 1 when the header is accepted. */
int header_accepted(unsigned magic) {
    return magic == 0x5EC0B1A5u;
}

/* A 1 KiB lookup table: 16 cache lines. */
static const unsigned table[256] = {
#define R(i) (i) * 2654435761u
#define R4(i) R(i), R(i + 1), R(i + 2), R(i + 3)
#define R16(i) R4(i), R4(i + 4), R4(i + 8), R4(i + 12)
#define R64(i) R16(i), R16(i + 16), R16(i + 32), R16(i + 48)
    R64(0), R64(64), R64(128), R64(192)
#undef R64
#undef R16
#undef R4
#undef R
};

/* An S-box style lookup indexed by the secret: which cache line it reads
 * depends on the secret. */
unsigned lookup_indexed(unsigned char secret) {
    return table[secret];
}

/* Reads every entry and keeps the one it wants with a mask. */
unsigned lookup_scan(unsigned char secret) {
    unsigned r = 0;
    unsigned i;
    for (i = 0; i < 256; i++) {
        unsigned m = 0u - (unsigned)(i == secret);
        r |= table[i] & m;
    }
    return r;
}

#include "tardis_sec.h"

/* Values with no pattern in the index, so an address that follows the
 * value does not also follow the index. */
static const unsigned char spectre_table[16] = { 7, 200, 13, 91, 164, 2, 255, 38, 119, 66, 181, 20, 233, 144, 5, 97 };
/* Not static: a static array nothing writes is all zeros to the
 * optimizer, which then drops the load. */
unsigned char spectre_probe[256 * 64];

/* The Spectre-v1 gadget: the second load's address is the first one's
 * value times 64. */
unsigned spectre_victim(size_t x) {
    if (TARDIS_SEC_BOUNDS(x, 16)) return spectre_probe[spectre_table[x] * 64];
    return 0;
}

/* The same lookup with the index hardened: out of bounds it is 0 also
 * when the branch is mispredicted. */
unsigned spectre_hardened(size_t x) {
    if (x < 16) {
        x = tardis_sec_index_nospec(x, 16);
        return spectre_probe[spectre_table[x] * 64];
    }
    return 0;
}

/* Two loads after the check, neither address taken from a value. */
unsigned spectre_plain(size_t x) {
    if (TARDIS_SEC_BOUNDS(x, 16)) return (unsigned)spectre_table[x] + spectre_table[15 - x];
    return 0;
}
