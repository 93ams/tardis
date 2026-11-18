/* C under test for shadow_test.zig: built with clang's load and store
 * tracing (-fsanitize-coverage=trace-pc,trace-loads,trace-stores), so its
 * accesses are reported to the shadow (plan2.md §3.8). */
#include <stddef.h>

void c_fill(unsigned char *p, size_t n, unsigned char value) {
    /* Not a plain fill: the optimizer would call libc's memset, which is
     * not traced. */
    for (size_t i = 0; i < n; i++) p[i] = (unsigned char)(value + i);
}

unsigned c_at(const unsigned char *p, size_t i) {
    return p[i];
}
