/* Windows baseline for the `chains` workload with the XAX arm's data layout: keys and links in two arrays, links
 * as 32-bit slot numbers (slot 0 is the end of a chain), where chains.c has 16-byte nodes with pointers.  It is the
 * fastest non-XAX arm measured on Windows 11 (2026-11-12), so the comparison must include it.  A baseline arm, so it
 * is C by definition (language rule, CLAUDE.md).  File descriptor 1 is in text mode: the line ends "\r\n". */
#include <stdint.h>
#include <stdio.h>
#include <io.h>
#include <windows.h>

enum { NODES = 1 << 20, BUCKETS = 1 << 16 };

static uint64_t next_key(uint64_t x) {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

static void *map(size_t bytes) { return VirtualAlloc(0, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); }

int main(void) {
    uint64_t *keys = map((NODES + 1) * sizeof(uint64_t));
    uint32_t *next = map((NODES + 1) * sizeof(uint32_t));
    uint32_t *buckets = map(BUCKETS * sizeof(uint32_t));
    char *out = map(4096);
    if (!keys || !next || !buckets || !out) return 4;
    uint64_t x = 0x9E3779B97F4A7C15ull;
    for (uint32_t i = 1; i <= NODES; i++) {
        x = next_key(x);
        uint64_t b = x >> 48;
        keys[i] = x;
        next[i] = buckets[b];
        buckets[b] = i;
    }
    uint64_t found = 0, steps = 0;
    x = 0x9E3779B97F4A7C15ull;
    for (uint64_t j = 0; j < NODES; j++) {
        x = next_key(x);
        for (uint32_t cur = buckets[x >> 48]; cur; cur = next[cur]) {
            steps++;
            if (keys[cur] == x) { found++; break; }
        }
    }
    int length = snprintf(out, 4096, "%llu %llu\n", (unsigned long long)found, (unsigned long long)steps);
    int status = _write(1, out, (unsigned)length) == length ? 0 : 3;
    VirtualFree(keys, 0, MEM_RELEASE);
    VirtualFree(next, 0, MEM_RELEASE);
    VirtualFree(buckets, 0, MEM_RELEASE);
    VirtualFree(out, 0, MEM_RELEASE);
    return status;
}
