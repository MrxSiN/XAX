/* Diagnostic twin of the OI-37 `chains` workload with XAX's representation:
 * links are arena indices (index + 1, 0 = end) over byte offsets.  With
 * -DCHECKED every dynamic access is range-checked like XAX's checked
 * load/store (trap on failure).  Not a baseline: it isolates representation
 * and bounds-check cost from XAX code generation. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

enum { NODES = 1 << 20, BUCKETS = 1 << 16, NODE_BYTES = 16 };

#ifdef CHECKED
#define CHECK(offset, extent) do { if ((uint64_t)(offset) > (uint64_t)(extent) - 8) __builtin_trap(); } while (0)
#else
#define CHECK(offset, extent) do { } while (0)
#endif

static uint64_t load64(const unsigned char *base, uint32_t offset, uint64_t extent) {
    CHECK(offset, extent);
    uint64_t value;
    memcpy(&value, base + offset, 8);
    return value;
}

static void store64(unsigned char *base, uint32_t offset, uint64_t extent, uint64_t value) {
    CHECK(offset, extent);
    memcpy(base + offset, &value, 8);
}

static uint64_t next_key(uint64_t x) {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

int main(void) {
    const uint64_t arena_bytes = (uint64_t)NODES * NODE_BYTES, bucket_bytes = (uint64_t)BUCKETS * 8;
    unsigned char *arena = mmap(0, arena_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *table = mmap(0, bucket_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *out = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED || table == MAP_FAILED || out == MAP_FAILED) return 4;
    uint64_t x = 0x9E3779B97F4A7C15ull;
    for (uint64_t i = 0; i < NODES; i++) {
        x = next_key(x);
        uint32_t bucket = (uint32_t)((x >> 48) * 8);
        uint64_t head = load64(table, bucket, bucket_bytes);
        uint32_t node = (uint32_t)(i * NODE_BYTES);
        store64(arena, node, arena_bytes, x);
        store64(arena, node + 8, arena_bytes, head);
        store64(table, bucket, bucket_bytes, i + 1);
    }
    uint64_t found = 0, steps = 0;
    x = 0x9E3779B97F4A7C15ull;
    for (uint64_t j = 0; j < NODES; j++) {
        x = next_key(x);
        uint64_t cur = load64(table, (uint32_t)((x >> 48) * 8), bucket_bytes);
        while (cur) {
            steps++;
            uint32_t node = (uint32_t)((cur - 1) * NODE_BYTES);
            if (load64(arena, node, arena_bytes) == x) { found++; break; }
            cur = load64(arena, node + 8, arena_bytes);
        }
    }
    int length = snprintf(out, 4096, "%llu %llu\n", (unsigned long long)found, (unsigned long long)steps);
    int status = write(1, out, (size_t)length) == length ? 0 : 3;
    munmap(arena, arena_bytes);
    munmap(table, bucket_bytes);
    munmap(out, 4096);
    return status;
}
