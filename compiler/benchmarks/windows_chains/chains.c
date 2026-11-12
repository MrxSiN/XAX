/* Windows baseline for the `chains` workload (OI-37): linux_filestat_c/chains.c with VirtualAlloc/VirtualFree in
 * place of mmap/munmap and msvcrt's _write in place of write.  A baseline arm, so it is C by definition
 * (language rule, CLAUDE.md).  File descriptor 1 is in text mode: the line ends "\r\n", as the XAX arm's does. */
#include <stdint.h>
#include <stdio.h>
#include <io.h>
#include <windows.h>

enum { NODES = 1 << 20, BUCKETS = 1 << 16 };
struct node { uint64_t key; struct node *next; };

static uint64_t next_key(uint64_t x) {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

static void *map(size_t bytes) { return VirtualAlloc(0, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); }

int main(void) {
    struct node *pool = map(NODES * sizeof(struct node));
    struct node **buckets = map(BUCKETS * sizeof(struct node *));
    char *out = map(4096);
    if (!pool || !buckets || !out) return 4;
    uint64_t x = 0x9E3779B97F4A7C15ull;
    for (uint64_t i = 0; i < NODES; i++) {
        x = next_key(x);
        uint64_t b = x >> 48;
        pool[i].key = x;
        pool[i].next = buckets[b];
        buckets[b] = &pool[i];
    }
    uint64_t found = 0, steps = 0;
    x = 0x9E3779B97F4A7C15ull;
    for (uint64_t j = 0; j < NODES; j++) {
        x = next_key(x);
        for (struct node *cur = buckets[x >> 48]; cur; cur = cur->next) {
            steps++;
            if (cur->key == x) { found++; break; }
        }
    }
    int length = snprintf(out, 4096, "%llu %llu\n", (unsigned long long)found, (unsigned long long)steps);
    int status = _write(1, out, (unsigned)length) == length ? 0 : 3;
    VirtualFree(pool, 0, MEM_RELEASE);
    VirtualFree(buckets, 0, MEM_RELEASE);
    VirtualFree(out, 0, MEM_RELEASE);
    return status;
}
