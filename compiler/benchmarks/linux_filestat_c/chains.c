/* Baseline for the OI-37 `chains` workload: the same chained hash table
 * with real `next` pointers into a pool (XAX uses arena + index). */
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

enum { NODES = 1 << 20, BUCKETS = 1 << 16 };
struct node { uint64_t key; struct node *next; };

static uint64_t next_key(uint64_t x) {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

int main(void) {
    struct node *pool = mmap(0, NODES * sizeof(struct node), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct node **buckets = mmap(0, BUCKETS * sizeof(struct node *), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *out = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool == MAP_FAILED || buckets == MAP_FAILED || out == MAP_FAILED) return 4;
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
    int status = write(1, out, (size_t)length) == length ? 0 : 3;
    munmap(pool, NODES * sizeof(struct node));
    munmap(buckets, BUCKETS * sizeof(struct node *));
    munmap(out, 4096);
    return status;
}
