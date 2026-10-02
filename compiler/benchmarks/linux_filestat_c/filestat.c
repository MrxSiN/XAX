/* Baseline for the U1 XAX filestat workload; same observable contract. */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <zlib.h>

enum { BUFFER_BYTES = 65536 };

int main(void) {
    unsigned char *buffer = mmap(0, BUFFER_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint64_t *table = mmap(0, 256 * sizeof(uint64_t), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buffer == MAP_FAILED || table == MAP_FAILED) return 4;
    int status = 0;
    int fd = openat(AT_FDCWD, "input.dat", O_RDONLY);
    if (fd < 0) { status = 2; goto done; }
    uint64_t bytes = 0, lines = 0, words = 0, hash = 0xcbf29ce484222325ull, prev_ws = 1;
    uLong crc = 0;
    for (;;) {
        ssize_t n = read(fd, buffer, BUFFER_BYTES);
        if (n == 0) break;
        if (n < 0) { status = 3; goto done; }
        crc = crc32(crc, buffer, (uInt)n);
        for (ssize_t i = 0; i < n; i++) {
            uint64_t c = buffer[i];
            uint64_t ws = (c == ' ') | (c == '\n') | (c == '\t') | (c == '\r');
            bytes++;
            lines += c == '\n';
            words += (ws ^ 1) & prev_ws;
            prev_ws = ws;
            hash = (hash ^ c) * 0x100000001b3ull;
            table[c]++;
        }
    }
    close(fd);
    uint64_t best = 0, best_count = 0;
    for (uint64_t k = 0; k < 256; k++)
        if (table[k] > best_count) { best = k; best_count = table[k]; }
    int length = snprintf((char *)buffer, BUFFER_BYTES, "%llu %llu %llu %llu %llu %llu\n",
                          (unsigned long long)bytes, (unsigned long long)lines, (unsigned long long)words,
                          (unsigned long long)hash, (unsigned long long)crc, (unsigned long long)best);
    if (write(1, buffer, (size_t)length) != length) status = 3;
done:
    munmap(buffer, BUFFER_BYTES);
    munmap(table, 256 * sizeof(uint64_t));
    return status;
}
