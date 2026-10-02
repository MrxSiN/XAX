/* Validation oracle only.  XAX production code generation never uses C.
 * Drives the persistent-counter Activity's two XAX JNI methods with real file
 * descriptors, as the generated managed code does, and checks persistence. */
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef int64_t (*callback)(void *env, void *self, void *argument, int32_t fd);

static int open_state(const char *path) { return open(path, O_RDWR | O_CREAT, 0600); }

int main(int argc, char **argv) {
    /* usage: counter_native_loader <library> <state file> <onCreate symbol> <onClick symbol> */
    if (argc != 5) return 64;
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 65; }
    callback create = (callback)dlsym(h, argv[3]);
    callback click = (callback)dlsym(h, argv[4]);
    if (!create || !click) return 66;
    unlink(argv[2]);
    int64_t seen[6];
    int closed = 1, fd;
    fd = open_state(argv[2]); seen[0] = create(0, 0, 0, fd); closed &= fcntl(fd, F_GETFD) == -1;   /* first launch */
    for (int i = 1; i <= 3; i++) { fd = open_state(argv[2]); seen[i] = click(0, 0, 0, fd); closed &= fcntl(fd, F_GETFD) == -1; }
    fd = open_state(argv[2]); seen[4] = create(0, 0, 0, fd); closed &= fcntl(fd, F_GETFD) == -1;   /* after a restart */
    fd = open_state(argv[2]); seen[5] = click(0, 0, 0, fd); closed &= fcntl(fd, F_GETFD) == -1;
    unsigned char bytes[16] = {0};
    int in = open(argv[2], O_RDONLY); ssize_t size = read(in, bytes, sizeof bytes); close(in);
    uint64_t stored = 0; memcpy(&stored, bytes, 8);
    printf("XAX_COUNTER seen=%lld,%lld,%lld,%lld,%lld,%lld file_bytes=%zd stored=%llu fds_closed=%d\n",
           (long long)seen[0], (long long)seen[1], (long long)seen[2], (long long)seen[3], (long long)seen[4], (long long)seen[5],
           size, (unsigned long long)stored, closed);
    return 0;
}
