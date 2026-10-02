/* Validation oracle only.  XAX production code generation never uses C.
 * Spawns four threads through the XAX export xax_spawn_fib, whose start routine
 * is an XAX function, joins them with bionic's pthread_join, and checks fib(n). */
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

typedef uint32_t (*spawn_fn)(pthread_t *, uint64_t);

static uint64_t fib(uint64_t n) {
    uint64_t a = 0, b = 1;
    while (n--) { uint64_t t = a + b; a = b; b = t; }
    return a;
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 65; }
    spawn_fn spawn = (spawn_fn)dlsym(library, "xax_spawn_fib");
    if (!spawn) return 66;
    static const uint64_t inputs[4] = {10, 50, 90, 93};
    pthread_t threads[4];
    for (int i = 0; i < 4; i++) {
        if (spawn(&threads[i], inputs[i]) != 0) { fprintf(stderr, "spawn %d failed\n", i); return 67; }
    }
    int ok = 0;
    for (int i = 0; i < 4; i++) {
        void *result = 0;
        if (pthread_join(threads[i], &result) != 0) return 68;
        ok += (uint64_t)(uintptr_t)result == fib(inputs[i]);
    }
    printf("XAX_THREAD_ENTRY_OK %d/4\n", ok);
    return ok == 4 ? 0 : 1;
}
