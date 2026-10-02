/* Validation oracle only. XAX production code generation never uses C. */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

typedef int (*HookFunType)(void *, void *, void **);
typedef int (*UnhookFunType)(void *);
typedef void (*NativeOnModuleLoaded)(const char *, void *);
typedef struct {
    uint32_t version;
    HookFunType hook_func;
    UnhookFunType unhook_func;
} NativeAPIEntries;
typedef NativeOnModuleLoaded (*NativeInit)(const NativeAPIEntries *);

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 65; }
    NativeInit init = (NativeInit)dlsym(handle, "native_init");
    if (!init) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 66; }
    NativeAPIEntries entries = {102, 0, 0};
    NativeOnModuleLoaded callback = init(&entries);
    if (!callback) return 67;
    callback("libvalidation.so", handle);
    dlclose(handle);
    return 0;
}
