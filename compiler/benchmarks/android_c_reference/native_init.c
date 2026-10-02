#include <stdint.h>
typedef void (*NativeOnModuleLoaded)(const char *, void *);
typedef struct { uint32_t version; void *hook_func; void *unhook_func; } NativeAPIEntries;
static void on_loaded(const char *name, void *handle) { (void)name; (void)handle; }
__attribute__((visibility("default"), used)) NativeOnModuleLoaded native_init(const NativeAPIEntries *entries) {
    (void)entries;
    return on_loaded;
}
