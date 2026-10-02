#include <unistd.h>
__attribute__((visibility("default"))) int probe_getpid(void) { return (int)getpid(); }
