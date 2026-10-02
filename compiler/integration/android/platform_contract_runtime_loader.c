#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef uint64_t (*file_probe_fn)(const uint8_t *, const uint8_t *, uint64_t, uint8_t *);
typedef int32_t (*thread_create_probe_fn)(uint8_t *, const uint8_t *, void *, uint8_t *);
typedef int32_t (*thread_join_probe_fn)(uint64_t, uint8_t *);
typedef uint64_t (*socket_probe_fn)(const uint8_t *, uint32_t, const uint8_t *, uint64_t, uint8_t *, uint64_t);

struct server_state { int listener; int ok; };

static void *xax_thread_callback(void *argument) {
    *(volatile uint32_t *)argument = 0x5a5aa55aU;
    return (void *)(uintptr_t)0x1234U;
}

static void *server_main(void *opaque) {
    struct server_state *state = (struct server_state *)opaque;
    int client = accept(state->listener, NULL, NULL);
    if (client < 0) return NULL;
    char buffer[8] = {0};
    ssize_t got = recv(client, buffer, sizeof(buffer), 0);
    if (got == 4 && memcmp(buffer, "ping", 4) == 0 && send(client, "pong", 4, 0) == 4) state->ok = 1;
    close(client);
    return NULL;
}

static int fail(const char *what) {
    fprintf(stderr, "XAX_PLATFORM_RUNTIME_FAIL %s errno=%d\n", what, errno);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) return fail("usage");
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    file_probe_fn file_probe = (file_probe_fn)dlsym(library, "xax_file_probe");
    thread_create_probe_fn thread_create_probe = (thread_create_probe_fn)dlsym(library, "xax_thread_create_probe");
    thread_join_probe_fn thread_join_probe = (thread_join_probe_fn)dlsym(library, "xax_thread_join_probe");
    socket_probe_fn socket_probe = (socket_probe_fn)dlsym(library, "xax_socket_probe");
    if (!file_probe || !thread_create_probe || !thread_join_probe || !socket_probe) return fail("dlsym");

    const char *path = "/data/local/tmp/xax_platform_contract_runtime.txt";
    const char file_data[] = "file-ok";
    unlink(path);
    char file_check[8] = {0};
    if (file_probe((const uint8_t *)path, (const uint8_t *)file_data, 7, (uint8_t *)file_check) != 7) return fail("file-probe");
    if (memcmp(file_check, file_data, 7) != 0) return fail("file-verify");
    unlink(path);

    pthread_t created = 0;
    volatile uint32_t thread_word = 0;
    if (thread_create_probe((uint8_t *)&created, NULL, (void *)xax_thread_callback, (uint8_t *)&thread_word) != 0) return fail("pthread-create");
    void *thread_result = NULL;
    if (thread_join_probe((uint64_t)created, (uint8_t *)&thread_result) != 0) return fail("pthread-join");
    if (thread_word != 0x5a5aa55aU || thread_result != (void *)(uintptr_t)0x1234U) return fail("pthread-verify");

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return fail("server-socket");
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(listener, 1) != 0) return fail("server-bind-listen");
    socklen_t address_size = sizeof(address);
    if (getsockname(listener, (struct sockaddr *)&address, &address_size) != 0) return fail("server-name");
    struct server_state server = {listener, 0};
    pthread_t server_thread;
    if (pthread_create(&server_thread, NULL, server_main, &server) != 0) return fail("server-thread");
    char receive_buffer[8] = {0};
    if (socket_probe((const uint8_t *)&address, (uint32_t)sizeof(address), (const uint8_t *)"ping", 4, (uint8_t *)receive_buffer, 4) != 4) return fail("socket-probe");
    if (pthread_join(server_thread, NULL) != 0 || !server.ok || memcmp(receive_buffer, "pong", 4) != 0) return fail("socket-verify");
    close(listener);

    dlclose(library);
    puts("XAX_PLATFORM_RUNTIME_OK file=1 thread=1 socket=1");
    return 0;
}
