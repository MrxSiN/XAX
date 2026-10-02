/* Measurement harness only: fork/exec one program with stdout to /dev/null,
 * report wall nanoseconds, exit status, and wait4 ru_maxrss (KiB).  The
 * child's pre-exec high-water mark is this small runner's, not Python's. */
#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    pid_t pid = fork();
    if (pid == 0) {
        int null = open("/dev/null", O_WRONLY);
        dup2(null, 1);
        execl(argv[1], argv[1], (char *)0);
        _exit(127);
    }
    int status;
    struct rusage usage;
    wait4(pid, &status, 0, &usage);
    clock_gettime(CLOCK_MONOTONIC, &end);
    long long ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
    printf("%lld %d %ld\n", ns, WIFEXITED(status) ? WEXITSTATUS(status) : -1, usage.ru_maxrss);
    return 0;
}
