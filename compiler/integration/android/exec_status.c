/* Test harness only: run argv[1..] and print "exit N" or "signal N" on stdout's
 * replacement fd 3, so a caller behind `adb shell` can tell a trap from an exit
 * status above 128 (the shell's $? cannot). */
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 64;
    pid_t pid = fork();
    if (pid == 0) {
        execv(argv[1], argv + 1);
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) return 70;
    FILE *report = fdopen(3, "w");
    if (!report) return 71;
    if (WIFSIGNALED(status)) fprintf(report, "signal %d\n", WTERMSIG(status));
    else fprintf(report, "exit %d\n", WEXITSTATUS(status));
    return 0;
}
