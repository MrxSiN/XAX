/* Semantic twin of tests/test_xax_pe.py::hosted_fixture for size/time baselines.
   Suggested no-CRT build (MSVC): cl /O2 /GS- hosted.c /link /NODEFAULTLIB /ENTRY:start /SUBSYSTEM:CONSOLE kernel32.lib */
#include <windows.h>

static unsigned sum_to(unsigned n) {
    unsigned acc = 0;
    for (unsigned i = 1; i <= n; i++) acc += i;
    return acc;
}

void start(void) {
    char msg[4] = {'X', 'A', 'X', '\n'};
    DWORD written;
    unsigned ok_write = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, 4, &written, 0);
    HANDLE heap = GetProcessHeap();
    void *block = HeapAlloc(heap, 0, 64);
    unsigned ok_free = HeapFree(heap, 0, block);
    ExitProcess(sum_to(10) + ok_write + ok_free);
}
