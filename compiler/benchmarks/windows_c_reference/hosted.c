/* Semantic twin of tests/test_xax_pe.py::hosted_fixture (exit status 1339).
   No CRT, like the XAX artifact.  MinGW-w64 build (bench_windows_pe_c_wine.py):
     x86_64-w64-mingw32-gcc -O2 -nostdlib -ffreestanding -fno-asynchronous-unwind-tables \
       -e start -s -o hosted.exe hosted.c -lkernel32
   MSVC equivalent: cl /O2 /GS- hosted.c /link /NODEFAULTLIB /ENTRY:start /SUBSYSTEM:CONSOLE kernel32.lib */
#include <windows.h>

static unsigned sum_to(unsigned n) {
    unsigned acc = 0;
    for (unsigned i = 1; i <= n; i++) acc += i;
    return acc;
}

/* 16 x u32 in zero-filled VirtualAlloc pages: store i*i, sum, VirtualFree. */
static unsigned squares_sum(void) {
    unsigned *values = VirtualAlloc(0, 64, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    unsigned acc = 0;
    for (unsigned i = 0; i < 16; i++) values[i] = i * i;
    for (unsigned i = 0; i < 16; i++) acc += values[i];
    return acc + (unsigned)VirtualFree(values, 0, MEM_RELEASE);
}

static unsigned add1(unsigned x) { return x + 1; }
static unsigned times3(unsigned x) { return x * 3; }

/* A two-entry function-pointer table in stack memory, called through loaded entries. */
static unsigned dispatch(void) {
    unsigned (*table[2])(unsigned) = {add1, times3};
    return table[0](10) + table[1](10);
}

void start(void) {
    char msg[4] = {'X', 'A', 'X', '\n'};
    DWORD written = 0;
    unsigned ok_write = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, 4, &written, 0);
    HANDLE heap = GetProcessHeap();
    void *block = HeapAlloc(heap, 0, 64);
    unsigned ok_free = HeapFree(heap, 0, block);
    ExitProcess(sum_to(10) + ok_write + ok_free + squares_sum() + dispatch());
}
