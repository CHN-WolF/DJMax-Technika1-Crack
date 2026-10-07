// qpccheck.c — measure QPC vs GetTickCount drift over 3 seconds
#include <windows.h>
#include <stdio.h>
int main(void) {
    timeBeginPeriod(1);
    LARGE_INTEGER f, q0, q1;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&q0);
    DWORD t0 = GetTickCount();
    Sleep(3000);
    QueryPerformanceCounter(&q1);
    DWORD t1 = GetTickCount();
    double qpc_ms = (double)(q1.QuadPart - q0.QuadPart) * 1000.0 / (double)f.QuadPart;
    printf("freq=%lld  wall(GetTickCount)=%lu ms  QPC=%.1f ms  ratio=%.4f\n",
           f.QuadPart, (unsigned long)(t1 - t0), qpc_ms, qpc_ms / (double)(t1 - t0));
    return 0;
}
