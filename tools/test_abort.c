// self-test for RC_GrandLocal_diag.dll hook machinery.
// argv[1]: "abort" -> calls abort()  |  "exit" -> calls ExitProcess(42)
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    HMODULE m = LoadLibraryA("RC_GrandLocal_diag.dll");
    if (!m) { printf("load fail %lu\n", GetLastError()); return 1; }
    printf("dll loaded, hooks should be installed\n");
    fflush(stdout);
    if (argc > 1 && !strcmp(argv[1], "exit")) {
        printf("calling ExitProcess(42)\n"); fflush(stdout);
        ExitProcess(42);
    }
    printf("calling abort()\n"); fflush(stdout);
    abort();
    return 0;
}
