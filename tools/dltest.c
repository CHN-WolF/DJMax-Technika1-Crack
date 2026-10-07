// dltest.c — LoadLibrary a DLL in this process (local DllMain test harness)
#include <windows.h>
#include <stdio.h>
int main(int argc, char** argv) {
    HMODULE m = LoadLibraryA(argv[1]);
    printf("LoadLibrary -> %p (err %lu)\n", m, GetLastError());
    if (m) { Sleep(500); printf("still alive\n"); }
    return 0;
}
