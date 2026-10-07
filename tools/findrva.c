// findrva.c — print module RVA of an export: findrva <dll> <name>
#include <windows.h>
#include <stdio.h>
int main(int argc, char** argv) {
    HMODULE m = GetModuleHandleA(argv[1]);
    if (!m) m = LoadLibraryA(argv[1]);
    if (!m) { printf("no module %s\n", argv[1]); return 1; }
    void* f = (void*)GetProcAddress(m, argv[2]);
    printf("%s!%s = %p (rva %08lx)\n", argv[1], argv[2], f, (DWORD)(BYTE*)f - (DWORD)m);
    return 0;
}
