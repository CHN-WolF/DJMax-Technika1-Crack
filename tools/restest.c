#include <windows.h>
#include <stdio.h>
static FILE* lf;
int main() {
    lf = fopen("rt.txt", "w"); setvbuf(lf, 0, _IONBF, 0);
    fprintf(lf, "step1: before load\n");
    HMODULE d = LoadLibraryA("RC_GrandLocal_replay.dll");
    fprintf(lf, "step2: replay=%p err=%lu\n", d, GetLastError());
    if (!d) return 1;
    HRSRC r = FindResourceA(d, "RCLOCALBIN", (LPCSTR)10);
    fprintf(lf, "step3: find=%p\n", r);
    if (!r) return 1;
    DWORD sz = SizeofResource(d, r);
    HGLOBAL g = LoadResource(d, r);
    void* p = LockResource(g);
    fprintf(lf, "step4: size=%lu head=%02x%02x\n", sz, ((BYTE*)p)[0], ((BYTE*)p)[1]);
    return 0;
}
