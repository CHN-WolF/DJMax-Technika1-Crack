// DJMax Technika 1 replay-dog v3 (portable, static CRT, with black-box log).
// Byte-exact replay of the real GrandDog responses, captured 2026-09-30.
// Real dog writes:
//   rc_OpenDog          : *(DWORD*)a3 = 0x11
//   rc_VerifyPassword   : *(BYTE*)a4  = 0xFF
//   rc_GetDogInfo       : writes a3[0] bytes (0x0D) at a2: aa3e0000 db1a0200 01554752 41
//   rc_GetProductCurrentNo: leaves buffer untouched
// Log: dogpatch_api.log in game dir.
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static FILE* g_lf;
static void lg(const char* fmt, ...) {
    if (!g_lf) { g_lf = fopen("dogpatch_api.log", "a"); if (g_lf) setvbuf(g_lf, 0, _IONBF, 0); }
    if (!g_lf) return;
    va_list ap; va_start(ap, fmt); vfprintf(g_lf, fmt, ap); va_end(ap);
}

__declspec(dllexport) int WINAPI rc_OpenDog(DWORD a1, DWORD a2, DWORD a3) {
    lg("rc_OpenDog(%x,%x,%x)\n", a1, a2, a3);
    if (a3 >= 0x10000) { __try { *(DWORD*)a3 = 0x11; } __except(1) {} }
    return 0;
}

__declspec(dllexport) int WINAPI rc_VerifyPassword(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    lg("rc_VerifyPassword(%x,%x,%x,%x)\n", a1, a2, a3, a4);
    if (a4 >= 0x10000) { __try { *(BYTE*)a4 = 0xFF; } __except(1) {} }
    return 0;
}

__declspec(dllexport) int WINAPI rc_GetDogInfo(DWORD a1, DWORD a2, DWORD a3) {
    static const BYTE blob[13] = {0xaa,0x3e,0x00,0x00, 0xdb,0x1a,0x02,0x00, 0x01,0x55,0x47,0x52, 0x41};
    lg("rc_GetDogInfo(%x,%x,%x)\n", a1, a2, a3);
    if (a2 >= 0x10000) {
        DWORD len = 13;
        if (a3 >= 0x10000) { __try { DWORD g = *(DWORD*)a3; if (g > 0 && g < 256) len = g; } __except(1) {} }
        __try {
            DWORD n = len > 13 ? 13 : len;
            memcpy((void*)a2, blob, n);
            if (len > 13) memset((void*)(a2 + 13), 0, len - 13);
        } __except(1) {}
    }
    return 0;
}

__declspec(dllexport) int WINAPI rc_GetProductCurrentNo(DWORD a1, DWORD a2) { return 0; }
__declspec(dllexport) int WINAPI rc_CloseDog(DWORD a1) { return 0; }
__declspec(dllexport) int WINAPI rc_CheckDog(DWORD a1) { return 0; }
__declspec(dllexport) int WINAPI rc_ChangePassword(DWORD a1, DWORD a2, DWORD a3) { return 0; }
__declspec(dllexport) int WINAPI rc_Upgrade(DWORD a1, DWORD a2, DWORD a3) { return 0; }
__declspec(dllexport) int WINAPI rc_UpgradeForDB(DWORD a1, DWORD a2) { return 0; }
__declspec(dllexport) int WINAPI rc_SetKey(DWORD a1, DWORD a2, DWORD a3, DWORD a4) { return 0; }
__declspec(dllexport) int WINAPI rc_SignData(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) { return 0; }
__declspec(dllexport) int WINAPI rc_ExecuteFile(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6, DWORD a7) { return 0; }
__declspec(dllexport) int WINAPI rc_WriteFile(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6) { return 0; }
__declspec(dllexport) int WINAPI rc_CreateFile(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) { return 0; }
__declspec(dllexport) int WINAPI rc_DeleteFile(DWORD a1, DWORD a2, DWORD a3) { return 0; }
__declspec(dllexport) int WINAPI rc_CreateDir(DWORD a1, DWORD a2, DWORD a3) { return 0; }
__declspec(dllexport) int WINAPI rc_DeleteDir(DWORD a1, DWORD a2) { return 0; }
__declspec(dllexport) int WINAPI rc_DefragFileSystem(DWORD a1, DWORD a2) { return 0; }
__declspec(dllexport) int WINAPI rc_GetUpgradeRequestString(DWORD a1, DWORD a2, DWORD a3) { return 0; }
__declspec(dllexport) int WINAPI rc_GetDogInfoForDB(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) { return 0; }
__declspec(dllexport) int WINAPI GetError(DWORD a1, DWORD a2) { return 0; }
__declspec(dllexport) int WINAPI rc_GetRandom(DWORD a1, DWORD a2, DWORD a3) { return 0; }
__declspec(dllexport) int WINAPI rc_EncryptData(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) { return 0; }
__declspec(dllexport) int WINAPI rc_DecryptData(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) { return 0; }
__declspec(dllexport) int WINAPI rc_ConvertData(DWORD a1, DWORD a2, DWORD a3, DWORD a4) { return 0; }
__declspec(dllexport) int WINAPI rc_ReadFile(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6) { return 0; }
__declspec(dllexport) int WINAPI rc_VisitLicenseFile(DWORD a1, DWORD a2, DWORD a3, DWORD a4) { return 0; }
