
#include <windows.h>
#include <stdio.h>

static HMODULE hReal = 0;
static FILE* g_log = 0;
static CRITICAL_SECTION g_cs;

static void log_open() {
    if (!g_log) {
        g_log = fopen("rclog.txt", "a");
        if (g_log) setvbuf(g_log, 0, _IONBF, 0);
    }
}
static void LOG(const char* fmt, ...) {
    if (!g_log) return;
    EnterCriticalSection(&g_cs);
    va_list ap; va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    LeaveCriticalSection(&g_cs);
}
static void dumpbuf(const char* tag, DWORD p) {
    if (p < 0x10000) return;
    unsigned char b[16];
    for (int off = 0; off < 512; off += 16) {
        __try { memcpy(b, (void*)(p + off), 16); }
        __except(1) { return; }
        LOG("    %s+%03x: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x | %.16s\n",
            tag, off, b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15], b);
    }
}

typedef int (WINAPI *t_GetError)(DWORD a1, DWORD a2);
typedef int (WINAPI *t_rc_ChangePassword)(DWORD a1, DWORD a2, DWORD a3);
typedef int (WINAPI *t_rc_CheckDog)(DWORD a1);
typedef int (WINAPI *t_rc_CloseDog)(DWORD a1);
typedef int (WINAPI *t_rc_ConvertData)(DWORD a1, DWORD a2, DWORD a3, DWORD a4);
typedef int (WINAPI *t_rc_CreateDir)(DWORD a1, DWORD a2, DWORD a3);
typedef int (WINAPI *t_rc_CreateFile)(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5);
typedef int (WINAPI *t_rc_DecryptData)(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5);
typedef int (WINAPI *t_rc_DefragFileSystem)(DWORD a1, DWORD a2);
typedef int (WINAPI *t_rc_DeleteDir)(DWORD a1, DWORD a2);
typedef int (WINAPI *t_rc_DeleteFile)(DWORD a1, DWORD a2, DWORD a3);
typedef int (WINAPI *t_rc_EncryptData)(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5);
typedef int (WINAPI *t_rc_ExecuteFile)(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6, DWORD a7);
typedef int (WINAPI *t_rc_GetDogInfo)(DWORD a1, DWORD a2, DWORD a3);
typedef int (WINAPI *t_rc_GetDogInfoForDB)(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5);
typedef int (WINAPI *t_rc_GetProductCurrentNo)(DWORD a1, DWORD a2);
typedef int (WINAPI *t_rc_GetRandom)(DWORD a1, DWORD a2, DWORD a3);
typedef int (WINAPI *t_rc_GetUpgradeRequestString)(DWORD a1, DWORD a2, DWORD a3);
typedef int (WINAPI *t_rc_OpenDog)(DWORD a1, DWORD a2, DWORD a3);
typedef int (WINAPI *t_rc_ReadFile)(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6);
typedef int (WINAPI *t_rc_SetKey)(DWORD a1, DWORD a2, DWORD a3, DWORD a4);
typedef int (WINAPI *t_rc_SignData)(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5);
typedef int (WINAPI *t_rc_Upgrade)(DWORD a1, DWORD a2, DWORD a3);
typedef int (WINAPI *t_rc_UpgradeForDB)(DWORD a1, DWORD a2);
typedef int (WINAPI *t_rc_VerifyPassword)(DWORD a1, DWORD a2, DWORD a3, DWORD a4);
typedef int (WINAPI *t_rc_VisitLicenseFile)(DWORD a1, DWORD a2, DWORD a3, DWORD a4);
typedef int (WINAPI *t_rc_WriteFile)(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6);

static t_GetError p_GetError;
static t_rc_ChangePassword p_rc_ChangePassword;
static t_rc_CheckDog p_rc_CheckDog;
static t_rc_CloseDog p_rc_CloseDog;
static t_rc_ConvertData p_rc_ConvertData;
static t_rc_CreateDir p_rc_CreateDir;
static t_rc_CreateFile p_rc_CreateFile;
static t_rc_DecryptData p_rc_DecryptData;
static t_rc_DefragFileSystem p_rc_DefragFileSystem;
static t_rc_DeleteDir p_rc_DeleteDir;
static t_rc_DeleteFile p_rc_DeleteFile;
static t_rc_EncryptData p_rc_EncryptData;
static t_rc_ExecuteFile p_rc_ExecuteFile;
static t_rc_GetDogInfo p_rc_GetDogInfo;
static t_rc_GetDogInfoForDB p_rc_GetDogInfoForDB;
static t_rc_GetProductCurrentNo p_rc_GetProductCurrentNo;
static t_rc_GetRandom p_rc_GetRandom;
static t_rc_GetUpgradeRequestString p_rc_GetUpgradeRequestString;
static t_rc_OpenDog p_rc_OpenDog;
static t_rc_ReadFile p_rc_ReadFile;
static t_rc_SetKey p_rc_SetKey;
static t_rc_SignData p_rc_SignData;
static t_rc_Upgrade p_rc_Upgrade;
static t_rc_UpgradeForDB p_rc_UpgradeForDB;
static t_rc_VerifyPassword p_rc_VerifyPassword;
static t_rc_VisitLicenseFile p_rc_VisitLicenseFile;
static t_rc_WriteFile p_rc_WriteFile;

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_cs);
        log_open();
        hReal = LoadLibraryA("RCGrandDogW32Real.dll");
        LOG("=== logger attached, hReal=%p\n", hReal);
        if (!hReal) return TRUE;
        p_GetError = (t_GetError)GetProcAddress(hReal, "GetError");
        p_rc_ChangePassword = (t_rc_ChangePassword)GetProcAddress(hReal, "rc_ChangePassword");
        p_rc_CheckDog = (t_rc_CheckDog)GetProcAddress(hReal, "rc_CheckDog");
        p_rc_CloseDog = (t_rc_CloseDog)GetProcAddress(hReal, "rc_CloseDog");
        p_rc_ConvertData = (t_rc_ConvertData)GetProcAddress(hReal, "rc_ConvertData");
        p_rc_CreateDir = (t_rc_CreateDir)GetProcAddress(hReal, "rc_CreateDir");
        p_rc_CreateFile = (t_rc_CreateFile)GetProcAddress(hReal, "rc_CreateFile");
        p_rc_DecryptData = (t_rc_DecryptData)GetProcAddress(hReal, "rc_DecryptData");
        p_rc_DefragFileSystem = (t_rc_DefragFileSystem)GetProcAddress(hReal, "rc_DefragFileSystem");
        p_rc_DeleteDir = (t_rc_DeleteDir)GetProcAddress(hReal, "rc_DeleteDir");
        p_rc_DeleteFile = (t_rc_DeleteFile)GetProcAddress(hReal, "rc_DeleteFile");
        p_rc_EncryptData = (t_rc_EncryptData)GetProcAddress(hReal, "rc_EncryptData");
        p_rc_ExecuteFile = (t_rc_ExecuteFile)GetProcAddress(hReal, "rc_ExecuteFile");
        p_rc_GetDogInfo = (t_rc_GetDogInfo)GetProcAddress(hReal, "rc_GetDogInfo");
        p_rc_GetDogInfoForDB = (t_rc_GetDogInfoForDB)GetProcAddress(hReal, "rc_GetDogInfoForDB");
        p_rc_GetProductCurrentNo = (t_rc_GetProductCurrentNo)GetProcAddress(hReal, "rc_GetProductCurrentNo");
        p_rc_GetRandom = (t_rc_GetRandom)GetProcAddress(hReal, "rc_GetRandom");
        p_rc_GetUpgradeRequestString = (t_rc_GetUpgradeRequestString)GetProcAddress(hReal, "rc_GetUpgradeRequestString");
        p_rc_OpenDog = (t_rc_OpenDog)GetProcAddress(hReal, "rc_OpenDog");
        p_rc_ReadFile = (t_rc_ReadFile)GetProcAddress(hReal, "rc_ReadFile");
        p_rc_SetKey = (t_rc_SetKey)GetProcAddress(hReal, "rc_SetKey");
        p_rc_SignData = (t_rc_SignData)GetProcAddress(hReal, "rc_SignData");
        p_rc_Upgrade = (t_rc_Upgrade)GetProcAddress(hReal, "rc_Upgrade");
        p_rc_UpgradeForDB = (t_rc_UpgradeForDB)GetProcAddress(hReal, "rc_UpgradeForDB");
        p_rc_VerifyPassword = (t_rc_VerifyPassword)GetProcAddress(hReal, "rc_VerifyPassword");
        p_rc_VisitLicenseFile = (t_rc_VisitLicenseFile)GetProcAddress(hReal, "rc_VisitLicenseFile");
        p_rc_WriteFile = (t_rc_WriteFile)GetProcAddress(hReal, "rc_WriteFile");
    }
    return TRUE;
}


__declspec(dllexport) int WINAPI GetError(DWORD a1, DWORD a2) {
    LOG("GetError(%08x, %08x)\n", a1, a2);
    int ret = p_GetError ? p_GetError(a1, a2) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    return ret;
}

__declspec(dllexport) int WINAPI rc_ChangePassword(DWORD a1, DWORD a2, DWORD a3) {
    LOG("rc_ChangePassword(%08x, %08x, %08x)\n", a1, a2, a3);
    int ret = p_rc_ChangePassword ? p_rc_ChangePassword(a1, a2, a3) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    return ret;
}

__declspec(dllexport) int WINAPI rc_CheckDog(DWORD a1) {
    LOG("rc_CheckDog(%08x)\n", a1);
    dumpbuf("a1-pre", a1);
    int ret = p_rc_CheckDog ? p_rc_CheckDog(a1) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1-post", a1);
    return ret;
}

__declspec(dllexport) int WINAPI rc_CloseDog(DWORD a1) {
    LOG("rc_CloseDog(%08x)\n", a1);
    int ret = p_rc_CloseDog ? p_rc_CloseDog(a1) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    return ret;
}

__declspec(dllexport) int WINAPI rc_ConvertData(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    LOG("rc_ConvertData(%08x, %08x, %08x, %08x)\n", a1, a2, a3, a4);
    int ret = p_rc_ConvertData ? p_rc_ConvertData(a1, a2, a3, a4) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1", a1);
    dumpbuf("a2", a2);
    dumpbuf("a3", a3);
    dumpbuf("a4", a4);
    return ret;
}

__declspec(dllexport) int WINAPI rc_CreateDir(DWORD a1, DWORD a2, DWORD a3) {
    LOG("rc_CreateDir(%08x, %08x, %08x)\n", a1, a2, a3);
    int ret = p_rc_CreateDir ? p_rc_CreateDir(a1, a2, a3) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    return ret;
}

__declspec(dllexport) int WINAPI rc_CreateFile(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    LOG("rc_CreateFile(%08x, %08x, %08x, %08x, %08x)\n", a1, a2, a3, a4, a5);
    int ret = p_rc_CreateFile ? p_rc_CreateFile(a1, a2, a3, a4, a5) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    return ret;
}

__declspec(dllexport) int WINAPI rc_DecryptData(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    LOG("rc_DecryptData(%08x, %08x, %08x, %08x, %08x)\n", a1, a2, a3, a4, a5);
    int ret = p_rc_DecryptData ? p_rc_DecryptData(a1, a2, a3, a4, a5) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1", a1);
    dumpbuf("a2", a2);
    dumpbuf("a3", a3);
    dumpbuf("a4", a4);
    dumpbuf("a5", a5);
    return ret;
}

__declspec(dllexport) int WINAPI rc_DefragFileSystem(DWORD a1, DWORD a2) {
    LOG("rc_DefragFileSystem(%08x, %08x)\n", a1, a2);
    int ret = p_rc_DefragFileSystem ? p_rc_DefragFileSystem(a1, a2) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    return ret;
}

__declspec(dllexport) int WINAPI rc_DeleteDir(DWORD a1, DWORD a2) {
    LOG("rc_DeleteDir(%08x, %08x)\n", a1, a2);
    int ret = p_rc_DeleteDir ? p_rc_DeleteDir(a1, a2) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    return ret;
}

__declspec(dllexport) int WINAPI rc_DeleteFile(DWORD a1, DWORD a2, DWORD a3) {
    LOG("rc_DeleteFile(%08x, %08x, %08x)\n", a1, a2, a3);
    int ret = p_rc_DeleteFile ? p_rc_DeleteFile(a1, a2, a3) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    return ret;
}

__declspec(dllexport) int WINAPI rc_EncryptData(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    LOG("rc_EncryptData(%08x, %08x, %08x, %08x, %08x)\n", a1, a2, a3, a4, a5);
    int ret = p_rc_EncryptData ? p_rc_EncryptData(a1, a2, a3, a4, a5) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1", a1);
    dumpbuf("a2", a2);
    dumpbuf("a3", a3);
    dumpbuf("a4", a4);
    dumpbuf("a5", a5);
    return ret;
}

__declspec(dllexport) int WINAPI rc_ExecuteFile(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6, DWORD a7) {
    LOG("rc_ExecuteFile(%08x, %08x, %08x, %08x, %08x, %08x, %08x)\n", a1, a2, a3, a4, a5, a6, a7);
    int ret = p_rc_ExecuteFile ? p_rc_ExecuteFile(a1, a2, a3, a4, a5, a6, a7) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1", a1);
    dumpbuf("a2", a2);
    dumpbuf("a3", a3);
    dumpbuf("a4", a4);
    dumpbuf("a5", a5);
    dumpbuf("a6", a6);
    dumpbuf("a7", a7);
    return ret;
}

__declspec(dllexport) int WINAPI rc_GetDogInfo(DWORD a1, DWORD a2, DWORD a3) {
    LOG("rc_GetDogInfo(%08x, %08x, %08x)\n", a1, a2, a3);
    dumpbuf("a2-pre", a2);
    dumpbuf("a3-pre", a3);
    int ret = p_rc_GetDogInfo ? p_rc_GetDogInfo(a1, a2, a3) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1-post", a1);
    dumpbuf("a2-post", a2);
    dumpbuf("a3-post", a3);
    return ret;
}

__declspec(dllexport) int WINAPI rc_GetDogInfoForDB(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    LOG("rc_GetDogInfoForDB(%08x, %08x, %08x, %08x, %08x)\n", a1, a2, a3, a4, a5);
    int ret = p_rc_GetDogInfoForDB ? p_rc_GetDogInfoForDB(a1, a2, a3, a4, a5) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1", a1);
    dumpbuf("a2", a2);
    dumpbuf("a3", a3);
    dumpbuf("a4", a4);
    dumpbuf("a5", a5);
    return ret;
}

__declspec(dllexport) int WINAPI rc_GetProductCurrentNo(DWORD a1, DWORD a2) {
    LOG("rc_GetProductCurrentNo(%08x, %08x)\n", a1, a2);
    dumpbuf("a2-pre", a2);
    int ret = p_rc_GetProductCurrentNo ? p_rc_GetProductCurrentNo(a1, a2) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1-post", a1);
    dumpbuf("a2-post", a2);
    return ret;
}

__declspec(dllexport) int WINAPI rc_GetRandom(DWORD a1, DWORD a2, DWORD a3) {
    LOG("rc_GetRandom(%08x, %08x, %08x)\n", a1, a2, a3);
    int ret = p_rc_GetRandom ? p_rc_GetRandom(a1, a2, a3) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1", a1);
    dumpbuf("a2", a2);
    dumpbuf("a3", a3);
    return ret;
}

__declspec(dllexport) int WINAPI rc_GetUpgradeRequestString(DWORD a1, DWORD a2, DWORD a3) {
    LOG("rc_GetUpgradeRequestString(%08x, %08x, %08x)\n", a1, a2, a3);
    int ret = p_rc_GetUpgradeRequestString ? p_rc_GetUpgradeRequestString(a1, a2, a3) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1", a1);
    dumpbuf("a2", a2);
    dumpbuf("a3", a3);
    return ret;
}

__declspec(dllexport) int WINAPI rc_OpenDog(DWORD a1, DWORD a2, DWORD a3) {
    LOG("rc_OpenDog(%08x, %08x, %08x)\n", a1, a2, a3);
    dumpbuf("a2-pre", a2);
    dumpbuf("a3-pre", a3);
    int ret = p_rc_OpenDog ? p_rc_OpenDog(a1, a2, a3) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a2-post", a2);
    dumpbuf("a3-post", a3);
    return ret;
}

__declspec(dllexport) int WINAPI rc_ReadFile(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6) {
    LOG("rc_ReadFile(%08x, %08x, %08x, %08x, %08x, %08x)\n", a1, a2, a3, a4, a5, a6);
    int ret = p_rc_ReadFile ? p_rc_ReadFile(a1, a2, a3, a4, a5, a6) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1", a1);
    dumpbuf("a2", a2);
    dumpbuf("a3", a3);
    dumpbuf("a4", a4);
    dumpbuf("a5", a5);
    dumpbuf("a6", a6);
    return ret;
}

__declspec(dllexport) int WINAPI rc_SetKey(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    LOG("rc_SetKey(%08x, %08x, %08x, %08x)\n", a1, a2, a3, a4);
    int ret = p_rc_SetKey ? p_rc_SetKey(a1, a2, a3, a4) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1", a1);
    dumpbuf("a2", a2);
    dumpbuf("a3", a3);
    dumpbuf("a4", a4);
    return ret;
}

__declspec(dllexport) int WINAPI rc_SignData(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    LOG("rc_SignData(%08x, %08x, %08x, %08x, %08x)\n", a1, a2, a3, a4, a5);
    int ret = p_rc_SignData ? p_rc_SignData(a1, a2, a3, a4, a5) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1", a1);
    dumpbuf("a2", a2);
    dumpbuf("a3", a3);
    dumpbuf("a4", a4);
    dumpbuf("a5", a5);
    return ret;
}

__declspec(dllexport) int WINAPI rc_Upgrade(DWORD a1, DWORD a2, DWORD a3) {
    LOG("rc_Upgrade(%08x, %08x, %08x)\n", a1, a2, a3);
    int ret = p_rc_Upgrade ? p_rc_Upgrade(a1, a2, a3) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    return ret;
}

__declspec(dllexport) int WINAPI rc_UpgradeForDB(DWORD a1, DWORD a2) {
    LOG("rc_UpgradeForDB(%08x, %08x)\n", a1, a2);
    int ret = p_rc_UpgradeForDB ? p_rc_UpgradeForDB(a1, a2) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    return ret;
}

__declspec(dllexport) int WINAPI rc_VerifyPassword(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    LOG("rc_VerifyPassword(%08x, %08x, %08x, %08x)\n", a1, a2, a3, a4);
    dumpbuf("a3-pre", a3);
    dumpbuf("a4-pre", a4);
    int ret = p_rc_VerifyPassword ? p_rc_VerifyPassword(a1, a2, a3, a4) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a3-post", a3);
    dumpbuf("a4-post", a4);
    return ret;
}

__declspec(dllexport) int WINAPI rc_VisitLicenseFile(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    LOG("rc_VisitLicenseFile(%08x, %08x, %08x, %08x)\n", a1, a2, a3, a4);
    int ret = p_rc_VisitLicenseFile ? p_rc_VisitLicenseFile(a1, a2, a3, a4) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    dumpbuf("a1", a1);
    dumpbuf("a2", a2);
    dumpbuf("a3", a3);
    dumpbuf("a4", a4);
    return ret;
}

__declspec(dllexport) int WINAPI rc_WriteFile(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6) {
    LOG("rc_WriteFile(%08x, %08x, %08x, %08x, %08x, %08x)\n", a1, a2, a3, a4, a5, a6);
    int ret = p_rc_WriteFile ? p_rc_WriteFile(a1, a2, a3, a4, a5, a6) : -999;
    LOG("  -> %d (0x%x)\n", ret, ret);
    return ret;
}