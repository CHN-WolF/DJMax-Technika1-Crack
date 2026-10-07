// ptffhook.dll — hook the PTFF decrypt loop (0x5d2830): log args, dump the
// decrypted buffer after the original runs. Also log v64 (0x5d2780 init).
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef unsigned int u32;
static FILE* g_log;
static int g_seq;

typedef u32 (WINAPI *DECF)(u32 buf, u32 len);
typedef u32 (WINAPI *INITF)(u32, u32, u32, u32);
static BYTE g_dec_tramp[16];
static BYTE g_init_tramp[16];
static u32 g_this, g_buf, g_len;

static u32 WINAPI my_dec(u32 buf, u32 len);
static u32 WINAPI my_init(u32 a, u32 b, u32 c, u32 d);

static void install(void* addr, void* detour, BYTE* tramp) {
    DWORD old;
    memcpy(tramp, addr, 5);
    tramp[5] = 0xE9;
    DWORD rel = (DWORD)((BYTE*)addr + 5) - (DWORD)(tramp + 10);
    memcpy(tramp + 6, &rel, 4);
    VirtualProtect(tramp, 16, PAGE_EXECUTE_READWRITE, &old);
    VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &old);
    BYTE jb[5] = { 0xE9, 0, 0, 0, 0 };
    rel = (DWORD)detour - (DWORD)((BYTE*)addr + 5);
    memcpy(jb + 1, &rel, 4);
    memcpy(addr, jb, 5);
    VirtualProtect(addr, 5, old, &old);
}

static DWORD WINAPI patcher(void* pv) {
    // delayed blind patch: wait for the game to fully load (blocks resident),
    // WITHOUT polling the protected code bytes (in-process reads trip anti-tamper).
    Sleep(90000);
    install((void*)0x5d2830, my_dec, g_dec_tramp);
    install((void*)0x5d2780, my_init, g_init_tramp);
    if (g_log) { fprintf(g_log, "hooks installed after delay\n"); fflush(g_log); }
    return 0;
}

// 0x5d2830: decrypt loop. ecx=this, [esp+4]=buf, [esp+8]=len. returns buf.
static u32 WINAPI my_dec(u32 buf, u32 len) {
    u32 thisp;
    __asm__ volatile ("mov %%ecx, %0" : "=r"(thisp));
    u32 r = ((DECF)g_dec_tramp)(buf, len);
    if (g_log) {
        fprintf(g_log, "decrypt this=%08x buf=%08x len=%u -> %08x\n", thisp, buf, len, r);
        char path[MAX_PATH];
        _snprintf(path, MAX_PATH, "tpkdump_out\\ptff_dec_%d.bin", g_seq++);
        FILE* f = fopen(path, "wb");
        if (f) { fwrite((void*)buf, 1, len, f); fclose(f); fprintf(g_log, "  wrote %s\n", path); }
        fflush(g_log);
    }
    return r;
}

// 0x5d2780: crypto init. ecx=this, args: lo, hi, buf, cnt.
static u32 WINAPI my_init(u32 a, u32 b, u32 c, u32 d) {
    u32 thisp;
    __asm__ volatile ("mov %%ecx, %0" : "=r"(thisp));
    u32 r = ((INITF)g_init_tramp)(a, b, c, d);
    if (g_log) { fprintf(g_log, "init this=%08x lo=%08x hi=%08x buf=%08x cnt=%u\n", thisp, a, b, c, d); fflush(g_log); }
    return r;
}

// ---- p02 file-IO logging (minimal: track read buffer VAs) ----
typedef struct { WORD Length, MaximumLength; WCHAR* Buffer; } USTR32;
typedef struct { DWORD Length; HANDLE RootDirectory; USTR32* ObjectName; DWORD Attributes; void* SD; void* SQS; } OA32;
typedef LONG (WINAPI *NCF)(HANDLE*, DWORD, OA32*, void*, void*, DWORD, DWORD, DWORD, DWORD, void*, DWORD);
typedef LONG (WINAPI *NRF)(HANDLE, HANDLE, void*, void*, void*, void*, DWORD, void*, void*);
static BYTE g_ncf_tramp[16], g_nrf_tramp[16];
static HANDLE g_p02h;

static LONG WINAPI my_NtCreateFile(HANDLE* fh, DWORD acc, OA32* oa, void* iosb, void* alloc,
                                   DWORD fattr, DWORD share, DWORD disp, DWORD copts, void* ea, DWORD ealen) {
    LONG r = ((NCF)g_ncf_tramp)(fh, acc, oa, iosb, alloc, fattr, share, disp, copts, ea, ealen);
    if (r >= 0 && fh && *fh && oa && oa->ObjectName && oa->ObjectName->Buffer) {
        USTR32* nm = oa->ObjectName;
        int is_p02 = 0;
        for (int i = 0; i + 3 < (int)(nm->Length / 2); i++)
            if ((nm->Buffer[i] == L'p' || nm->Buffer[i] == L'P') && nm->Buffer[i+1] == L'0' && nm->Buffer[i+2] == L'2' && nm->Buffer[i+3] == L'\\') { is_p02 = 1; break; }
        if (is_p02) {
            g_p02h = *fh;
            if (g_log) { fprintf(g_log, "p02 open h=%p\n", *fh); fflush(g_log); }
        }
    }
    return r;
}
static LONG WINAPI my_NtReadFile(HANDLE h, HANDLE ev, void* apc, void* apcctx, void* iosb,
                                 void* buf, DWORD len, void* off, void* key) {
    LONG r = ((NRF)g_nrf_tramp)(h, ev, apc, apcctx, iosb, buf, len, off, key);
    if (r >= 0 && h == g_p02h && g_log) { fprintf(g_log, "p02 read buf=%p len=%u\n", buf, len); fflush(g_log); }
    return r;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        CreateDirectoryA("tpkdump_out", NULL);
        g_log = fopen("tpkdump_out\\ptffhook.log", "w");
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        install(GetProcAddress(nt, "NtCreateFile"), my_NtCreateFile, g_ncf_tramp);
        install(GetProcAddress(nt, "NtReadFile"), my_NtReadFile, g_nrf_tramp);
        QueueUserWorkItem(patcher, 0, 0);
        if (g_log) { fprintf(g_log, "chartcap loaded\n"); fflush(g_log); }
    }
    return TRUE;
}
