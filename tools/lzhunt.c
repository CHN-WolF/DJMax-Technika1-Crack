// lzhunt.dll — find the game's LZ decompressor: hook NtReadFile for c00.tpk,
// wait for the in-place AES decryption to finish, then PAGE_GUARD the decrypted
// body; whoever reads it (parser / decompressor) faults with EIP logged.
// The LZ reader is a tight loop => same EIP repeatedly with advancing address.
#include <windows.h>
#include <stdio.h>
#include <string.h>

static FILE* g_log;
static CRITICAL_SECTION g_cs;
static BYTE* g_buf;
static DWORD g_total;
static int g_armed;
static int g_hits;

typedef struct { BYTE tramp[16]; } HOOK;
static int patch(void* addr, void* detour, BYTE* tramp) {
    DWORD old;
    memcpy(tramp, addr, 5);
    tramp[5] = 0xE9;
    DWORD rel = (DWORD)((BYTE*)addr + 5) - (DWORD)(tramp + 10);
    memcpy(tramp + 6, &rel, 4);
    if (!VirtualProtect(tramp, 16, PAGE_EXECUTE_READWRITE, &old)) return 0;
    if (!VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &old)) return 0;
    BYTE jb[5] = { 0xE9, 0, 0, 0, 0 };
    rel = (DWORD)detour - (DWORD)((BYTE*)addr + 5);
    memcpy(jb + 1, &rel, 4);
    memcpy(addr, jb, 5);
    VirtualProtect(addr, 5, old, &old);
    return 1;
}

typedef LONG (WINAPI *NRF)(HANDLE, HANDLE, void*, void*, void*, void*, DWORD, void*, void*);
static HOOK g_nrf;
static LONG WINAPI my_NtReadFile(HANDLE h, HANDLE ev, void* apc, void* apcctx, void* iosb,
                                 void* buf, DWORD len, void* off, void* key) {
    LONG r = ((NRF)g_nrf.tramp)(h, ev, apc, apcctx, iosb, buf, len, off, key);
    if (r >= 0 && buf && len > 1000000) {
        g_buf = (BYTE*)buf;
        g_total = len;
        DWORD old;
        VirtualProtect(g_buf, g_total, PAGE_GUARD | PAGE_READWRITE, &old);
        if (g_log) { fprintf(g_log, "big read buf=%p len=%u -> guard armed immediately\n", buf, len); fflush(g_log); }
    }
    return r;
}

static DWORD g_rearm;
static LONG WINAPI veh(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == 0x80000001) {
        DWORD addr = ep->ExceptionRecord->ExceptionInformation[1];
        DWORD eip = (DWORD)ep->ExceptionRecord->ExceptionAddress;
        if (!g_buf || addr < (DWORD)g_buf || addr >= (DWORD)g_buf + g_total)
            return EXCEPTION_CONTINUE_SEARCH;   // not ours (stack growth etc.)
        int isAES = (eip >= 0x5ac000 && eip <= 0x5ae000);
        if (!isAES) {
            EnterCriticalSection(&g_cs);
            // chase: guard the copy destination page too (decompressor reads it)
            DWORD dst = ep->ContextRecord->Edi;
            DWORD old2;
            VirtualProtect((LPVOID)(dst & ~0xfff), 1, PAGE_GUARD | PAGE_READWRITE, &old2);
            if (g_log && g_hits < 400) {
                fprintf(g_log, "hit %d: eip=%08x read=%08x (body+%u) esi=%08x edi=%08x ecx=%08x edx=%08x eax=%08x\n",
                        g_hits, eip, addr, addr - (DWORD)g_buf - 12,
                        ep->ContextRecord->Esi, ep->ContextRecord->Edi,
                        ep->ContextRecord->Ecx, ep->ContextRecord->Edx, ep->ContextRecord->Eax);
                fflush(g_log);
            }
            g_hits++;
            LeaveCriticalSection(&g_cs);
        }
        // re-arm this page AFTER the faulting instruction completes (TF -> single-step)
        g_rearm = addr & ~0xfff;
        ep->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code == 0x80000004) {  // single-step: rearm now
        if (g_rearm) {
            DWORD old;
            VirtualProtect((LPVOID)g_rearm, 1, PAGE_GUARD | PAGE_READWRITE, &old);
            g_rearm = 0;
        }
        ep->ContextRecord->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// poll thread: when the buffer shows decrypted content ("resource/" present),
// arm the guard
static DWORD WINAPI armer(void* pv) {
    Sleep(600);  // let the big read land
    for (int t = 0; t < 120 && !g_armed; t++) {
        if (g_buf) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(g_buf, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT) {
                // arm on the compressed-entries area (font.xml etc. around body+620k..624k)
                DWORD base = (DWORD)g_buf + 12 + 618000;
                DWORD old;
                VirtualProtect((void*)base, 8192, PAGE_GUARD | PAGE_READWRITE, &old);
                g_armed = 1;
                if (g_log) { fprintf(g_log, "guard armed on %p (body+618000)\n", (void*)base); fflush(g_log); }
                break;
            }
        }
        Sleep(50);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_cs);
        CreateDirectoryA("tpkdump_out", NULL);
        g_log = fopen("tpkdump_out\\lzhunt.log", "w");
        AddVectoredExceptionHandler(1, veh);
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        patch(GetProcAddress(nt, "NtReadFile"), my_NtReadFile, g_nrf.tramp);
        QueueUserWorkItem(armer, 0, 0);
        if (g_log) { fprintf(g_log, "lzhunt loaded\n"); fflush(g_log); }
    }
    return TRUE;
}
