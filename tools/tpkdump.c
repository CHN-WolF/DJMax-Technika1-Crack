// tpkdump.dll v3 — runtime oracle for tpk. Hooks the NTDLL layer (the game's
// file IO goes through Themida wrappers = direct syscalls, kernel32 hooks see
// nothing): NtCreateFile / NtReadFile / NtClose, plus kernel32 mmap chain and
// PAGE_GUARD on tpk-backed views to catch the decryptor's EIP.
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <string.h>

#define MAXH 128
static struct { HANDLE h; char name[128]; BYTE* buf; DWORD total; int dirty; int is_p02; BYTE snap[64]; } g_trk[MAXH];
static int g_ntrk;
static struct { BYTE* base; DWORD size; } g_view[32]; static int g_nview;
static CRITICAL_SECTION g_cs;
static FILE* g_log;
static int g_hits;
#define HIT_BUDGET 256

// ---- inline hook machinery ----
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

// ---- native types ----
typedef struct { WORD Length, MaximumLength; WCHAR* Buffer; } USTR32;
typedef struct { DWORD Length; HANDLE RootDirectory; USTR32* ObjectName; DWORD Attributes; void* SD; void* SQS; } OA32;
typedef LONG (WINAPI *NCF)(HANDLE*, DWORD, OA32*, void*, void*, DWORD, DWORD, DWORD, DWORD, void*, DWORD);
typedef LONG (WINAPI *NRF)(HANDLE, HANDLE, void*, void*, void*, void*, DWORD, void*, void*);
typedef LONG (WINAPI *NCLOSE)(HANDLE);
static HOOK g_ncf, g_nrf, g_nclose;

static int tail_tpkW(const WCHAR* p, int chars) {
    if (chars < 4) return 0;
    const WCHAR* e = p + chars - 4;
    if (e[0] == L'.' && (e[1] | 32) == L't' && (e[2] | 32) == L'p' && (e[3] | 32) == L'k') return 1;
    // also catch p02\ hash-named files (PTFF reachability probe)
    for (int i = 0; i + 4 < chars; i++)
        if ((p[i] == L'p' || p[i] == L'P') && p[i+1] == L'0' && p[i+2] == L'2' && p[i+3] == L'\\') return 2;
    return 0;
}

static void track_handle(HANDLE h, const WCHAR* wname, int wlen, int is_p02) {
    if (!h) return;
    char n8[128];
    int n = WideCharToMultiByte(CP_ACP, 0, wname, wlen, n8, 127, 0, 0);
    n8[n] = 0;
    EnterCriticalSection(&g_cs);
    if (g_ntrk < MAXH) {
        g_trk[g_ntrk].h = h;
        _snprintf(g_trk[g_ntrk].name, 127, "%s", n8);
        g_trk[g_ntrk].buf = 0; g_trk[g_ntrk].total = 0; g_trk[g_ntrk].dirty = 0;
        g_trk[g_ntrk].is_p02 = is_p02;
        g_ntrk++;
        if (g_log) { fprintf(g_log, "open%s %s h=%p\n", is_p02 ? "(p02)" : "", n8, h); fflush(g_log); }
    }
    LeaveCriticalSection(&g_cs);
}

static LONG WINAPI my_NtCreateFile(HANDLE* fh, DWORD acc, OA32* oa, void* iosb, void* alloc,
                                   DWORD fattr, DWORD share, DWORD disp, DWORD copts, void* ea, DWORD ealen) {
    LONG r = ((NCF)g_ncf.tramp)(fh, acc, oa, iosb, alloc, fattr, share, disp, copts, ea, ealen);
    if (r >= 0 && fh && *fh && oa && oa->ObjectName && oa->ObjectName->Buffer) {
        USTR32* nm = oa->ObjectName;
        int mm = tail_tpkW(nm->Buffer, nm->Length / 2);
        if (mm) track_handle(*fh, nm->Buffer, nm->Length / 2, mm == 2);
        else if (g_log) {
            // log ALL other opens (find out who/what reads p02 or chart data)
            char n8[160];
            int n = WideCharToMultiByte(CP_ACP, 0, nm->Buffer, nm->Length / 2, n8, 159, 0, 0);
            n8[n] = 0;
            const char* sl = strrchr(n8, '\\');
            fprintf(g_log, "open* %s\n", sl ? sl + 1 : n8);
            fflush(g_log);
        }
    }
    return r;
}

static LONG WINAPI my_NtReadFile(HANDLE h, HANDLE ev, void* apc, void* apcctx, void* iosb,
                                 void* buf, DWORD len, void* off, void* key) {
    LONG r = ((NRF)g_nrf.tramp)(h, ev, apc, apcctx, iosb, buf, len, off, key);
    if (r >= 0 && buf && len) {
        EnterCriticalSection(&g_cs);
        for (int i = 0; i < g_ntrk; i++) if (g_trk[i].h == h) {
            if (!g_trk[i].buf) {
                g_trk[i].buf = (BYTE*)buf;
                memcpy(g_trk[i].snap, buf, len < 64 ? len : 64);
            }
            DWORD end = (DWORD)((BYTE*)buf - g_trk[i].buf) + len;
            if (end > g_trk[i].total) g_trk[i].total = end;
            if (!g_trk[i].dirty && memcmp(g_trk[i].snap, buf, len < 64 ? len : 64)) g_trk[i].dirty = 1;
            if (g_log) { fprintf(g_log, "read h=%p buf=%p len=%u\n", h, buf, len); fflush(g_log); }
            // p02 charts: the PTFF decryptor reads the ciphertext from this buffer
            // later -> arm PAGE_GUARD so its read faults with EIP logged (veh).
            if (g_trk[i].is_p02 && g_trk[i].total >= 16 && g_nview < 32) {
                DWORD already = 0;
                for (int v = 0; v < g_nview; v++) if (g_view[v].base == g_trk[i].buf) already = 1;
                if (!already) {
                    g_view[g_nview].base = g_trk[i].buf;
                    g_view[g_nview].size = g_trk[i].total;
                    g_nview++;
                    DWORD old;
                    VirtualProtect(g_trk[i].buf, g_trk[i].total, PAGE_GUARD | PAGE_READWRITE, &old);
                    if (g_log) { fprintf(g_log, "p02 guard armed buf=%p size=%u\n", g_trk[i].buf, g_trk[i].total); fflush(g_log); }
                }
            }
            break;
        }
        LeaveCriticalSection(&g_cs);
    }
    return r;
}

// NtWriteFile: dump writes to tracked handles (p02 cache writes = plaintext before encryption?)
typedef LONG (WINAPI *NWF)(HANDLE, HANDLE, void*, void*, void*, void*, DWORD, void*, void*);
static HOOK g_nwf;
static LONG WINAPI my_NtWriteFile(HANDLE h, HANDLE ev, void* apc, void* apcctx, void* iosb,
                                  void* buf, DWORD len, void* off, void* key) {
    if (buf && len) {
        EnterCriticalSection(&g_cs);
        for (int i = 0; i < g_ntrk; i++) if (g_trk[i].h == h) {
            if (g_log) { fprintf(g_log, "WRITE %s len=%u\n", g_trk[i].name, len); fflush(g_log); }
            char path[MAX_PATH];
            const char* bn = strrchr(g_trk[i].name, '\\'); bn = bn ? bn + 1 : g_trk[i].name;
            static int wseq;
            _snprintf(path, MAX_PATH, "tpkdump_out\\w%03d_%s.bin", wseq++, bn);
            FILE* f = fopen(path, "wb");
            if (f) { fwrite(buf, 1, len, f); fclose(f); }
            break;
        }
        LeaveCriticalSection(&g_cs);
    }
    return ((NWF)g_nwf.tramp)(h, ev, apc, apcctx, iosb, buf, len, off, key);
}

static DWORD WINAPI delayed_dump(void* pv) {
    int i = (int)(DWORD_PTR)pv;
    Sleep(1500);
    EnterCriticalSection(&g_cs);
    BYTE* buf = g_trk[i].buf;
    DWORD total = g_trk[i].total;
    char name[128]; _snprintf(name, 127, "%s", g_trk[i].name);
    int valid = 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (buf && VirtualQuery(buf, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT) valid = 1;
    if (valid && buf && total > 0) {
        char path[MAX_PATH];
        const char* bn = strrchr(name, '\\'); bn = bn ? bn + 1 : name;
        _snprintf(path, MAX_PATH, "tpkdump_out\\dec_%s.bin", bn);
        FILE* f = fopen(path, "wb");
        if (f) { fwrite(buf, 1, total, f); fclose(f); }
        if (g_log) { fprintf(g_log, "delayed-dump %s total=%u\n", path, total); fflush(g_log); }
    }
    LeaveCriticalSection(&g_cs);
    return 0;
}

static LONG WINAPI my_NtClose(HANDLE h) {
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_ntrk; i++) if (g_trk[i].h == h) {
        if (g_trk[i].buf && g_trk[i].total > 0) {
            // decryption happens AFTER close (in place): dump 1.5s later
            QueueUserWorkItem(delayed_dump, (void*)(DWORD_PTR)i, 0);
            LeaveCriticalSection(&g_cs);
            return ((NCLOSE)g_nclose.tramp)(h);  // keep tracking until dump fires
        }
        g_trk[i] = g_trk[--g_ntrk];
        break;
    }
    LeaveCriticalSection(&g_cs);
    return ((NCLOSE)g_nclose.tramp)(h);
}

// ---- kernel32 mmap chain (in case some path uses it) ----
typedef HANDLE (WINAPI *CFMA)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef HANDLE (WINAPI *CFMW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef LPVOID (WINAPI *MVF)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
static HOOK g_cfma, g_cfmw, g_mvf;
static struct { HANDLE h; char name[128]; } g_map[MAXH]; static int g_nmap;

static LONG WINAPI veh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode == 0x80000001) {
        DWORD addr = ep->ExceptionRecord->ExceptionInformation[1];
        // only handle guard hits inside tracked tpk views; stack growth etc. pass on
        int ours = 0;
        for (int i = 0; i < g_nview; i++)
            if (addr >= (DWORD)g_view[i].base && addr < (DWORD)g_view[i].base + g_view[i].size) { ours = 1; break; }
        if (!ours) return EXCEPTION_CONTINUE_SEARCH;
        DWORD eip = (DWORD)ep->ExceptionRecord->ExceptionAddress;
        EnterCriticalSection(&g_cs);
        if (g_log && g_hits < HIT_BUDGET) {
            fprintf(g_log, "guard hit %d: eip=%08x read=%08x esi=%08x edi=%08x ecx=%08x ebp=%08x esp=%08x\n",
                    g_hits, eip, addr, ep->ContextRecord->Esi, ep->ContextRecord->Edi, ep->ContextRecord->Ecx,
                    ep->ContextRecord->Ebp, ep->ContextRecord->Esp);
            // dump stack (return addresses reveal the caller chain)
            if (g_hits < 4) {
                DWORD sp = ep->ContextRecord->Esp;
                MEMORY_BASIC_INFORMATION mbi;
                DWORD max = sp + 192;
                if (VirtualQuery((void*)sp, &mbi, sizeof(mbi))) {
                    DWORD end = (DWORD)mbi.BaseAddress + mbi.RegionSize;
                    if (max > end - 4) max = end - 4;
                }
                for (DWORD p = sp; p < max; p += 4)
                    fprintf(g_log, "  esp+%02x: %08x\n", p - sp, *(DWORD*)p);
                // dump the decryptor context: this = [ebp-0x30] in the 0x5ac1f0 frame
                DWORD ebp = ep->ContextRecord->Ebp;
                DWORD thisp = *(DWORD*)(ebp - 0x30);
                fprintf(g_log, "  this=%08x inpos=%08x out=%08x\n", thisp,
                        *(DWORD*)(ebp + 8), *(DWORD*)(ebp + 0xc));
                if (thisp > 0x10000 && thisp < 0x7fff0000) {
                    MEMORY_BASIC_INFORMATION m2;
                    if (VirtualQuery((void*)thisp, &m2, sizeof(m2))) {
                        char cp[MAX_PATH];
                        _snprintf(cp, MAX_PATH, "tpkdump_out\\ctx_%d.bin", g_hits);
                        FILE* cf = fopen(cp, "wb");
                        if (cf) {
                            DWORD avail = (DWORD)m2.BaseAddress + m2.RegionSize - thisp;
                            DWORD want = 0x480 < avail ? 0x480 : avail;
                            fwrite((void*)thisp, 1, want, cf);
                            fclose(cf);
                        }
                    }
                }
                fflush(g_log);
            }
            fflush(g_log);
        }
        g_hits++;
        LeaveCriticalSection(&g_cs);
        // guard flag on this page was auto-cleared by the fault; do NOT re-arm
        // here (re-arming before the faulting instruction retries = fault loop)
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static HANDLE WINAPI my_CFMA(HANDLE f, LPSECURITY_ATTRIBUTES sa, DWORD p, DWORD h, DWORD l, LPCSTR n) {
    HANDLE r = ((CFMA)g_cfma.tramp)(f, sa, p, h, l, n);
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_ntrk; i++) if (g_trk[i].h == f && r && g_nmap < MAXH) {
        g_map[g_nmap].h = r; _snprintf(g_map[g_nmap].name, 127, "%s", g_trk[i].name); g_nmap++;
        if (g_log) { fprintf(g_log, "mapping %s maph=%p\n", g_trk[i].name, r); fflush(g_log); }
        break;
    }
    LeaveCriticalSection(&g_cs);
    return r;
}
static HANDLE WINAPI my_CFMW(HANDLE f, LPSECURITY_ATTRIBUTES sa, DWORD p, DWORD h, DWORD l, LPCWSTR n) {
    HANDLE r = ((CFMW)g_cfmw.tramp)(f, sa, p, h, l, n);
    if (r) { /* same as A */ }
    return r;
}
static LPVOID WINAPI my_MVF(HANDLE m, DWORD a, DWORD h, DWORD l, SIZE_T s) {
    LPVOID r = ((MVF)g_mvf.tramp)(m, a, h, l, s);
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_nmap; i++) if (g_map[i].h == m && r && g_nview < 32) {
        DWORD sz = (DWORD)s;
        if (!sz) { MEMORY_BASIC_INFORMATION mbi; if (VirtualQuery(r, &mbi, sizeof(mbi))) sz = (DWORD)mbi.RegionSize; }
        g_view[g_nview].base = (BYTE*)r; g_view[g_nview].size = sz; g_nview++;
        if (g_log) { fprintf(g_log, "view %s va=%p size=%u\n", g_map[i].name, r, sz); fflush(g_log); }
        break;
    }
    LeaveCriticalSection(&g_cs);
    return r;
}

// ---- network capture ----
typedef int (WINAPI *RECV)(SOCKET, char*, int, int);
typedef int (WINAPI *WSARECV)(SOCKET, void*, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL (WINAPI *WSAGOR)(SOCKET, LPWSAOVERLAPPED, LPDWORD, BOOL, LPDWORD);
static HOOK g_recv, g_wsarecv, g_wsagor;

static void lognet(const char* tag, const unsigned char* buf, int len) {
    if (!g_log || len <= 0) return;
    EnterCriticalSection(&g_cs);
    static int seq;
    char path[MAX_PATH];
    _snprintf(path, MAX_PATH, "tpkdump_out\\net_%04d.bin", seq++);
    FILE* f = fopen(path, "wb");
    if (f) { fwrite(buf, 1, len, f); fclose(f); }
    fprintf(g_log, "%s len=%d -> %s\n", tag, len, path);
    fflush(g_log);
    LeaveCriticalSection(&g_cs);
}
static int WINAPI my_recv(SOCKET s, char* buf, int len, int flags) {
    int r = ((RECV)g_recv.tramp)(s, buf, len, flags);
    if (r > 0) lognet("recv", (unsigned char*)buf, r);
    return r;
}
typedef int (WINAPI *SENDF)(SOCKET, const char*, int, int);
static HOOK g_send;
static int WINAPI my_send(SOCKET s, const char* buf, int len, int flags) {
    if (len > 0) lognet("send", (unsigned char*)buf, len);
    return ((SENDF)g_send.tramp)(s, buf, len, flags);
}
// overlapped WSARecv: remember buffers, dump when WSAGetOverlappedResult completes
#define MAXPEND 32
static struct { SOCKET s; WSABUF* bufs; DWORD n; } g_pend[MAXPEND];
static int g_npend;
static int WINAPI my_wsarecv(SOCKET s, void* bufs, DWORD n, LPDWORD recvd, LPDWORD fl, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb) {
    int r = ((WSARECV)g_wsarecv.tramp)(s, bufs, n, recvd, fl, ov, cb);
    if (r == 0 && recvd && *recvd) {
        WSABUF* wb = (WSABUF*)bufs;
        lognet("wsarecv-imm", (unsigned char*)wb->buf, (int)*recvd);
    } else if (ov) {
        EnterCriticalSection(&g_cs);
        if (g_npend < MAXPEND) { g_pend[g_npend].s = s; g_pend[g_npend].bufs = (WSABUF*)bufs; g_pend[g_npend].n = n; g_npend++; }
        LeaveCriticalSection(&g_cs);
    }
    return r;
}
static BOOL WINAPI my_wsagor(SOCKET s, LPWSAOVERLAPPED ov, LPDWORD transferred, BOOL wait, LPDWORD flags) {
    BOOL r = ((WSAGOR)g_wsagor.tramp)(s, ov, transferred, wait, flags);
    if (r && transferred && *transferred) {
        EnterCriticalSection(&g_cs);
        for (int i = 0; i < g_npend; i++)
            if (g_pend[i].s == s) {
                lognet("wsarecv-ovl", (unsigned char*)g_pend[i].bufs[0].buf, (int)*transferred);
                g_pend[i] = g_pend[--g_npend];
                break;
            }
        LeaveCriticalSection(&g_cs);
    }
    return r;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_cs);
        CreateDirectoryA("tpkdump_out", NULL);
        g_log = fopen("tpkdump_out\\log.txt", "w");
        AddVectoredExceptionHandler(1, veh);
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        patch(GetProcAddress(nt, "NtCreateFile"), my_NtCreateFile, g_ncf.tramp);
        patch(GetProcAddress(nt, "NtReadFile"), my_NtReadFile, g_nrf.tramp);
        patch(GetProcAddress(nt, "NtClose"), my_NtClose, g_nclose.tramp);
        patch(GetProcAddress(nt, "NtWriteFile"), my_NtWriteFile, g_nwf.tramp);
        HMODULE k = GetModuleHandleA("kernel32.dll");
        patch(GetProcAddress(k, "CreateFileMappingA"), my_CFMA, g_cfma.tramp);
        patch(GetProcAddress(k, "CreateFileMappingW"), my_CFMW, g_cfmw.tramp);
        patch(GetProcAddress(k, "MapViewOfFile"), my_MVF, g_mvf.tramp);
        // network capture: hook ws2_32 recv/WSARecv
        HMODULE w = LoadLibraryA("ws2_32.dll");
        if (w) {
            patch(GetProcAddress(w, "recv"), my_recv, g_recv.tramp);
            patch(GetProcAddress(w, "WSARecv"), my_wsarecv, g_wsarecv.tramp);
            patch(GetProcAddress(w, "WSAGetOverlappedResult"), my_wsagor, g_wsagor.tramp);
            patch(GetProcAddress(w, "send"), my_send, g_send.tramp);
        }
        if (g_log) { fprintf(g_log, "tpkdump v3 loaded\n"); fflush(g_log); }
    }
    return TRUE;
}
