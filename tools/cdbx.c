// cdbx.c — minimal 32-bit debugger for the rebuilt client_unpacked exe.
// Port of minidbg.py essentials, plus arbitrary INT3 breakpoints, a MessageBoxA
// breakpoint, and stack/frame dumping on hit.
//
// usage: cdbx <exe> [args...] -- then breakpoint VAs are read from cdbx.ini
// (one hex VA per line, e.g. "76a01234"). "MSGBOX" (literally) sets a bp on
// user32!MessageBoxA. All output to stdout (line-buffered).
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <tlhelp32.h>
#include <psapi.h>

BOOL WINAPI Wow64GetThreadContext(HANDLE, void*);
BOOL WINAPI Wow64SetThreadContext(HANDLE, const void*);

#define W64_FULL 0x00010007  // WOW64_CONTEXT_FULL

typedef struct {
    DWORD ContextFlags;
    DWORD Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    BYTE FloatSave[112];
    DWORD SegGs, SegFs, SegEs, SegDs;
    DWORD Edi, Esi, Ebx, Edx, Ecx, Eax;
    DWORD Ebp, Eip, SegCs, EFlags, Esp, SegSs;
    BYTE ExtendedRegisters[512];
} W64CTX;

static HANDLE g_hp;
static DWORD g_bps[64];
static BYTE g_bporig[64];
static int g_nbp;
static DWORD g_msgbox_va;
static BYTE g_msgbox_orig;
static int g_msgbox_armed;
static DWORD g_exit_va;
static BYTE g_exit_orig;
static int g_exit_armed;
static DWORD g_exit2_va;
static BYTE g_exit2_orig;
static int g_exit2_armed;
static int g_restep_exit2;
static int g_restep_bp = -1;      // breakpoint index to re-arm after single-step
static int g_restep_msgbox;
static int g_restep_exit;
static DWORD g_dumpva;            // when a bp at this VA hits: full region dump + terminate

// tid -> handle map (debuggee may be multithreaded by the time we break)
static DWORD g_tids[128];
static HANDLE g_ths[128];
static int g_nth;
static HANDLE find_thread(DWORD tid) {
    for (int i = 0; i < g_nth; i++) if (g_tids[i] == tid) return g_ths[i];
    return 0;
}
static void add_thread(DWORD tid, HANDLE h) {
    if (g_nth < 128 && !find_thread(tid)) { g_tids[g_nth] = tid; g_ths[g_nth] = h; g_nth++; }
}

static void pl(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    fflush(stdout);
}

static int rpm(DWORD addr, void* buf, DWORD size) {
    SIZE_T got = 0;
    return ReadProcessMemory(g_hp, (void*)addr, buf, size, &got) && got == size;
}
static int wpm(DWORD addr, const void* buf, DWORD size) {
    SIZE_T wr = 0; DWORD old;
    VirtualProtectEx(g_hp, (void*)addr, size, PAGE_EXECUTE_READWRITE, &old);
    int ok = WriteProcessMemory(g_hp, (void*)addr, buf, size, &wr);
    VirtualProtectEx(g_hp, (void*)addr, size, old, &old);
    return ok && wr == size;
}

static int get_ctx(HANDLE ht, W64CTX* c) {
    c->ContextFlags = W64_FULL;
    return Wow64GetThreadContext(ht, c);
}
static int set_ctx(HANDLE ht, W64CTX* c) {
    return Wow64SetThreadContext(ht, c);
}

// dump every committed region of the debuggee into cdbx_dump/ + index.txt
static void dump_all_regions(void) {
    CreateDirectoryA("cdbx_dump", NULL);
    FILE* idx = fopen("cdbx_dump\\index.txt", "w");
    DWORD addr = 0x10000;
    int n = 0;
    while (addr < 0x7FFF0000) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(g_hp, (void*)addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
            DWORD base = (DWORD)mbi.BaseAddress, size = (DWORD)mbi.RegionSize;
            char fn[64]; sprintf(fn, "cdbx_dump\\region_%08x.bin", base);
            FILE* f = fopen(fn, "wb");
            if (f) {
                static BYTE buf[0x100000];
                DWORD off = 0;
                while (off < size) {
                    DWORD chunk = size - off; if (chunk > sizeof(buf)) chunk = sizeof(buf);
                    SIZE_T got = 0;
                    ReadProcessMemory(g_hp, (void*)(base + off), buf, chunk, &got);
                    fwrite(buf, 1, got, f);
                    if (got < chunk) { BYTE z = 0; for (DWORD k = got; k < chunk; k++) fwrite(&z, 1, 1, f); }
                    off += chunk;
                }
                fclose(f);
                if (idx) fprintf(idx, "%08x %08x prot=%08x type=%08x\n", base, size, mbi.Protect, mbi.Type);
                n++;
            }
        }
        addr = (DWORD)mbi.BaseAddress + mbi.RegionSize;
    }
    if (idx) fclose(idx);
    pl("dumped %d regions\n", n);
}

static void dump_at_break(HANDLE ht, const char* tag, DWORD va) {    W64CTX c;
    if (!get_ctx(ht, &c)) { pl("ctx fail\n"); return; }
    pl("\n==== BREAK %s @%08x ====\n", tag, va);
    pl("eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x eip=%08x\n",
       c.Eax, c.Ebx, c.Ecx, c.Edx, c.Esi, c.Edi, c.Ebp, c.Esp, c.Eip);
    // code bytes around eip
    BYTE code[48];
    if (rpm(c.Eip - 16, code, sizeof(code))) {
        pl("code@%08x:", c.Eip - 16);
        for (int i = 0; i < 48; i++) pl(" %02x", code[i]);
        pl("\n");
    }
    // ebp frame chain
    DWORD ebp = c.Ebp;
    for (int k = 0; k < 24; k++) {
        DWORD prev, ret;
        if (!rpm(ebp, &prev, 4) || !rpm(ebp + 4, &ret, 4)) break;
        pl("  frame[%02d] ebp=%08x ret=%08x\n", k, ebp, ret);
        if (prev <= ebp || prev - ebp > 0x10000) break;
        ebp = prev;
    }
    // raw stack scan: values into image code range
    DWORD sp = c.Esp & ~3;
    int found = 0;
    pl("  stack image-ptrs:\n");
    for (DWORD p = sp; p < sp + 0x400 && found < 48; p += 4) {
        DWORD v;
        if (!rpm(p, &v, 4)) break;
        if (v >= 0x401000 && v < 0xFF17000) { pl("    [%08x] = %08x\n", p, v); found++; }
    }
}

static void patch_peb(DWORD pid) {
    // get PEB via NtQueryInformationProcess
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    typedef LONG (WINAPI *NQIP)(HANDLE, UINT, PVOID, ULONG, PULONG);
    NQIP fn = (NQIP)GetProcAddress(nt, "NtQueryInformationProcess");
    struct { void* r1; void* peb; void* r2[2]; void* pid; void* r3; } pbi;
    ULONG rl;
    if (!fn || fn(g_hp, 0, &pbi, sizeof(pbi), &rl)) { pl("NQIP fail\n"); return; }
    DWORD peb = (DWORD)pbi.peb;
    pl("peb=%08x\n", peb);
    BYTE z = 0; DWORD zd = 0;
    wpm(peb + 2, &z, 1);          // BeingDebugged
    wpm(peb + 0x68, &zd, 4);      // NtGlobalFlag
    DWORD heap = 0;
    if (rpm(peb + 0x18, &heap, 4)) {
        DWORD flags = 2, force = 0;
        wpm(heap + 0x0C, &flags, 4);  // Flags = HEAP_GROWABLE
        wpm(heap + 0x10, &force, 4);  // ForceFlags = 0
    }
    pl("peb patched\n");
}

// called on LOAD_DLL: if the dll is user32 (by name), plant bp on MessageBoxA
// called on LOAD_DLL: arm the MessageBoxA bp on user32, ExitProcess on kernel32
static void maybe_arm_msgbox(DWORD base) {
    if (!g_msgbox_armed) {
        char path[MAX_PATH];
        if (GetModuleFileNameExA(g_hp, (HMODULE)base, path, sizeof(path)) && strstr(path, "user32.dll")) {
            HMODULE u = GetModuleHandleA("user32.dll");
            DWORD rva = (DWORD)(BYTE*)GetProcAddress(u, "MessageBoxA") - (DWORD)u;
            g_msgbox_va = base + rva;
            if (rpm(g_msgbox_va, &g_msgbox_orig, 1) && wpm(g_msgbox_va, "\xcc", 1)) {
                g_msgbox_armed = 1;
                pl("msgbox bp armed @%08x (user32 base %08x)\n", g_msgbox_va, base);
            }
        }
    }
    if (!g_exit_armed) {
        char path[MAX_PATH];
        if (GetModuleFileNameExA(g_hp, (HMODULE)base, path, sizeof(path)) && strstr(path, "kernel32.dll")) {
            HMODULE k = GetModuleHandleA("kernel32.dll");
            DWORD rva = (DWORD)(BYTE*)GetProcAddress(k, "ExitProcess") - (DWORD)k;
            g_exit_va = base + rva;
            if (rpm(g_exit_va, &g_exit_orig, 1) && wpm(g_exit_va, "\xcc", 1)) {
                g_exit_armed = 1;
                pl("exitproc bp armed @%08x (kernel32 base %08x)\n", g_exit_va, base);
            }
        }
    }
    if (!g_exit2_armed) {
        char path[MAX_PATH];
        if (GetModuleFileNameExA(g_hp, (HMODULE)base, path, sizeof(path)) && strstr(path, "ntdll.dll")) {
            HMODULE n = GetModuleHandleA("ntdll.dll");
            FARPROC f2 = GetProcAddress(n, "RtlExitUserProcess");
            if (f2) {
                DWORD rva = (DWORD)(BYTE*)f2 - (DWORD)n;
                g_exit2_va = base + rva;
                if (rpm(g_exit2_va, &g_exit2_orig, 1) && wpm(g_exit2_va, "\xcc", 1)) {
                    g_exit2_armed = 1;
                    pl("rtlexit bp armed @%08x (ntdll base %08x)\n", g_exit2_va, base);
                }
            }
        }
    }
}

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: cdbx <exe> [args]  (bps in cdbx.ini)\n"); return 1; }
    // build command line
    char cmd[1024] = { 0 };
    for (int i = 1; i < argc; i++) {
        if (i > 1) strcat(cmd, " ");
        strcat(cmd, argv[i]);
    }
    // read breakpoint list
    FILE* f = fopen("cdbx.ini", "r");
    if (f) {
        char line[128];
        while (fgets(line, sizeof(line), f)) {
            if (line[0] == 'D' || line[0] == 'd') {  // "DUMP <hexva>"
                char* sp = strchr(line, ' ');
                if (sp) g_dumpva = strtoul(sp + 1, 0, 16);
                if (g_dumpva && g_nbp < 64) g_bps[g_nbp++] = g_dumpva;
                continue;
            }
            DWORD v = strtoul(line, 0, 16);
            if (v && g_nbp < 64) g_bps[g_nbp++] = v;
        }
        fclose(f);
    }
    pl("cdbx: cmd='%s' bps=%d\n", cmd, g_nbp);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        pl("CreateProcess fail %lu\n", GetLastError()); return 1;
    }
    pl("pid=%lu\n", pi.dwProcessId);
    g_hp = pi.hProcess;
    add_thread(pi.dwThreadId, pi.hThread);
    DEBUG_EVENT ev;
    int bp_planted = 0, peb_done = 0;

    for (;;) {
        if (!WaitForDebugEvent(&ev, 30000)) { pl("debug event timeout\n"); break; }
        DWORD cont = DBG_CONTINUE;
        DWORD code = ev.dwDebugEventCode;
        HANDLE ht = find_thread(ev.dwThreadId);
        if (!ht) ht = pi.hThread;
        if (code == CREATE_PROCESS_DEBUG_EVENT) {
            pl("create_process base=%p\n", ev.u.CreateProcessInfo.lpBaseOfImage);
            if (!peb_done) { patch_peb(pi.dwProcessId); peb_done = 1; }
            CloseHandle(ev.u.CreateProcessInfo.hFile);
        } else if (code == EXCEPTION_DEBUG_EVENT) {
            DWORD ec = ev.u.Exception.ExceptionRecord.ExceptionCode;
            DWORD ea = (DWORD)ev.u.Exception.ExceptionRecord.ExceptionAddress;
            int first = ev.u.Exception.dwFirstChance;
            if (ec == 0x80000003 || ec == 0x4000001f) {  // int3
                if (!bp_planted) {
                    // system breakpoint: plant all our bps
                    for (int i = 0; i < g_nbp; i++) {
                        if (rpm(g_bps[i], &g_bporig[i], 1) && wpm(g_bps[i], "\xcc", 1))
                            pl("bp armed @%08x (orig %02x)\n", g_bps[i], g_bporig[i]);
                        else pl("bp FAILED @%08x\n", g_bps[i]);
                    }
                    bp_planted = 1;
                } else if (g_msgbox_armed && ea == g_msgbox_va) {
                    dump_at_break(ht, "MessageBoxA", ea);
                    wpm(ea, &g_msgbox_orig, 1);
                    W64CTX c; if (get_ctx(ht, &c)) { c.Eip = ea; c.EFlags |= 0x100; set_ctx(ht, &c); }
                    g_restep_msgbox = 1;
                } else if (g_exit_armed && ea == g_exit_va) {
                    dump_at_break(ht, "ExitProcess", ea);
                    wpm(ea, &g_exit_orig, 1);
                    W64CTX c; if (get_ctx(ht, &c)) { c.Eip = ea; c.EFlags |= 0x100; set_ctx(ht, &c); }
                    g_restep_exit = 1;
                } else if (g_exit2_armed && ea == g_exit2_va) {
                    dump_at_break(ht, "RtlExitUserProcess", ea);
                    wpm(ea, &g_exit2_orig, 1);
                    W64CTX c; if (get_ctx(ht, &c)) { c.Eip = ea; c.EFlags |= 0x100; set_ctx(ht, &c); }
                    g_restep_exit2 = 1;
                } else {
                    int hit = -1;
                    for (int i = 0; i < g_nbp; i++) if (g_bps[i] == ea) { hit = i; break; }
                    if (hit >= 0) {
                        char tag[32]; sprintf(tag, "bp#%d", hit);
                        dump_at_break(ht, tag, ea);
                        if (g_dumpva && ea == g_dumpva) {
                            dump_all_regions();
                            pl("dump done, terminating debuggee\n");
                            TerminateProcess(g_hp, 0);
                            return 0;
                        }
                        wpm(ea, &g_bporig[hit], 1);
                        W64CTX c; if (get_ctx(ht, &c)) { c.Eip = ea; c.EFlags |= 0x100; set_ctx(ht, &c); }
                        g_restep_bp = hit;
                    } else if (ea >= 0x401000 && ea < 0xFF17000) {
                        // Themida int3 in image code: must reach the shell's own
                        // VEH/SEH. Skipping eip+1 breaks its control flow -> loop.
                        pl("themida int3 @%08x (pass to app)\n", ea);
                        cont = DBG_EXCEPTION_NOT_HANDLED;
                    } else {
                        // system/ntdll breakpoint: retire it
                        W64CTX c; if (get_ctx(ht, &c)) { c.Eip = ea + 1; set_ctx(ht, &c); }
                    }
                }
            } else if (ec == 0x80000004) {  // single step: re-arm
                if (g_restep_bp >= 0) { wpm(g_bps[g_restep_bp], "\xcc", 1); g_restep_bp = -1; }
                if (g_restep_msgbox) { wpm(g_msgbox_va, "\xcc", 1); g_restep_msgbox = 0; }
                if (g_restep_exit) { wpm(g_exit_va, "\xcc", 1); g_restep_exit = 0; }
                if (g_restep_exit2) { wpm(g_exit2_va, "\xcc", 1); g_restep_exit2 = 0; }
            } else if (ec == 0x8000002d) {  // int2d: same - let the app handle it
                pl("int2d @%08x (pass to app)\n", ea);
                cont = DBG_EXCEPTION_NOT_HANDLED;
            } else {
                pl("exc %08x @%08x first=%d\n", ec, ea, first);
                cont = DBG_EXCEPTION_NOT_HANDLED;
                if (!first) { pl("second chance - giving up\n"); break; }
            }
        } else if (code == LOAD_DLL_DEBUG_EVENT) {
            char path[MAX_PATH] = { 0 };
            if (GetModuleFileNameExA(g_hp, (HMODULE)ev.u.LoadDll.lpBaseOfDll, path, sizeof(path)))
                pl("load_dll %p %s\n", ev.u.LoadDll.lpBaseOfDll, path);
            maybe_arm_msgbox((DWORD)ev.u.LoadDll.lpBaseOfDll);
            CloseHandle(ev.u.LoadDll.hFile);
        } else if (code == CREATE_THREAD_DEBUG_EVENT) {
            add_thread(ev.dwThreadId, ev.u.CreateThread.hThread);
        } else if (code == EXIT_PROCESS_DEBUG_EVENT) {
            pl("exit_process code=%08x\n", ev.u.ExitProcess.dwExitCode);
            break;
        }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
    }
    return 0;
}
