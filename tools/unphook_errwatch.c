// unphook_errwatch.c — injected into client_unpacked2.exe: hardware write-watchpoint on
// the shell's relocated error-code global (0xFB115AC, stable across runs).
// When the shell writes the error code, the VEH logs the writer's EIP/regs/
// stack frame chain -> that IS the failing check site.
// Also hooks user32!MessageBoxA/W as a backup stack-capture channel.
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>

#define WATCH_ADDR 0xFB115AC
#define DR7_WATCH  (1 | (1 << 16) | (3 << 18))  // L0 | RW0=write | LEN0=4bytes

static FILE* g_lf;
static void lg(const char* fmt, ...) {
    if (!g_lf) { g_lf = fopen("unphook.log", "a"); if (g_lf) setvbuf(g_lf, 0, _IONBF, 0); }
    if (!g_lf) return;
    va_list ap; va_start(ap, fmt); vfprintf(g_lf, fmt, ap); va_end(ap);
}

static int mem_ok(const void* p, DWORD n) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    return 1;
}

static int g_caught;
static LONG CALLBACK veh(PEXCEPTION_POINTERS p) {
    if (p->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    if (!(p->ContextRecord->Dr6 & 1))
        return EXCEPTION_CONTINUE_SEARCH;
    if (g_caught) return EXCEPTION_CONTINUE_EXECUTION;  // already logged; re-arms come from helper
    g_caught = 1;
    CONTEXT* c = p->ContextRecord;
    DWORD val = 0;
    if (mem_ok((void*)WATCH_ADDR, 4)) val = *(DWORD*)WATCH_ADDR;
    lg("!!!! WATCH HIT: [0x%08x] <- %08x  (error code)\n", WATCH_ADDR, val);
    lg("  eip=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x\n",
       c->Eip, c->Eax, c->Ebx, c->Ecx, c->Edx, c->Esi, c->Edi, c->Ebp, c->Esp);
    // code around eip (the write instruction is just before eip)
    if (mem_ok((void*)(c->Eip - 32), 64)) {
        BYTE* b = (BYTE*)(c->Eip - 32);
        lg("  code@%08x:", c->Eip - 32);
        for (int i = 0; i < 64; i++) lg(" %02x", b[i]);
        lg("\n");
    }
    // ebp chain
    DWORD ebp = c->Ebp;
    for (int k = 0; k < 24; k++) {
        DWORD prev, ret;
        if (!mem_ok((void*)ebp, 8)) break;
        prev = *(DWORD*)ebp; ret = *(DWORD*)(ebp + 4);
        lg("  frame[%02d] ebp=%08x ret=%08x\n", k, ebp, ret);
        if (prev <= ebp || prev - ebp > 0x20000) break;
        ebp = prev;
    }
    // stack image-pointer scan
    DWORD sp = c->Esp & ~3;
    int found = 0;
    for (DWORD q = sp; q < sp + 0x600 && found < 48; q += 4) {
        if (!mem_ok((void*)q, 4)) break;
        DWORD v = *(DWORD*)q;
        if (v >= 0x401000 && v < 0xFF17000) { lg("  stk[%08x] = %08x\n", q, v); found++; }
    }
    lg("  stack image-ptrs done\n");
    // THE EXPERIMENT: the check/write/report/shutdown all run on THIS thread.
    // Parking it here (after the write completed, before the reporter reads the
    // global) starves the whole error path. If the check was a pure integrity
    // nag, the game continues on its main thread.
    lg("!!!! suspending the writer thread to starve the error path\n");
    SuspendThread(GetCurrentThread());
    // never returns here while suspended
    return EXCEPTION_CONTINUE_EXECUTION;
}

// ---- backup: MessageBoxA/W stack capture ----
static BYTE g_mb_orig[8];
static DWORD g_mb_addr;
static int __stdcall dummy;  // never used; see asm-free approach below

// simplest reliable in-process hook: 5-byte jmp with trampoline, logging then call
static BYTE g_trampA[16];
typedef int (WINAPI *MBA)(HWND, LPCSTR, LPCSTR, UINT);
static int WINAPI my_MessageBoxA(HWND h, LPCSTR text, LPCSTR cap, UINT type) {
    lg("!!!! MessageBoxA: text=\"%s\" caption=\"%s\"\n", text ? text : "", cap ? cap : "");
    // walk ebp of OUR caller
    DWORD* f = (DWORD*)__builtin_frame_address(0);
    if (f && mem_ok(f, 8)) {
        DWORD ebp = (DWORD)f[0];
        for (int k = 0; k < 24; k++) {
            DWORD prev, ret;
            if (!mem_ok((void*)ebp, 8)) break;
            prev = *(DWORD*)ebp; ret = *(DWORD*)(ebp + 4);
            lg("  mbframe[%02d] ebp=%08x ret=%08x\n", k, ebp, ret);
            if (prev <= ebp || prev - ebp > 0x20000) break;
            ebp = prev;
        }
    }
    return ((MBA)g_trampA)(h, text, cap, type);
}

static void hook_msgbox(void) {
    HMODULE u = GetModuleHandleA("user32.dll");
    if (!u) { lg("unphook: user32 not loaded yet\n"); return; }
    BYTE* p = (BYTE*)GetProcAddress(u, "MessageBoxA");
    if (!p) return;
    DWORD old;
    memcpy(g_trampA, p, 5);
    g_trampA[5] = 0xE9;
    DWORD rel = (DWORD)(p + 5) - (DWORD)(g_trampA + 10);
    memcpy(g_trampA + 6, &rel, 4);
    if (!VirtualProtect(g_trampA, 16, PAGE_EXECUTE_READWRITE, &old)) { lg("unphook: tramp VP fail\n"); return; }
    if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &old)) { lg("unphook: mb VP fail\n"); return; }
    BYTE jb[5] = { 0xE9, 0, 0, 0, 0 };
    rel = (DWORD)my_MessageBoxA - (DWORD)(p + 5);
    memcpy(jb + 1, &rel, 4);
    memcpy(p, jb, 5);
    VirtualProtect(p, 5, old, &old);
    g_mb_addr = (DWORD)p;
    lg("unphook: MessageBoxA hooked @%08x\n", (DWORD)p);
}

// arm Dr0 write-watch on every thread except the current one
static DWORD g_self;
static void arm_all(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te; te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId();
    int n = 0;
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == g_self) continue;
        HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, te.th32ThreadID);
        if (!ht) continue;
        SuspendThread(ht);
        CONTEXT c; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(ht, &c)) {
            if (c.Dr0 != WATCH_ADDR || !(c.Dr7 & 1)) {
                c.Dr0 = WATCH_ADDR;
                c.Dr7 |= DR7_WATCH;   // keep other bits
                SetThreadContext(ht, &c);
                n++;
            }
        }
        ResumeThread(ht);
        CloseHandle(ht);
    }
    if (n) lg("unphook: armed Dr0 watch on %d threads\n", n);
}

static DWORD WINAPI helper(LPVOID) {
    g_self = GetCurrentThreadId();
    lg("unphook: helper running, watch=%08x\n", WATCH_ADDR);
    for (int i = 0; i < 200; i++) {  // ~20s of re-arming (covers new threads)
        arm_all();
        hook_msgbox();
        Sleep(100);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        lg("unphook: === attach ===\n");
        AddVectoredExceptionHandler(1, veh);
        CreateThread(0, 0, helper, 0, 0, 0);
    }
    return TRUE;
}
