// dumpthread.c — suspend all threads of a 32-bit process and dump each thread's
// context + ebp frame chain + stack image-pointers. For catching the rebuilt
// client_unpacked while its error MessageBox is parked.
// usage: dumpthread <pid> [outfile]
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

#define W64_FULL 0x00010007
BOOL WINAPI Wow64GetThreadContext(HANDLE, void*);

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
static FILE* g_out;

static int rpm(DWORD addr, void* buf, DWORD size) {
    SIZE_T got = 0;
    return ReadProcessMemory(g_hp, (void*)addr, buf, size, &got) && got == size;
}

static void pout(const char* fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fputs(buf, g_out);
}

static void dump_thread(DWORD tid) {
    HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, 0, tid);
    if (!ht) return;
    SuspendThread(ht);
    W64CTX c;
    c.ContextFlags = W64_FULL;
    if (!Wow64GetThreadContext(ht, &c)) { pout("tid %lu: ctx fail\n", tid); ResumeThread(ht); CloseHandle(ht); return; }
    pout("\n==== tid %lu eip=%08x esp=%08x ebp=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n",
         tid, c.Eip, c.Esp, c.Ebp, c.Eax, c.Ebx, c.Ecx, c.Edx, c.Esi, c.Edi);
    BYTE code[32];
    if (rpm(c.Eip - 16, code, sizeof(code))) {
        pout("  code@%08x:", c.Eip - 16);
        for (int i = 0; i < 32; i++) pout(" %02x", code[i]);
        pout("\n");
    }
    DWORD ebp = c.Ebp;
    for (int k = 0; k < 32; k++) {
        DWORD prev, ret;
        if (!rpm(ebp, &prev, 4) || !rpm(ebp + 4, &ret, 4)) break;
        pout("  frame[%02d] ebp=%08x ret=%08x\n", k, ebp, ret);
        if (prev <= ebp || prev - ebp > 0x20000) break;
        ebp = prev;
    }
    pout("  stack image-ptrs:\n");
    DWORD sp = c.Esp & ~3;
    int found = 0;
    for (DWORD p = sp; p < sp + 0x800 && found < 64; p += 4) {
        DWORD v;
        if (!rpm(p, &v, 4)) break;
        if (v >= 0x401000 && v < 0xFF17000) { pout("    [%08x] = %08x\n", p, v); found++; }
    }
    ResumeThread(ht);
    CloseHandle(ht);
}

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: dumpthread <pid> [outfile]\n"); return 1; }
    DWORD pid = strtoul(argv[1], 0, 10);
    g_out = argc > 2 ? fopen(argv[2], "w") : stdout;
    if (!g_out) g_out = stdout;
    g_hp = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
    if (!g_hp) { printf("OpenProcess fail %lu\n", GetLastError()); return 1; }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te; te.dwSize = sizeof(te);
    int n = 0;
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te))
        if (te.th32OwnerProcessID == pid) { dump_thread(te.th32ThreadID); n++; }
    CloseHandle(snap);
    pout("\ndumped %d threads\n", n);
    return 0;
}
