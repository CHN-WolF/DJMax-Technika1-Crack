// oepdump.c — catch the TRUE OEP moment: detour ntdll's app-entry launcher
// (RtlUserThreadStart flow: mov edx,edi / xor ecx,ecx / call esi at base+0x672a8,
// edx == app EP there). When edx == OEP (0xFA59700), the main thread is one call
// away from running the entry point with zero game code executed -> freeze + dump.
// Non-OEP threads pass through a trampoline.
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>

#define OEP 0xFA59700
#define IMG_LO 0x400000
#define IMG_HI 0xFF17000

static FILE* g_lf;
static void lg(const char* fmt, ...) {
    if (!g_lf) { g_lf = fopen("oepdump.log", "a"); if (g_lf) setvbuf(g_lf, 0, _IONBF, 0); }
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

static int g_dumped;
static void dump_all(void) {
    CreateDirectoryA("oepdump_out", NULL);
    DWORD self = GetCurrentThreadId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te; te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId();
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) continue;
        HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID);
        if (ht) { SuspendThread(ht); CloseHandle(ht); }
    }
    CloseHandle(snap);
    lg("oepdump: threads suspended, dumping...\n");

    FILE* fi = fopen("oepdump_out\\image.bin", "wb");
    if (fi) {
        static BYTE buf[0x1000];
        for (DWORD a = IMG_LO; a < IMG_HI; a += sizeof(buf)) {
            if (mem_ok((void*)a, sizeof(buf))) memcpy(buf, (void*)a, sizeof(buf));
            else memset(buf, 0, sizeof(buf));
            fwrite(buf, 1, sizeof(buf), fi);
        }
        fclose(fi);
        lg("oepdump: image.bin done\n");
    }
    FILE* idx = fopen("oepdump_out\\index.txt", "w");
    DWORD addr = 0x10000;
    int n = 0;
    while (addr < 0x7FFE0000) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;
        DWORD base = (DWORD)mbi.BaseAddress, size = (DWORD)mbi.RegionSize;
        int in_img = (base >= IMG_LO && base + size <= IMG_HI);
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) && !in_img && size <= 0x8000000) {
            char fn[80]; sprintf(fn, "oepdump_out\\region_%08x.bin", base);
            FILE* f = fopen(fn, "wb");
            if (f) {
                static BYTE rbuf[0x1000];
                for (DWORD off = 0; off < size; off += sizeof(rbuf)) {
                    DWORD chunk = size - off; if (chunk > sizeof(rbuf)) chunk = sizeof(rbuf);
                    if (mem_ok((void*)(base + off), chunk)) memcpy(rbuf, (void*)(base + off), chunk);
                    else memset(rbuf, 0, chunk);
                    fwrite(rbuf, 1, chunk, f);
                }
                fclose(f);
                if (idx) fprintf(idx, "%08x %08x prot=%08x\n", base, size, mbi.Protect);
                n++;
            }
        }
        addr = base + size;
    }
    if (idx) fclose(idx);
    lg("oepdump: %d private regions dumped\n", n);
}

// called on the main thread right before the app EP runs (edx=OEP), with the
// thread's registers: we dump and never return.
__attribute__((used)) void on_oep2(void) {
    g_dumped = 1;
    lg("oepdump: === EP launch caught! ===\n");
    dump_all();
    lg("oepdump: done, terminating\n");
    TerminateProcess(GetCurrentProcess(), 0);
    for (;;) Sleep(1000);
}

__attribute__((used)) void detour_log(int which, DWORD edi_v) {
    static int n;
    if (n < 30) { n++; lg("oepdump: site%d #%d edi=%08x\n", which, n, edi_v); }
}

DWORD g_site2_ret;   // back into site2 (call esi path)
DWORD g_site3_ret;   // back into site3 (call edi path)
DWORD g_cfgptr;      // runtime VA of the CFG-check pointer slot

__attribute__((naked)) static void detour2(void) {
    __asm__ volatile(
        "pusha\n\t"
        "mov 0(%esp), %eax\n\t"        // edi
        "sub $8, %esp\n\t"
        "movl $2, 0(%esp)\n\t"
        "mov %eax, 4(%esp)\n\t"
        "call _detour_log\n\t"
        "add $8, %esp\n\t"
        "popa\n\t"
        "cmp $0xFA59700, %edi\n\t"
        "jne 1f\n\t"
        "call _on_oep2\n\t"
        "1:\n\t"
        "mov %edi, %edx\n\t"
        "xor %ecx, %ecx\n\t"
        "call *%esi\n\t"
        "jmp *_g_site2_ret\n\t"
    );
}

__attribute__((naked)) static void detour3(void) {
    __asm__ volatile(
        "pusha\n\t"
        "mov 0(%esp), %eax\n\t"        // edi
        "sub $8, %esp\n\t"
        "movl $3, 0(%esp)\n\t"
        "mov %eax, 4(%esp)\n\t"
        "call _detour_log\n\t"
        "add $8, %esp\n\t"
        "popa\n\t"
        "cmp $0xFA59700, %edi\n\t"
        "jne 1f\n\t"
        "call _on_oep2\n\t"
        "1:\n\t"
        "mov %edi, %ecx\n\t"
        "call *_g_cfgptr\n\t"
        "call *%edi\n\t"
        "jmp *_g_site3_ret\n\t"
    );
}

static DWORD WINAPI helper(LPVOID);

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        lg("oepdump: === attach ===\n");
        // patch the site immediately (ntdll is loaded by now)
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        if (!nt) { lg("no ntdll?!\n"); return TRUE; }
        // site2: RVA 0x682a8: mov edx,edi / xor ecx,ecx / call esi
        // site3: RVA 0xa4876: mov ecx,edi / call [cfg] / call edi
        DWORD site2 = (DWORD)nt + 0x682a8;
        DWORD site3 = (DWORD)nt + 0xa4876;
        g_site2_ret = site2 + 6;
        g_site3_ret = site3 + 10;
        g_cfgptr = (DWORD)nt + 0x1291e0;
        BYTE* b2 = (BYTE*)site2;
        BYTE* b3 = (BYTE*)site3;
        if (!mem_ok(b2, 6) || !mem_ok(b3, 10)) { lg("sites unreadable\n"); return TRUE; }
        lg("oepdump: site2 %08x: %02x %02x %02x %02x %02x %02x\n",
           site2, b2[0], b2[1], b2[2], b2[3], b2[4], b2[5]);
        lg("oepdump: site3 %08x: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
           site3, b3[0], b3[1], b3[2], b3[3], b3[4], b3[5], b3[6], b3[7], b3[8], b3[9]);
        DWORD old;
        if (b2[0] == 0x8b && b2[1] == 0xd7 && b2[4] == 0xff && b2[5] == 0xd6) {
            if (VirtualProtect(b2, 6, PAGE_EXECUTE_READWRITE, &old)) {
                DWORD rel = (DWORD)detour2 - (site2 + 5);
                BYTE jb[6] = { 0xE9, 0, 0, 0, 0, 0x90 };
                memcpy(jb + 1, &rel, 4);
                memcpy(b2, jb, 6);
                VirtualProtect(b2, 6, old, &old);
                lg("oepdump: site2 detoured\n");
            }
        } else lg("oepdump: site2 pattern mismatch\n");
        if (b3[0] == 0x8b && b3[1] == 0xcf && b3[2] == 0xff && b3[3] == 0x15 && b3[8] == 0xff && b3[9] == 0xd7) {
            if (VirtualProtect(b3, 10, PAGE_EXECUTE_READWRITE, &old)) {
                DWORD rel = (DWORD)detour3 - (site3 + 5);
                BYTE jb[10] = { 0xE9, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0x90 };
                memcpy(jb + 1, &rel, 4);
                memcpy(b3, jb, 10);
                VirtualProtect(b3, 10, old, &old);
                lg("oepdump: site3 detoured\n");
            }
        } else lg("oepdump: site3 pattern mismatch\n");
    }
    return TRUE;
}
