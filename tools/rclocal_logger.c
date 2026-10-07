// RC_GrandLocal.dll local-layer logger C part (globals + logging + DllMain).
// Thunks live in rclocal_thunks.asm (MASM), convention-agnostic.
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

HMODULE hReal = 0;
static FILE* g_log;
static CRITICAL_SECTION g_cs;
int g_count[33];
DWORD g_ord, g_a1, g_a2, g_a3, g_a4, g_ret, g_orig_ret;
void* g_fn[33];

void log_pre_c();
void log_post_c();

static void log_open() {
    if (!g_log) { g_log = fopen("rclog2.txt", "a"); if (g_log) setvbuf(g_log, 0, _IONBF, 0); }
}
static void LOG(const char* fmt, ...) {
    if (!g_log) return;
    EnterCriticalSection(&g_cs);
    va_list ap; va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap);
    LeaveCriticalSection(&g_cs);
}
static void dumpbuf(const char* tag, DWORD p) {
    if (p < 0x10000) return;
    unsigned char b[16];
    for (int off = 0; off < 256; off += 16) {
        __try { memcpy(b, (void*)(p + off), 16); }
        __except(1) { return; }
        LOG("    %s+%03x: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x | %.16s\n",
            tag, off, b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15], b);
    }
}
static void maydump(const char* tag, DWORD v) {
    if (v < 0x10000) return;
    unsigned char probe[4];
    __try { memcpy(probe, (void*)v, 4); } __except(1) { return; }
    dumpbuf(tag, v);
}

void log_pre_c() {
    if (++g_count[g_ord] > 60) return;
    LOG("local#%u(%08x, %08x, %08x, %08x)\n", g_ord, g_a1, g_a2, g_a3, g_a4);
    maydump("a1-pre", g_a1); maydump("a2-pre", g_a2); maydump("a3-pre", g_a3); maydump("a4-pre", g_a4);
}
void log_post_c() {
    if (g_count[g_ord] > 60) return;
    LOG("  -> %d (0x%x)\n", g_ret, g_ret);
    maydump("a1-post", g_a1); maydump("a2-post", g_a2); maydump("a3-post", g_a3); maydump("a4-post", g_a4);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_cs);
        log_open();
        hReal = LoadLibraryA("RC_GrandLocalReal.dll");
        LOG("=== local logger v2 attached, hReal=%p\n", hReal);
        if (!hReal) return TRUE;
        for (int i = 1; i <= 32; i++) {
            g_fn[i] = GetProcAddress(hReal, (LPCSTR)(DWORD)i);
            if (!g_fn[i]) LOG("  warn: ordinal %d missing in Real\n", i);
        }
    }
    return TRUE;
}
