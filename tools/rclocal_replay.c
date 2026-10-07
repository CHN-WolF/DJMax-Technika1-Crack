// RC_GrandLocal replay forwarder C part (with per-call diagnostics).
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

HMODULE hReal = 0;
void* g_fn[33];
static HINSTANCE g_hinst;

static FILE* g_lf;
static int g_calls;
DWORD g_ord, g_a1, g_a2, g_a3, g_a4, g_ret, g_orig_ret;

static void lg(const char* fmt, ...) {
    if (!g_lf) { g_lf = fopen("dogpatch_local.log", "a"); if (g_lf) setvbuf(g_lf, 0, _IONBF, 0); }
    if (!g_lf) return;
    va_list ap; va_start(ap, fmt); vfprintf(g_lf, fmt, ap); va_end(ap);
}

static void hexbuf(const char* tag, DWORD p, int n) {
    if (p < 0x10000) return;
    lg("%s=", tag);
    __try {
        for (int i = 0; i < n; i++) lg("%02x", ((BYTE*)p)[i]);
    } __except(1) { lg("<bad>"); }
    lg("\n");
}

void log_pre_c() {
    if (g_calls >= 80) return;
    lg("local#%u(%08x,%08x,%08x,%08x)\n", g_ord, g_a1, g_a2, g_a3, g_a4);
    if (g_ord == 5) {
        hexbuf("  ord5.in32", g_a1, 32);
        hexbuf("  ord5.in16@a2", g_a2, 16);
    }
    if (g_ord == 23) hexbuf("  ord23.pre16@a2", g_a2, 16);
}
void log_post_c() {
    if (g_calls >= 80) return;
    lg("  -> %d (0x%x)\n", g_ret, g_ret);
    if (g_ord == 5) hexbuf("  ord5.out16@a2", g_a2, 16);
    if (g_ord == 23) hexbuf("  ord23.post16@a2", g_a2, 16);
    g_calls++;
}

static HMODULE load_official() {
    HMODULE m = LoadLibraryA("C:\\Windows\\SysWOW64\\RC_GrandLocal.dll");
    if (m) { lg("local: official from SysWOW64\n"); return m; }
    m = LoadLibraryA("RC_GrandLocalReal.dll");
    if (m) { lg("local: official from appdir Real\n"); return m; }
    lg("local: syswow64 & real missing, trying embedded...\n");
    HRSRC r = FindResourceA(g_hinst, "RCLOCALBIN", (LPCSTR)10);
    if (!r) { lg("local: EMBED RESOURCE NOT FOUND\n"); return 0; }
    HGLOBAL g = LoadResource(g_hinst, r);
    DWORD sz = SizeofResource(g_hinst, r);
    void* p = LockResource(g);
    if (!p || !sz) return 0;
    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH - 40, tmp);
    lstrcatA(tmp, "RC_GrandLocal_official.dll");
    HANDLE f = CreateFileA(tmp, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE) { lg("local: temp write fail\n"); return 0; }
    DWORD wr;
    WriteFile(f, p, sz, &wr, 0);
    CloseHandle(f);
    m = LoadLibraryA(tmp);
    lg("local: embedded extracted -> %p\n", m);
    return m;
}

void apply_patches() {
    static const struct { DWORD va; BYTE bytes[6]; int n; } patches[3] = {
        { 0x0FD7FC63, { 0xe9, 0xa3, 0x00, 0x00, 0x00, 0x90 }, 6 },
        { 0x0FD8011D, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }, 6 },
        { 0x0FD80191, { 0x90, 0x90 }, 2 },
    };
    for (int i = 0; i < 3; i++) {
        __try {
            DWORD old;
            if (VirtualProtect((void*)patches[i].va, patches[i].n, PAGE_EXECUTE_READWRITE, &old)) {
                memcpy((void*)patches[i].va, patches[i].bytes, patches[i].n);
                VirtualProtect((void*)patches[i].va, patches[i].n, old, &old);
            }
        } __except (1) {}
    }
}

static int g_fake28_on = 1;
static void* g_real28 = 0;
// ord5 pinned to the verified response from the reference machine; the game's
// expectation is bound to the replayed dog blob, not to the random challenge.
static const BYTE g_ord5_resp[16] = {0xc2,0x73,0xbd,0x84, 0xd0,0x10,0x68,0x6c, 0x33,0x7d,0x97,0x8b, 0x05,0xab,0xf7,0x8b};
static int __stdcall fake5(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    lg("local#5 PINNED (real skipped), resp=c273bd84...\n");
    if (a2 >= 0x10000) { __try { memcpy((void*)a2, g_ord5_resp, 16); } __except(1) {} }
    return 0;
}
static int __stdcall fake28(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    typedef int (__stdcall *t)(DWORD, DWORD, DWORD, DWORD);
    int r = -999;
    if (g_real28) r = ((t)g_real28)(a1, a2, a3, a4);
    lg("local#28 real=%d (0x%x) -> faked 0\n", r, r);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        g_hinst = h;
        lg("local: === attach ===\n");
        hReal = load_official();
        lg("local: hReal=%p\n", hReal);
        if (hReal) {
            int ok = 0;
            for (int i = 1; i <= 32; i++) {
                g_fn[i] = GetProcAddress(hReal, (LPCSTR)(DWORD)i);
                if (g_fn[i]) ok++;
            }
            lg("local: ordinals %d/32\n", ok);
        }
        if (g_fake28_on) {
            g_fn[5] = (void*)fake5;
            g_real28 = g_fn[28];
            g_fn[28] = (void*)fake28;
            lg("local: ordinal 5 PINNED, ordinal 28 wrapped\n");
        }
        apply_patches();
        lg("local: patches applied\n");
    }
    return TRUE;
}
