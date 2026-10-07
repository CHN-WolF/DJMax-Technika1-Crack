// RC_GrandLocal replay forwarder - DIAGNOSTIC build v2 (MinGW/gcc port).
// v2 adds:
//   - vectored exception handler: logs all first-chance exceptions (code/EIP),
//     full detail for C++ EH (0xE06D7363: throw site + thrown type name) and AV
//   - on hook hit: module table dump + hex-dump of LIVE code bytes around every
//     client.exe-range return address (pages are decrypted while executing -
//     this captures them) for offline disassembly
//   - module list so off-image return addresses can be attributed
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <tlhelp32.h>
#include <cpuid.h>

HMODULE hReal = 0;
void* g_fn[33];
static HINSTANCE g_hinst;

static FILE* g_lf;
static int g_calls;
static DWORD g_tick0;
DWORD g_ord, g_a1, g_a2, g_a3, g_a4, g_ret, g_orig_ret;

static void lg(const char* fmt, ...) {
    if (!g_lf) { g_lf = fopen("dogpatch_local.log", "a"); if (g_lf) setvbuf(g_lf, 0, _IONBF, 0); }
    if (!g_lf) return;
    if (!g_tick0) g_tick0 = GetTickCount();
    fprintf(g_lf, "[t=%6lums] ", (unsigned long)(GetTickCount() - g_tick0));
    va_list ap; va_start(ap, fmt); vfprintf(g_lf, fmt, ap); va_end(ap);
}

// guarded read helpers (replace __try/__except)
static int mem_ok(const void* p, DWORD n) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    if ((DWORD)p + n > (DWORD)mbi.BaseAddress + mbi.RegionSize) {
        return mem_ok((void*)((DWORD)mbi.BaseAddress + mbi.RegionSize),
                      (DWORD)p + n - ((DWORD)mbi.BaseAddress + mbi.RegionSize));
    }
    return 1;
}
static int rd32(DWORD p, DWORD* out) {
    if (!mem_ok((void*)p, 4)) return 0;
    memcpy(out, (void*)p, 4);
    return 1;
}

// hex dump of live code bytes around va (va-48 .. va+16), 16 per line
static void dump_code(const char* tag, DWORD va) {
    if (va < 0x10000) return;
    if (!mem_ok((void*)(va - 48), 64)) { lg("     code@%08x: <unreadable>\n", va); return; }
    lg("     code@%08x (%s):\n", va, tag);
    for (DWORD p = va - 48; p < va + 16; p += 16) {
        lg("       %08x: ", p);
        for (int i = 0; i < 16; i++) lg("%02x ", ((BYTE*)p)[i]);
        lg("\n");
    }
}

static void dump_modules(void) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
    if (s == INVALID_HANDLE_VALUE) { lg("mods: snapshot fail\n"); return; }
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    if (Module32First(s, &me)) {
        do {
            lg("mod %08x-%08x %s\n", (DWORD)me.modBaseAddr,
               (DWORD)me.modBaseAddr + me.modBaseSize, me.szExePath);
        } while (Module32Next(s, &me));
    }
    CloseHandle(s);
}

static void hexbuf(const char* tag, DWORD p, int n) {
    if (p < 0x10000) return;
    lg("%s=", tag);
    if (!mem_ok((void*)p, n)) { lg("<bad>\n"); return; }
    for (int i = 0; i < n; i++) lg("%02x", ((BYTE*)p)[i]);
    lg("\n");
}

void install_gai_hook_if_ready(void);
void install_media_hooks_if_ready(void);

void log_pre_c(void) {
    extern void install_hooks(void);
    install_hooks();  // idempotent, per-hook flags
    install_gai_hook_if_ready();  // lazy; needs to be outside loader lock
    install_media_hooks_if_ready();  // ini + d3d9/cursor hooks
    if (g_calls >= 400) return;
    lg("local#%u(%08x,%08x,%08x,%08x)\n", g_ord, g_a1, g_a2, g_a3, g_a4);
    if (g_ord == 5) {
        hexbuf("  ord5.in32", g_a1, 32);
        hexbuf("  ord5.in16@a2", g_a2, 16);
    }
    if (g_ord == 23) hexbuf("  ord23.pre16@a2", g_a2, 16);
}
void log_post_c(void) {
    if (g_calls >= 400) return;
    lg("  -> %d (0x%x)\n", g_ret, g_ret);
    if (g_ord == 5) hexbuf("  ord5.out16@a2", g_a2, 16);
    if (g_ord == 23) hexbuf("  ord23.post16@a2", g_a2, 16);
    g_calls++;
}

static HMODULE load_official(void) {
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

void apply_patches(void) {
    // patches[0..2]: skip the hardware direct check (startup dog verification)
    // patches[3]: neuter Themida's periodic re-check thread proc (0xFD7FB90) -
    //   the block it re-executes gets re-mutated at runtime and the +0xA3 jump
    //   in patches[0] lands mid-instruction -> wild jump crash ~1.5min into gameplay.
    static const struct { DWORD va; BYTE bytes[6]; int n; } patches[4] = {
        { 0x0FD7FC63, { 0xe9, 0xa3, 0x00, 0x00, 0x90 }, 6 },
        { 0x0FD8011D, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }, 6 },
        { 0x0FD80191, { 0x90, 0x90 }, 2 },
        { 0x0FD7FB90, { 0x33, 0xc0, 0xc2, 0x04, 0x00 }, 5 },  // xor eax,eax; ret 4
    };
    for (int i = 0; i < 4; i++) {
        DWORD old;
        if (VirtualProtect((void*)patches[i].va, patches[i].n, PAGE_EXECUTE_READWRITE, &old)) {
            if (mem_ok((void*)patches[i].va, patches[i].n))
                memcpy((void*)patches[i].va, patches[i].bytes, patches[i].n);
            VirtualProtect((void*)patches[i].va, patches[i].n, old, &old);
        }
    }
}

static int g_fake28_on = 1;
static void* g_real28 = 0;
static const BYTE g_ord5_resp[16] = {0xc2,0x73,0xbd,0x84, 0xd0,0x10,0x68,0x6c, 0x33,0x7d,0x97,0x8b, 0x05,0xab,0xf7,0x8b};
static int __stdcall fake5(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    lg("local#5 PINNED (real skipped), resp=c273bd84...\n");
    if (a2 >= 0x10000 && mem_ok((void*)a2, 16)) memcpy((void*)a2, g_ord5_resp, 16);
    return 0;
}
static int __stdcall fake28(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    typedef int (__stdcall *t)(DWORD, DWORD, DWORD, DWORD);
    int r = -999;
    if (g_real28) r = ((t)g_real28)(a1, a2, a3, a4);
    lg("local#28 real=%d (0x%x) -> faked 0\n", r, r);
    return 0;
}

// ===================== vectored exception logging =====================

static int g_exc_count;
static DWORD g_noise_count;

// raw hex+ascii dump of memory (for stack content around the throw)
static void dump_ascii(DWORD base, DWORD len, const char* tag) {
    lg("     rawdump %s @%08x len=%04x:\n", tag, base, len);
    for (DWORD p = base; p < base + len; p += 16) {
        if (!mem_ok((void*)p, 16)) { lg("       %08x: <unreadable>\n", p); continue; }
        lg("       %08x: ", p);
        for (int i = 0; i < 16; i++) lg("%02x ", ((BYTE*)p)[i]);
        lg(" |");
        for (int i = 0; i < 16; i++) {
            BYTE c = ((BYTE*)p)[i];
            lg("%c", (c >= 32 && c < 127) ? c : '.');
        }
        lg("|\n");
    }
}

static void scan_ctx_stack(PCONTEXT ctx, const char* why) {
    DWORD sb = 0, sl = 0;
    NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
    if (tib) { sb = (DWORD)tib->StackBase; sl = (DWORD)tib->StackLimit; }
    lg("     ctx(%s): eip=%08x esp=%08x ebp=%08x\n", why, ctx->Eip, ctx->Esp, ctx->Ebp);
    DWORD ebp = ctx->Ebp;
    for (int k = 0; k < 32; k++) {
        DWORD prev, ret;
        if (sl && (ebp < sl || ebp >= sb)) break;
        if (!rd32(ebp, &prev) || !rd32(ebp + 4, &ret)) break;
        lg("     xframe[%02d] ebp=%08x ret=%08x\n", k, ebp, ret);
        if (ret >= 0x401000 && ret < 0xFF17000) dump_code("xframe", ret);
        if (prev <= ebp || (sb && prev >= sb)) break;
        ebp = prev;
    }
    int found = 0;
    for (DWORD p = ctx->Esp & ~3; p + 4 <= sb && found < 64; p += 4) {
        DWORD v;
        if (!rd32(p, &v)) break;
        if (v >= 0x401000 && v < 0xFF17000) {
            lg("     xstk[%08x] = %08x\n", p, v);
            dump_code("xstk", v);
            found++;
        }
    }
}

static void log_cpp_throwinfo(DWORD ti) {
    // _ThrowInfo*: {attributes, pmfnUnwind, pForwardCompat, pCatchableTypeArray}
    DWORD cta, n, ct, td;
    char name[96];
    if (!rd32(ti + 12, &cta) || !cta) return;
    // CatchableTypeArray: {nCatchableTypes, array[0]=CatchableType*}
    if (!rd32(cta, &n) || !n) return;
    if (!rd32(cta + 4, &ct) || !ct) return;
    // CatchableType: {properties, thisType=_TypeDescriptor*, ...}
    if (!rd32(ct + 4, &td) || !td) return;
    // _TypeDescriptor: {hash, spare, name[]} (VC2005 x86: name at +8)
    int i;
    for (i = 0; i < (int)sizeof(name) - 1; i++) {
        if (!mem_ok((void*)(td + 8 + i), 1)) break;
        name[i] = ((char*)(td + 8))[i];
        if (!name[i]) break;
    }
    name[i] = 0;
    lg("     C++ thrown type: %s\n", name);
}

static LONG CALLBACK veh(PEXCEPTION_POINTERS p) {
    DWORD code = p->ExceptionRecord->ExceptionCode;
    DWORD addr = (DWORD)p->ExceptionRecord->ExceptionAddress;
    DWORD eip = p->ContextRecord ? p->ContextRecord->Eip : 0;
    // known Themida anti-debug noise (present in healthy runs too): count only
    if (code == 0x80000004 || code == 0x80000003 || code == 0xC0000094 ||
        addr == 0x0fdb4197 || addr == 0x0fdb4219) {
        g_noise_count++;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (g_exc_count < 64) {
        g_exc_count++;
        lg("EXC code=%08x addr=%08x eip=%08x flags=%x (noise so far: %lu)\n", code, addr, eip,
           p->ExceptionRecord->ExceptionFlags, (unsigned long)g_noise_count);
        if (code == 0xE06D7363) {  // C++ EH
            DWORD* ei = (DWORD*)p->ExceptionRecord->ExceptionInformation;
            lg("     cpp magic=%08x obj=%08x throwinfo=%08x\n",
               ei ? ei[0] : 0, ei ? ei[1] : 0, ei ? ei[2] : 0);
            if (ei && p->ExceptionRecord->NumberParameters >= 3)
                log_cpp_throwinfo(ei[2]);
            dump_code("throw site", eip);
            if (p->ContextRecord) {
                scan_ctx_stack(p->ContextRecord, "cpp throw");
                // raw stack bytes: the offending std::string object lives here
                dump_ascii(p->ContextRecord->Esp & ~15, 0x800, "throw stack");
                // Themida swaps code blocks; the abort-time memdump shows a
                // different variant. Capture the LIVE function bytes NOW:
                dump_ascii(0x64F000, 0x2000, "live code 64f000-650000");
                dump_ascii(0x401000, 0x2000, "live code 401000-403000");
            }
        }
        if (code == 0xC0000005 || code == 0xC00000FD || code == 0xC000001D) {
            dump_code("fault site", eip);
            if (p->ContextRecord) scan_ctx_stack(p->ContextRecord, "fault");
        }
        if (g_lf) fflush(g_lf);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// ===================== GetAdaptersInfo compatibility hook =====================
// Root cause of the startup abort on multi-adapter machines:
// the game allocates a fixed 648-byte buffer for GetAdaptersInfo and gets an
// EMPTY MAC string (then string::at(0) throws out_of_range -> terminate) when
// the machine has 2+ adapters (needs ~648*N bytes). This hook calls the real
// API with a 16KB static buffer and hands the game its first entry.

static BYTE g_gai_tramp[16];   // stolen prologue + jmp back
static int g_gai_state;        // 0=not tried, 1=hooked, -1=failed
static BYTE g_gai_bigbuf[16384];

void hook_h_gai(void);  // asm stub: jmp my_GetAdaptersInfo

__stdcall DWORD my_GetAdaptersInfo(BYTE* pInfo, DWORD* pLen) {
    typedef DWORD (__stdcall *GAI)(BYTE*, DWORD*);
    DWORD r, need, n;
    lg("gai: called, pInfo=%p *pLen=%lu\n", pInfo, pLen ? (unsigned long)*pLen : 0);
    if (!pInfo || !pLen) return ((GAI)g_gai_tramp)(pInfo, pLen);
    need = sizeof(g_gai_bigbuf);
    r = ((GAI)g_gai_tramp)(g_gai_bigbuf, &need);
    lg("gai: real(bigbuf) -> %lu, needed=%lu, game buffer=%lu\n",
       (unsigned long)r, (unsigned long)need, (unsigned long)*pLen);
    if (r != 0) return r;
    n = *pLen < need ? *pLen : need;
    memcpy(pInfo, g_gai_bigbuf, n);
    *pLen = n;
    return 0;
}

void install_gai_hook_if_ready(void) {
    if (g_gai_state) return;
    HMODULE m = GetModuleHandleA("iphlpapi.dll");
    if (!m) m = LoadLibraryA("iphlpapi.dll");  // called outside loader lock (ord path)
    if (!m) { lg("gai: iphlpapi unavailable\n"); g_gai_state = -1; return; }
    BYTE* p = (BYTE*)GetProcAddress(m, "GetAdaptersInfo");
    if (!p) { lg("gai: GetAdaptersInfo not found\n"); g_gai_state = -1; return; }
    static const BYTE expect[5] = { 0x8b, 0xff, 0x55, 0x8b, 0xec };  // mov edi,edi; push ebp; mov ebp,esp
    if (!mem_ok(p, 5) || memcmp(p, expect, 5) != 0) {
        lg("gai: unexpected prologue %02x %02x %02x %02x %02x - NOT hooking\n",
           mem_ok(p,5)?p[0]:0, mem_ok(p,5)?p[1]:0, mem_ok(p,5)?p[2]:0, mem_ok(p,5)?p[3]:0, mem_ok(p,5)?p[4]:0);
        g_gai_state = -1; return;
    }
    DWORD old;
    memcpy(g_gai_tramp, p, 5);
    g_gai_tramp[5] = 0xE9;
    DWORD rel = (DWORD)(p + 5) - (DWORD)(g_gai_tramp + 10);
    memcpy(g_gai_tramp + 6, &rel, 4);
    if (!VirtualProtect(g_gai_tramp, sizeof(g_gai_tramp), PAGE_EXECUTE_READWRITE, &old)) { g_gai_state = -1; return; }
    if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &old)) { g_gai_state = -1; return; }
    BYTE jb[5]; jb[0] = 0xE9;
    rel = (DWORD)hook_h_gai - ((DWORD)p + 5);
    memcpy(jb + 1, &rel, 4);
    memcpy(p, jb, 5);
    VirtualProtect(p, 5, old, &old);
    g_gai_state = 1;
    lg("gai: GetAdaptersInfo hooked @%p\n", p);
}

void install_gai_hook_if_ready(void);

static void install_gai_hook_dllmain(void) {
    // no LoadLibrary under loader lock: only hook if the game already loaded it
    if (!GetModuleHandleA("iphlpapi.dll")) return;
    install_gai_hook_if_ready();
}

// ===================== ini-driven windowed/cursor forcing =====================
// The game parses debugInfo.ini [setting] fullscreen/show_cursor but its video
// path ignores them (exclusive fullscreen regardless). We honor them ourselves:
// wrap IDirect3D9::CreateDevice (vtable swap) and user32 cursor calls.

static int g_ini_read;
static int g_force_windowed;
static int g_force_cursor;
static int g_pcm_dump;
static int g_fixed_frame;

static void read_game_ini(void) {
    if (g_ini_read) return;
    g_ini_read = 1;
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, path, MAX_PATH - 32);
    path[n] = 0;
    while (n > 0 && path[n - 1] != '\\' && path[n - 1] != '/') n--;
    strcpy(path + n, "debugInfo.ini");
    char buf[32];
    GetPrivateProfileStringA("setting", "fullscreen", "true", buf, sizeof(buf), path);
    g_force_windowed = !strcmp(buf, "false");
    GetPrivateProfileStringA("setting", "show_cursor", "false", buf, sizeof(buf), path);
    g_force_cursor = !strcmp(buf, "true");
    GetPrivateProfileStringA("setting", "fixed_frame", "true", buf, sizeof(buf), path);
    g_fixed_frame = !strcmp(buf, "true");
    // the game REWRITES debugInfo.ini on exit and drops unknown keys -
    // our own flags live in RCdiag.ini instead (never touched by the game)
    strcpy(path + n, "RCdiag.ini");
    GetPrivateProfileStringA("debug_info", "pcm_dump", "false", buf, sizeof(buf), path);
    g_pcm_dump = !strcmp(buf, "true");
    lg("ini: %s -> force_windowed=%d force_cursor=%d pcm_dump=%d\n",
       path, g_force_windowed, g_force_cursor, g_pcm_dump);
}

// generic 5-byte redirect hook with trampoline
static int redirect_hook(const char* mod, const char* fn, void* repl, BYTE* tramp, int* state, int allow_load) {
    if (*state) return *state > 0;
    HMODULE m = GetModuleHandleA(mod);
    if (!m && allow_load) m = LoadLibraryA(mod);
    if (!m) return 0;  // retry later
    BYTE* p = (BYTE*)GetProcAddress(m, fn);
    if (!p) { *state = -1; lg("rhook: %s!%s not found\n", mod, fn); return 0; }
    // follow "jmp dword ptr [slot]" forwarding thunks to the real body
    if (mem_ok(p, 6) && p[0] == 0xFF && p[1] == 0x25) {
        DWORD slot;
        memcpy(&slot, p + 2, 4);
        if (mem_ok((void*)slot, 4)) {
            DWORD real;
            memcpy(&real, (void*)slot, 4);
            if (mem_ok((void*)real, 5)) { lg("rhook: %s!%s thunk %p -> %p\n", mod, fn, p, real); p = (BYTE*)real; }
        }
    }
    // accepted 5-byte prologues: 8B FF 55 8B EC (hotpatch) or B8 xx xx xx xx (mov eax,imm)
    int ok = 0;
    if (mem_ok(p, 5)) {
        static const BYTE expect[5] = { 0x8b, 0xff, 0x55, 0x8b, 0xec };
        if (memcmp(p, expect, 5) == 0) ok = 1;
        else if (p[0] == 0xB8) ok = 1;
    }
    if (!ok) {
        lg("rhook: %s!%s unexpected prologue %02x %02x %02x %02x %02x - NOT hooking\n",
           mod, fn, mem_ok(p,5)?p[0]:0, mem_ok(p,5)?p[1]:0, mem_ok(p,5)?p[2]:0, mem_ok(p,5)?p[3]:0, mem_ok(p,5)?p[4]:0);
        *state = -1; return 0;
    }
    DWORD old;
    memcpy(tramp, p, 5);
    tramp[5] = 0xE9;
    DWORD rel = (DWORD)(p + 5) - (DWORD)(tramp + 10);
    memcpy(tramp + 6, &rel, 4);
    if (!VirtualProtect(tramp, 16, PAGE_EXECUTE_READWRITE, &old)) { *state = -1; return 0; }
    if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &old)) { *state = -1; return 0; }
    BYTE jb[5]; jb[0] = 0xE9;
    rel = (DWORD)repl - ((DWORD)p + 5);
    memcpy(jb + 1, &rel, 4);
    memcpy(p, jb, 5);
    VirtualProtect(p, 5, old, &old);
    *state = 1;
    lg("rhook: %s!%s hooked @%p -> %p\n", mod, fn, p, repl);
    return 1;
}

// ---- IDirect3D9(IDirect3D9Ex)/IDirect3DDevice9(Ex) hooks (in-place vtable patching) ----
// IMPORTANT: never replace an object's vtable pointer with a truncated copy
// here. d3d9's runtime classes have internal virtuals far beyond the COM
// interface (e.g. the present path calls [vtbl+0x288] = slot 162); a 32/128
// slot copy turns those into garbage -> _purecall right after device creation.
// Patch entries inside the REAL (shared, process-wide) class vtable instead.
//
// The game may also use Direct3DCreate9Ex/CreateDeviceEx/PresentEx (the plain
// CreateDevice hook alone never fired in a real run) - hook both families.
// Keyed maps keep per-class originals: the plain and Ex class vtables differ.
static BYTE g_d3d_tramp[16];
static int g_d3d_state;
static BYTE g_d3dex_tramp[16];
static int g_d3dex_state;

static struct { DWORD vt, real_cd, real_cdex; } g_d3dcls[4];  // IDirect3D9/Ex classes
static int g_d3dcls_n;
static struct { DWORD vt, real_reset, real_present, real_presentex, real_resetex,
                    real_addsc, real_getsc, real_qi; } g_devcls[4];
static int g_devcls_n;
static struct { DWORD vt, real_present; } g_sccls[4];          // IDirect3DSwapChain9 classes
static int g_sccls_n;

static void wrap_device9(void* dev, int is_ex);
static void wrap_swapchain9(void* sc);
__stdcall HRESULT my_CreateDevice(void*, UINT, DWORD, HWND, DWORD, DWORD*, void**);
__stdcall HRESULT my_CreateDeviceEx(void*, UINT, DWORD, HWND, DWORD, DWORD*, DWORD*, void**);

void hook_h_d3dcreate9(void);
void hook_h_d3dcreate9ex(void);
void hook_h_showcursor(void);
void hook_h_setcursor(void);
void hook_h_ds8create(void);

// patch one vtable slot in place, returning the original
static DWORD vt_patch(DWORD vt, int slot, DWORD repl) {
    DWORD* v = (DWORD*)vt;
    DWORD old_prot, orig = v[slot];
    if (!VirtualProtect(&v[slot], 4, PAGE_EXECUTE_READWRITE, &old_prot)) return 0;
    v[slot] = repl;
    VirtualProtect(&v[slot], 4, old_prot, &old_prot);
    lg("d3d:   vt %08x slot %d: %08x -> %08x\n", vt, slot, orig, repl);
    return orig;
}

// force windowed mode on a D3DPRESENT_PARAMETERS dword array
static void pp_force_windowed(DWORD* pPP, const char* tag) {
    if (!pPP) return;
    lg("d3d: %s %lux%lu fmt=%lu MSAA=%lu/%lu Windowed=%lu refresh=%lu interval=%lu hWnd=%p",
       tag, (unsigned long)pPP[0], (unsigned long)pPP[1], (unsigned long)pPP[2],
       (unsigned long)pPP[4], (unsigned long)pPP[5],
       (unsigned long)pPP[8], (unsigned long)pPP[12], (unsigned long)pPP[13], pPP[7]);
    if (g_force_windowed && !pPP[8]) {
        pPP[8] = 1;    // Windowed = TRUE
        pPP[12] = 0;   // FullScreen_RefreshRateInHz must be 0 when windowed
        lg(" -> FORCED windowed");
    }
    lg("\n");
}

static void hook_d3d_object(void* obj) {
    if (!obj) return;
    DWORD vt = *(DWORD*)obj;
    for (int i = 0; i < g_d3dcls_n; i++)
        if (g_d3dcls[i].vt == vt) return;  // already patched
    if (g_d3dcls_n >= 4) return;
    if (!mem_ok((void*)vt, 21 * 4)) return;
    int i = g_d3dcls_n++;
    g_d3dcls[i].vt = vt;
    g_d3dcls[i].real_cd = vt_patch(vt, 16, (DWORD)my_CreateDevice);     // CreateDevice
    g_d3dcls[i].real_cdex = mem_ok((void*)(vt + 20 * 4), 4) ?
        vt_patch(vt, 20, (DWORD)my_CreateDeviceEx) : 0;                  // CreateDeviceEx (Ex only)
    lg("d3d: IDirect3D9(Ex) class %08x patched (CreateDevice%s)\n", vt, g_d3dcls[i].real_cdex ? "+Ex" : "");
}

__stdcall HRESULT my_CreateDevice(void* self, UINT Adapter, DWORD DevType, HWND hFocus,
                                  DWORD Behav, DWORD* pPP, void** ppDev) {
    typedef HRESULT (__stdcall *CD)(void*, UINT, DWORD, HWND, DWORD, DWORD*, void**);
    DWORD vt = *(DWORD*)self, orig = 0;
    for (int i = 0; i < g_d3dcls_n; i++)
        if (g_d3dcls[i].vt == vt) { orig = g_d3dcls[i].real_cd; break; }
    if (!orig) return 0x80004001;  // E_NOTIMPL; should never happen
    lg("d3d: CreateDevice #%u caller=%p\n", Adapter, __builtin_return_address(0));
    pp_force_windowed(pPP, "CreateDevice");
    HRESULT hr = ((CD)orig)(self, Adapter, DevType, hFocus, Behav, pPP, ppDev);
    lg("d3d: CreateDevice -> %08x dev=%p\n", (unsigned)hr, (ppDev && SUCCEEDED(hr)) ? *ppDev : 0);
    if (SUCCEEDED(hr) && ppDev && *ppDev) wrap_device9(*ppDev, 0);
    return hr;
}

__stdcall HRESULT my_CreateDeviceEx(void* self, UINT Adapter, DWORD DevType, HWND hFocus,
                                    DWORD Behav, DWORD* pPP, DWORD* pFM, void** ppDev) {
    typedef HRESULT (__stdcall *CDX)(void*, UINT, DWORD, HWND, DWORD, DWORD*, DWORD*, void**);
    DWORD vt = *(DWORD*)self, orig = 0;
    for (int i = 0; i < g_d3dcls_n; i++)
        if (g_d3dcls[i].vt == vt) { orig = g_d3dcls[i].real_cdex; break; }
    if (!orig) return 0x80004001;
    lg("d3d: CreateDeviceEx #%u caller=%p\n", Adapter, __builtin_return_address(0));
    pp_force_windowed(pPP, "CreateDeviceEx");
    HRESULT hr = ((CDX)orig)(self, Adapter, DevType, hFocus, Behav, pPP, pFM, ppDev);
    lg("d3d: CreateDeviceEx -> %08x dev=%p\n", (unsigned)hr, (ppDev && SUCCEEDED(hr)) ? *ppDev : 0);
    if (SUCCEEDED(hr) && ppDev && *ppDev) wrap_device9(*ppDev, 1);
    return hr;
}

__stdcall void* my_Direct3DCreate9(UINT sdk) {
    typedef void* (__stdcall *D9)(UINT);
    void* obj = ((D9)g_d3d_tramp)(sdk);
    lg("d3d: Direct3DCreate9(%u) -> %p caller=%p\n", sdk, obj, __builtin_return_address(0));
    hook_d3d_object(obj);
    return obj;
}

__stdcall HRESULT my_Direct3DCreate9Ex(UINT sdk, void** ppEx) {
    typedef HRESULT (__stdcall *D9X)(UINT, void**);
    HRESULT hr = ((D9X)g_d3dex_tramp)(sdk, ppEx);
    lg("d3d: Direct3DCreate9Ex(%u) -> %08x obj=%p caller=%p\n",
       sdk, (unsigned)hr, (ppEx && SUCCEEDED(hr)) ? *ppEx : 0, __builtin_return_address(0));
    if (SUCCEEDED(hr) && ppEx && *ppEx) hook_d3d_object(*ppEx);
    return hr;
}

// ---- 60fps frame cap (fixed_frame key) + Reset passthrough ----
// The countdown/game logic is frame-count-tied assuming 60fps; on high-refresh
// desktops (240Hz) the game runs 4x fast (60s music-select countdown in ~15s).
// Arcade-authentic fix: throttle IDirect3DDevice9::Present/PresentEx to 16.67ms.
// vtable slots per d3d9.h: Reset=16, Present=17 (15 is GetNumberOfSwapChains);
// IDirect3DDevice9Ex adds PresentEx=121, ResetEx=132.
static LARGE_INTEGER g_qpf, g_qpl;
static int g_frame_n;
static double g_frame_sum;
static int g_vtable_wipes;
static void throttle_60fps(void);
__stdcall HRESULT my_Device9_QueryInterface(void*, BYTE*, void**);
__stdcall HRESULT my_Device9_Reset(void*, DWORD*);
__stdcall HRESULT my_Device9_Present(void*, DWORD, DWORD, DWORD, DWORD);

// body-patch helper (redirect_hook-style) for d3d9 internal functions
static int body_patch(void* p, void* repl, BYTE* tramp) {
    DWORD old;
    if (!mem_ok(p, 5)) return 0;
    memcpy(tramp, p, 5);
    tramp[5] = 0xE9;
    DWORD rel = (DWORD)p + 5 - (DWORD)(tramp + 10);
    memcpy(tramp + 6, &rel, 4);
    if (!VirtualProtect(tramp, 16, PAGE_EXECUTE_READWRITE, &old)) return 0;
    if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &old)) return 0;
    BYTE jb[5] = { 0xE9, 0, 0, 0, 0 };
    rel = (DWORD)repl - ((DWORD)p + 5);
    memcpy(jb + 1, &rel, 4);
    memcpy(p, jb, 5);
    VirtualProtect(p, 5, old, &old);
    return 1;
}

// body hook on d3d9's own Present worker (catches internal forwarding paths too)
// PRIMARY throttle point: d3d9 re-fills its heap device vtable shortly after
// creation (observed: our slot patches wiped between frames 3 and 600), so the
// vtable hooks are unreliable; this .text body patch survives. my_PresentBody
// also re-applies the vtable slot patch whenever it notices the wipe.
static BYTE g_presentbody_tramp[16];
static int g_presentbody_n;
__stdcall HRESULT my_PresentBody(void* self, DWORD r1, DWORD r2, DWORD r3, DWORD r4) {
    typedef HRESULT (__stdcall *PR)(void*, DWORD, DWORD, DWORD, DWORD);
    if (g_presentbody_n < 3 || (g_presentbody_n % 600) == 0)
        lg("d3d: Present BODY hit #%d self=%p caller=%p\n", g_presentbody_n, self, __builtin_return_address(0));
    g_presentbody_n++;
    // vtable-wipe watchdog + self heal
    if (self && mem_ok(self, 4)) {
        DWORD vt = *(DWORD*)self;
        for (int i = 0; i < g_devcls_n; i++)
            if (g_devcls[i].vt == vt && mem_ok((void*)vt, 18 * 4) &&
                ((DWORD*)vt)[17] != (DWORD)my_Device9_Present) {
                g_devcls[i].real_qi = vt_patch(vt, 0, (DWORD)my_Device9_QueryInterface);
                vt_patch(vt, 16, (DWORD)my_Device9_Reset);
                vt_patch(vt, 17, (DWORD)my_Device9_Present);
                lg("d3d: device vtable wiped -> re-patched (wipe #%d at hit #%d)\n",
                   ++g_vtable_wipes, g_presentbody_n);
                break;
            }
    }
    HRESULT hr = ((PR)g_presentbody_tramp)(self, r1, r2, r3, r4);
    throttle_60fps();
    return hr;
}

// body hook on d3d9's Reset worker: keep windowed enforcement alive even if the
// device vtable slot 16 patch got wiped
static BYTE g_resetbody_tramp[16];
__stdcall HRESULT my_ResetBody(void* self, DWORD* pPP) {
    typedef HRESULT (__stdcall *RS)(void*, DWORD*);
    pp_force_windowed(pPP, "Reset(body)");
    return ((RS)g_resetbody_tramp)(self, pPP);
}

static void throttle_60fps(void) {
    if (!g_fixed_frame || !g_qpf.QuadPart) {
        static int g_skip_n;
        if (g_skip_n++ < 3) lg("d3d: throttle SKIP fixed_frame=%d qpf=%lld\n", g_fixed_frame, (long long)g_qpf.QuadPart);
        return;
    }
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    if (g_qpl.QuadPart) {
        double el = (double)(now.QuadPart - g_qpl.QuadPart) * 1000.0 / (double)g_qpf.QuadPart;
        g_frame_sum += el;
        const double target = 16.6667;  // 60 fps
        static int g_dbg_n;
        if (g_dbg_n < 40) { g_dbg_n++; lg("d3d: frame #%d el=%.2fms%s\n", g_dbg_n, el, el < target ? " (sleep)" : ""); }
        if (el < target) {
            DWORD s = (DWORD)(target - el);
            if (s > 2) Sleep(s - 2);
            do { QueryPerformanceCounter(&now); }
            while ((double)(now.QuadPart - g_qpl.QuadPart) * 1000.0 / (double)g_qpf.QuadPart < target);
        }
        if (++g_frame_n >= 300) {
            lg("d3d: avg arrival %.2f ms over %d presents (pre-throttle rate)\n",
               g_frame_sum / g_frame_n, g_frame_n);
            g_frame_n = 0; g_frame_sum = 0;
        }
    }
    g_qpl = now;
}

__stdcall HRESULT my_Device9_Reset(void* self, DWORD* pPP) {
    typedef HRESULT (__stdcall *RS)(void*, DWORD*);
    DWORD vt = *(DWORD*)self, orig = 0;
    for (int i = 0; i < g_devcls_n; i++)
        if (g_devcls[i].vt == vt) { orig = g_devcls[i].real_reset; break; }
    if (!orig) return 0x80004001;
    pp_force_windowed(pPP, "Reset");
    return ((RS)orig)(self, pPP);
}

__stdcall HRESULT my_Device9_ResetEx(void* self, DWORD* pPP, DWORD* pFM) {
    typedef HRESULT (__stdcall *RSX)(void*, DWORD*, DWORD*);
    DWORD vt = *(DWORD*)self, orig = 0;
    for (int i = 0; i < g_devcls_n; i++)
        if (g_devcls[i].vt == vt) { orig = g_devcls[i].real_resetex; break; }
    if (!orig) return 0x80004001;
    pp_force_windowed(pPP, "ResetEx");
    return ((RSX)orig)(self, pPP, pFM);
}

__stdcall HRESULT my_Device9_Present(void* self, DWORD r1, DWORD r2, DWORD r3, DWORD r4) {
    typedef HRESULT (__stdcall *PR)(void*, DWORD, DWORD, DWORD, DWORD);
    DWORD vt = *(DWORD*)self, orig = 0;
    for (int i = 0; i < g_devcls_n; i++)
        if (g_devcls[i].vt == vt) { orig = g_devcls[i].real_present; break; }
    if (!orig) return 0x80004001;
    // passthrough only - throttling lives in the body hook (my_PresentBody),
    // which survives d3d9's heap-vtable re-fills
    return ((PR)orig)(self, r1, r2, r3, r4);
}

__stdcall HRESULT my_Device9_PresentEx(void* self, DWORD r1, DWORD r2, DWORD r3, DWORD r4, DWORD flags) {
    typedef HRESULT (__stdcall *PRX)(void*, DWORD, DWORD, DWORD, DWORD, DWORD);
    DWORD vt = *(DWORD*)self, orig = 0;
    for (int i = 0; i < g_devcls_n; i++)
        if (g_devcls[i].vt == vt) { orig = g_devcls[i].real_presentex; break; }
    if (!orig) return 0x80004001;
    HRESULT hr = ((PRX)orig)(self, r1, r2, r3, r4, flags);
    throttle_60fps();
    return hr;
}

// The game presents through the implicit swap chain (IDirect3DSwapChain9::Present,
// slot 3), never via device->Present - so capture swap chains here.
// Also watch QueryInterface (slot 0): whichever interface the game asks for
// (IDirect3DDevice9Ex / IDirect3DSwapChain9) tells us the real present path.
static const BYTE IID_Dev9Ex[16] = {0xce,0x10,0x8b,0xb1,0x49,0x26,0x5a,0x40,0x87,0x0f,0x95,0xf7,0x77,0xd4,0x31,0x3a};
static const BYTE IID_SwapChain9[16] = {0xf2,0x50,0x49,0x79,0xfc,0xad,0x8a,0x45,0x90,0x5e,0x10,0xa1,0x0b,0x0b,0x50,0x3b};

__stdcall HRESULT my_Device9_QueryInterface(void* self, BYTE* riid, void** ppv) {
    typedef HRESULT (__stdcall *QI)(void*, BYTE*, void**);
    DWORD vt = *(DWORD*)self, orig = 0;
    for (int i = 0; i < g_devcls_n; i++)
        if (g_devcls[i].vt == vt) { orig = g_devcls[i].real_qi; break; }
    if (!orig) return 0x80004001;
    HRESULT hr = ((QI)orig)(self, riid, ppv);
    if (mem_ok(riid, 16)) {
        lg("d3d: device QI {%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x} -> %08x caller=%p\n",
           riid[0],riid[1],riid[2],riid[3],riid[4],riid[5],riid[6],riid[7],
           riid[8],riid[9],riid[10],riid[11],riid[12],riid[13],riid[14],riid[15], (unsigned)hr,
           __builtin_return_address(0));
        if (SUCCEEDED(hr) && ppv && *ppv) {
            if (!memcmp(riid, IID_Dev9Ex, 16)) { lg("d3d:  ^ IDirect3DDevice9Ex!\n"); wrap_device9(*ppv, 1); }
            if (!memcmp(riid, IID_SwapChain9, 16)) { lg("d3d:  ^ IDirect3DSwapChain9!\n"); wrap_swapchain9(*ppv); }
            // one-time introspection dump for any other succeeded interface:
            // the real present path may live behind a non-standard IID
            DWORD ivt = *(DWORD*)*ppv;
            static DWORD seen_vt[8];
            static int seen_n;
            int seen = 0;
            for (int k = 0; k < seen_n; k++) if (seen_vt[k] == ivt) seen = 1;
            if (!seen && seen_n < 8 && mem_ok((void*)ivt, 4)) {
                seen_vt[seen_n++] = ivt;
                lg("d3d: iface dump obj=%p vt=%08x\n", *ppv, ivt);
                for (int s = 0; s < 40; s++) {
                    DWORD fn;
                    if (!mem_ok((void*)(ivt + s * 4), 4)) break;
                    fn = ((DWORD*)ivt)[s];
                    int retn = -1;
                    BYTE* b = (BYTE*)fn;
                    if (mem_ok(b, 0x300))
                        for (int k = 0; k < 0x2fd; k++)
                            if (b[k] == 0xC2) { retn = b[k + 1] | (b[k + 2] << 8); break; }
                            else if (b[k] == 0xC3) { retn = 0; break; }
                    lg("d3d:   iface[%d]=%08x first-ret=%d\n", s, fn, retn);
                }
            }
        }
    }
    return hr;
}

__stdcall HRESULT my_Device9_GetSwapChain(void* self, UINT idx, void** ppSC) {
    typedef HRESULT (__stdcall *GS)(void*, UINT, void**);
    DWORD vt = *(DWORD*)self, orig = 0;
    for (int i = 0; i < g_devcls_n; i++)
        if (g_devcls[i].vt == vt) { orig = g_devcls[i].real_getsc; break; }
    if (!orig) return 0x80004001;
    HRESULT hr = ((GS)orig)(self, idx, ppSC);
    if (SUCCEEDED(hr) && ppSC && *ppSC) wrap_swapchain9(*ppSC);
    return hr;
}

__stdcall HRESULT my_Device9_CreateAdditionalSwapChain(void* self, DWORD* pPP, void** ppSC) {
    typedef HRESULT (__stdcall *CAS)(void*, DWORD*, void**);
    DWORD vt = *(DWORD*)self, orig = 0;
    for (int i = 0; i < g_devcls_n; i++)
        if (g_devcls[i].vt == vt) { orig = g_devcls[i].real_addsc; break; }
    if (!orig) return 0x80004001;
    pp_force_windowed(pPP, "CreateAdditionalSwapChain");
    HRESULT hr = ((CAS)orig)(self, pPP, ppSC);
    if (SUCCEEDED(hr) && ppSC && *ppSC) wrap_swapchain9(*ppSC);
    return hr;
}

__stdcall HRESULT my_SC9_Present(void* self, DWORD r1, DWORD r2, DWORD r3, DWORD r4, DWORD flags) {
    typedef HRESULT (__stdcall *SPR)(void*, DWORD, DWORD, DWORD, DWORD, DWORD);
    DWORD vt = *(DWORD*)self, orig = 0;
    for (int i = 0; i < g_sccls_n; i++)
        if (g_sccls[i].vt == vt) { orig = g_sccls[i].real_present; break; }
    if (!orig) return 0x80004001;
    HRESULT hr = ((SPR)orig)(self, r1, r2, r3, r4, flags);
    throttle_60fps();
    return hr;
}

static void wrap_swapchain9(void* sc) {
    DWORD vt = *(DWORD*)sc;
    for (int i = 0; i < g_sccls_n; i++)
        if (g_sccls[i].vt == vt) return;
    if (g_sccls_n >= 4) return;
    if (!mem_ok((void*)vt, 4 * 4)) return;
    int i = g_sccls_n++;
    g_sccls[i].vt = vt;
    g_sccls[i].real_present = vt_patch(vt, 3, (DWORD)my_SC9_Present);  // Present
    lg("d3d: IDirect3DSwapChain9 class %08x patched (Present)\n", vt);
}

static void wrap_device9(void* dev, int is_ex) {
    DWORD vt = *(DWORD*)dev;
    for (int i = 0; i < g_devcls_n; i++)
        if (g_devcls[i].vt == vt) return;  // class already patched
    if (g_devcls_n >= 4) return;
    if (!mem_ok((void*)vt, 18 * 4)) return;
    DWORD* v = (DWORD*)vt;
    // empirical slot ID log: first `ret N` in each candidate body
    // (GetNumberOfSwapChains=ret 4, Reset=ret 8, Present=ret 0x14)
    for (int s = 15; s <= 17; s++) {
        BYTE* fn = (BYTE*)v[s];
        int retn = -1;
        if (mem_ok(fn, 0x300))
            for (int k = 0; k < 0x2fd; k++)
                if (fn[k] == 0xC2) { retn = fn[k + 1] | (fn[k + 2] << 8); break; }
                else if (fn[k] == 0xC3) { retn = 0; break; }
        lg("d3d: devvt[%d]=%08x first-ret=%d\n", s, (DWORD)fn, retn);
    }
    int i = g_devcls_n++;
    g_devcls[i].vt = vt;
    g_devcls[i].real_qi = vt_patch(vt, 0, (DWORD)my_Device9_QueryInterface);
    g_devcls[i].real_reset = vt_patch(vt, 16, (DWORD)my_Device9_Reset);
    g_devcls[i].real_present = vt_patch(vt, 17, (DWORD)my_Device9_Present);
    g_devcls[i].real_presentex = 0;
    g_devcls[i].real_resetex = 0;
    g_devcls[i].real_addsc = vt_patch(vt, 13, (DWORD)my_Device9_CreateAdditionalSwapChain);
    g_devcls[i].real_getsc = vt_patch(vt, 14, (DWORD)my_Device9_GetSwapChain);
    if (is_ex && mem_ok((void*)(vt + 133 * 4), 4)) {
        g_devcls[i].real_presentex = vt_patch(vt, 121, (DWORD)my_Device9_PresentEx);
        g_devcls[i].real_resetex = vt_patch(vt, 132, (DWORD)my_Device9_ResetEx);
    }
    timeBeginPeriod(1);
    QueryPerformanceFrequency(&g_qpf);
    g_qpl.QuadPart = 0;
    lg("d3d: IDirect3DDevice9%s class %08x patched (Reset/Present%s), fixed_frame=%d\n",
       is_ex ? "Ex" : "", vt, is_ex ? "/PresentEx" : "", g_fixed_frame);
    // also body-patch d3d9's Present/Reset workers themselves, once (they live
    // in .text and survive the heap-vtable re-fill that wipes our slot patches)
    static int g_body_done;
    if (!g_body_done && g_devcls[i].real_present) {
        int ok = body_patch((void*)g_devcls[i].real_present, (void*)my_PresentBody, g_presentbody_tramp);
        lg("d3d: Present body patch %s @%08x\n", ok ? "ok" : "FAILED", g_devcls[i].real_present);
        if (ok && g_devcls[i].real_reset) {
            ok = body_patch((void*)g_devcls[i].real_reset, (void*)my_ResetBody, g_resetbody_tramp);
            lg("d3d: Reset body patch %s @%08x\n", ok ? "ok" : "FAILED", g_devcls[i].real_reset);
        }
        if (ok) g_body_done = 1;
    }
}


// ---- DirectSound PCM capture (verify 背景音增强/效果音增强 toggles) ----
// Safe design (v10 regression lesson): each REAL buffer class gets its OWN
// vtable copy (primary vs secondary classes differ - mixing their vtables
// broke GetStatus). Only Unlock (slot 19) is replaced; everything else stays
// the class's own code. Capture is OFF unless [debug_info] pcm_dump=true.

static BYTE g_ds8_tramp[16];
static int g_ds8_state;
static DWORD g_ds8_vtbl[32];
static DWORD g_ds8_real_csb;
static int g_ds8_wrapped;

typedef struct { DWORD orig; DWORD copy[25]; DWORD real_unlock; } VTMAP;
static VTMAP g_vtmap[8];
static int g_vtmap_n;

static FILE* pcm_file_for(void* buf) {
    // one file per buffer object: pcm_<addr>.raw in the game dir
    static struct { void* buf; FILE* f; } slots[64];
    static int nslots;
    for (int i = 0; i < nslots; i++)
        if (slots[i].buf == buf) return slots[i].f;
    if (nslots >= 64) return 0;
    char name[64];
    wsprintfA(name, "pcm_%08x.raw", (unsigned)buf);
    FILE* f = fopen(name, "wb");
    if (!f) return 0;
    slots[nslots].buf = buf;
    slots[nslots].f = f;
    nslots++;
    lg("pcm: capture start buf=%p -> %s\n", buf, name);
    return f;
}

__stdcall HRESULT my_DSB_Unlock(void* self, void* p1, DWORD b1, void* p2, DWORD b2) {
    typedef HRESULT (__stdcall *UL)(void*, void*, DWORD, void*, DWORD);
    DWORD vt = *(DWORD*)self;
    DWORD real = 0;
    for (int i = 0; i < g_vtmap_n; i++)
        if ((DWORD)g_vtmap[i].copy == vt) { real = g_vtmap[i].real_unlock; break; }
    if (!real) return 0x80004005;  // should never happen
    if (g_pcm_dump) {
        FILE* f = pcm_file_for(self);
        if (f) {
            if (p1 && b1 && mem_ok(p1, b1)) fwrite(p1, 1, b1, f);
            if (p2 && b2 && mem_ok(p2, b2)) fwrite(p2, 1, b2, f);
        }
    }
    return ((UL)real)(self, p1, b1, p2, b2);
}

static void wrap_dsb(void* obj) {
    DWORD* vtfield = (DWORD*)obj;
    DWORD vt = *vtfield;
    for (int i = 0; i < g_vtmap_n; i++)
        if (g_vtmap[i].orig == vt) {
            DWORD old;
            if (VirtualProtect(vtfield, 4, PAGE_EXECUTE_READWRITE, &old)) {
                *vtfield = (DWORD)g_vtmap[i].copy;
                VirtualProtect(vtfield, 4, old, &old);
            }
            return;
        }
    if (g_vtmap_n >= 8) return;
    if (!mem_ok((void*)vt, 21 * 4)) return;
    VTMAP* m = &g_vtmap[g_vtmap_n++];
    m->orig = vt;
    int nent = mem_ok((void*)vt, 25 * 4) ? 25 : 21;
    memcpy(m->copy, (void*)vt, nent * 4);
    m->real_unlock = m->copy[19];
    m->copy[19] = (DWORD)my_DSB_Unlock;
    DWORD old;
    if (VirtualProtect(vtfield, 4, PAGE_EXECUTE_READWRITE, &old)) {
        *vtfield = (DWORD)m->copy;
        VirtualProtect(vtfield, 4, old, &old);
    }
    lg("pcm: wrapped buffer class vt=%08x (entries=%d)\n", vt, nent);
}

__stdcall HRESULT my_DS8_CreateSoundBuffer(void* self, void* desc, void** ppBuf, void* unk) {
    typedef HRESULT (__stdcall *CSB)(void*, void*, void**, void*);
    HRESULT hr = ((CSB)g_ds8_real_csb)(self, desc, ppBuf, unk);
    if (SUCCEEDED(hr) && ppBuf && *ppBuf) {
        DWORD flags = 0, bytes = 0, rate = 0, ch = 0, bits = 0;
        if (mem_ok(desc, 12)) {
            flags = *(DWORD*)((BYTE*)desc + 4);
            bytes = *(DWORD*)((BYTE*)desc + 8);
            DWORD wfx = *(DWORD*)((BYTE*)desc + 12);
            if (mem_ok((void*)wfx, 16)) {
                ch = *(WORD*)(wfx + 2);
                rate = *(DWORD*)(wfx + 4);
                bits = *(WORD*)(wfx + 14);
            }
        }
        lg("pcm: CreateSoundBuffer flags=%08x bytes=%lu %luHz %luch %lubit -> %p\n",
           flags, (unsigned long)bytes, (unsigned long)rate, (unsigned long)ch,
           (unsigned long)bits, *ppBuf);
        if (!(flags & 1)) wrap_dsb(*ppBuf);  // skip primary buffer entirely
    }
    return hr;
}

__stdcall HRESULT my_DirectSoundCreate8(void* guid, void** ppDS, void* unk) {
    typedef HRESULT (__stdcall *DSC)(void*, void**, void*);
    HRESULT hr = ((DSC)g_ds8_tramp)(guid, ppDS, unk);
    lg("pcm: DirectSoundCreate8 -> %08x\n", (unsigned)hr);
    if (SUCCEEDED(hr) && ppDS && *ppDS) {
        DWORD* pobj = (DWORD*)*ppDS;
        DWORD vt = *pobj;
        if (!g_ds8_wrapped) {
            if (mem_ok((void*)vt, 32 * 4)) {
                DWORD old;
                memcpy(g_ds8_vtbl, (void*)vt, 32 * 4);
                g_ds8_real_csb = g_ds8_vtbl[3];
                g_ds8_vtbl[3] = (DWORD)my_DS8_CreateSoundBuffer;
                if (VirtualProtect(pobj, 4, PAGE_EXECUTE_READWRITE, &old)) {
                    *pobj = (DWORD)g_ds8_vtbl;
                    VirtualProtect(pobj, 4, old, &old);
                    g_ds8_wrapped = 1;
                    lg("pcm: IDirectSound8 vtable wrapped\n");
                }
            }
        } else if (vt != (DWORD)g_ds8_vtbl) {
            // Bink and friends get their own IDirectSound8 objects - wrap them all
            DWORD old;
            if (VirtualProtect(pobj, 4, PAGE_EXECUTE_READWRITE, &old)) {
                *pobj = (DWORD)g_ds8_vtbl;
                VirtualProtect(pobj, 4, old, &old);
                lg("pcm: extra IDirectSound8 object wrapped\n");
            }
        }
    }
    return hr;
}

// ---- cursor visibility ----
static BYTE g_scur_tramp[16];
static int g_scur_state;
static int g_cur_log_count;

__stdcall int my_ShowCursor(int bShow) {
    typedef int (__stdcall *SC)(int);
    if (g_force_cursor && !bShow) {
        if (g_cur_log_count < 8) { g_cur_log_count++; lg("cursor: ShowCursor(FALSE) -> TRUE (forced)\n"); }
        bShow = TRUE;
    }
    return ((SC)g_scur_tramp)(bShow);
}

static BYTE g_setcur_tramp[16];
static int g_setcur_state;
static DWORD g_arrow_cursor;

__stdcall DWORD my_SetCursor(DWORD hCursor) {
    typedef DWORD (__stdcall *SC)(DWORD);
    if (g_force_cursor && !hCursor) {
        if (!g_arrow_cursor) g_arrow_cursor = (DWORD)LoadCursorA(NULL, (LPCSTR)32512); // IDC_ARROW
        if (g_cur_log_count < 8) { g_cur_log_count++; lg("cursor: SetCursor(NULL) -> arrow (forced)\n"); }
        hCursor = g_arrow_cursor;
    }
    return ((SC)g_setcur_tramp)(hCursor);
}


void install_media_hooks_if_ready(void) {
    read_game_ini();
    redirect_hook("d3d9.dll", "Direct3DCreate9", (void*)hook_h_d3dcreate9, g_d3d_tramp, &g_d3d_state, 1);
    redirect_hook("d3d9.dll", "Direct3DCreate9Ex", (void*)hook_h_d3dcreate9ex, g_d3dex_tramp, &g_d3dex_state, 0);
    if (g_pcm_dump)
        redirect_hook("dsound.dll", "DirectSoundCreate8", (void*)hook_h_ds8create, g_ds8_tramp, &g_ds8_state, 1);
    if (g_force_cursor) {
        redirect_hook("user32.dll", "ShowCursor", (void*)hook_h_showcursor, g_scur_tramp, &g_scur_state, 0);
        redirect_hook("user32.dll", "SetCursor", (void*)hook_h_setcursor, g_setcur_tramp, &g_setcur_state, 0);
    }
}

// ===================== abort/exit catcher =====================

enum { H_ABORT, H_PURECALL, H_ASSERT, H_WASSERT, H_EXITPROC, H_TERMPROC, H_MSGBOXA, H_MSGBOXW, H_COUNT };

typedef struct {
    const char* mod;
    const char* fn;
    void* addr;
    BYTE orig[5];
    volatile LONG installed;  // 0=no, 1=hooked, 2=restored, 3=fn missing
    void* handler;
} HOOKT;

void hook_h_abort(void);
void hook_h_purecall(void);
void hook_h_assert(void);
void hook_h_wassert(void);
void hook_h_exitproc(void);
void hook_h_termproc(void);
void hook_h_msgboxa(void);
void hook_h_msgboxw(void);

static HOOKT g_hk[H_COUNT] = {
    { "msvcrt.dll",  "abort",            0, {0}, 0, hook_h_abort },
    { "msvcrt.dll",  "_purecall",        0, {0}, 0, hook_h_purecall },
    { "msvcrt.dll",  "_assert",          0, {0}, 0, hook_h_assert },
    { "msvcrt.dll",  "_wassert",         0, {0}, 0, hook_h_wassert },
    { "kernel32.dll","ExitProcess",      0, {0}, 0, hook_h_exitproc },
    { "kernel32.dll","TerminateProcess", 0, {0}, 0, hook_h_termproc },
    { "user32.dll",  "MessageBoxA",      0, {0}, 0, hook_h_msgboxa },
    { "user32.dll",  "MessageBoxW",      0, {0}, 0, hook_h_msgboxw },
};

DWORD g_hit_esp, g_hit_ebp, g_hit_ret, g_hit_arg1, g_hit_arg2, g_hit_arg3, g_hit_arg4;
DWORD g_hit_id;
DWORD g_resume;
static int g_mods_dumped;

static void log_cstrA(DWORD p) {
    char buf[160];
    int i;
    if (!p || !mem_ok((void*)p, 1)) { lg("<null>"); return; }
    for (i = 0; i < (int)sizeof(buf) - 1; i++) {
        if (!mem_ok((void*)(p + i), 1)) break;
        buf[i] = ((char*)p)[i];
        if (!buf[i]) break;
    }
    buf[i] = 0;
    lg("\"%s\"%s", buf, i >= (int)sizeof(buf) - 1 ? "..." : "");
}
static void log_cstrW(DWORD p) {
    char buf[160];
    int i;
    if (!p || !mem_ok((void*)p, 2)) { lg("<null>"); return; }
    for (i = 0; i < (int)sizeof(buf) - 1; i++) {
        WCHAR c;
        if (!mem_ok((void*)(p + i * 2), 2)) break;
        c = *(WCHAR*)(p + i * 2);
        if (!c) break;
        buf[i] = (c < 128) ? (char)c : '?';
    }
    buf[i] = 0;
    lg("L\"%s\"%s", buf, i >= (int)sizeof(buf) - 1 ? "..." : "");
}

void full_image_dump(void);

void stack_report(void) {
    DWORD sb = 0, sl = 0;
    NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
    if (tib) { sb = (DWORD)tib->StackBase; sl = (DWORD)tib->StackLimit; }
    HOOKT* h = &g_hk[g_hit_id];
    lg("!!!! HOOK %s!%s hit, caller=%08x args=%08x,%08x,%08x,%08x esp=%08x ebp=%08x stk=%08x-%08x\n",
       h->mod, h->fn, g_hit_ret, g_hit_arg1, g_hit_arg2, g_hit_arg3, g_hit_arg4,
       g_hit_esp, g_hit_ebp, sl, sb);
    full_image_dump();
    if (g_hit_id == H_MSGBOXA) {
        lg("     MsgBoxA caption="); log_cstrA(g_hit_arg3);
        lg(" text="); log_cstrA(g_hit_arg2); lg("\n");
    }
    if (g_hit_id == H_MSGBOXW) {
        lg("     MsgBoxW caption="); log_cstrW(g_hit_arg3);
        lg(" text="); log_cstrW(g_hit_arg2); lg("\n");
    }
    if (!g_mods_dumped) { g_mods_dumped = 1; dump_modules(); }
    // dump live code at the direct caller of the hooked function
    dump_code("hook caller", g_hit_ret);
    // EBP chain + code dumps
    DWORD ebp = g_hit_ebp;
    for (int k = 0; k < 32; k++) {
        DWORD prev, ret;
        if (sl && (ebp < sl || ebp >= sb)) break;
        if (!rd32(ebp, &prev) || !rd32(ebp + 4, &ret)) break;
        lg("     frame[%02d] ebp=%08x ret=%08x\n", k, ebp, ret);
        if (ret >= 0x401000 && ret < 0xFF17000) dump_code("frame", ret);
        if (prev <= ebp || (sb && prev >= sb)) break;
        ebp = prev;
    }
    // raw stack scan: values pointing into client.exe image (fixed base 0x400000)
    int found = 0;
    for (DWORD p = g_hit_esp & ~3; p + 4 <= sb && found < 48; p += 4) {
        DWORD v;
        if (!rd32(p, &v)) break;
        if (v >= 0x401000 && v < 0xFF17000) {
            lg("     stk[%08x] = %08x\n", p, v);
            dump_code("stk", v);
            found++;
        }
    }
    if (g_lf) fflush(g_lf);
}

void* unhook_and_target(void) {
    HOOKT* h = &g_hk[g_hit_id];
    void* t = h->addr;
    if (t && InterlockedCompareExchange(&h->installed, 2, 1) == 1) {
        DWORD old;
        if (VirtualProtect(t, 5, PAGE_EXECUTE_READWRITE, &old)) {
            memcpy(t, h->orig, 5);
            VirtualProtect(t, 5, old, &old);
        }
    }
    return t;
}

// full-image dump of the decrypted code regions, once, at first hook hit.
// Format: [DWORD base][DWORD size][bytes] per region.
static int g_img_dumped;
void full_image_dump(void) {
    if (g_img_dumped) return;
    g_img_dumped = 1;
    static const struct { DWORD base, size; } regions[2] = {
        { 0x401000, 0x75D000 - 0x401000 },     // sections 1-3 (CRT + low game code)
        { 0xFA50000, 0xFF17000 - 0xFA50000 },  // section 7 (WL, real game code)
    };
    HANDLE f = CreateFileA("memdump_at_abort.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE) { lg("memdump: create fail\n"); return; }
    static BYTE buf[0x10000];
    for (int r = 0; r < 2; r++) {
        DWORD base = regions[r].base, size = regions[r].size;
        DWORD wr;
        WriteFile(f, &base, 4, &wr, 0);
        WriteFile(f, &size, 4, &wr, 0);
        for (DWORD p = base; p < base + size; p += sizeof(buf)) {
            DWORD chunk = sizeof(buf);
            if (p + chunk > base + size) chunk = base + size - p;
            if (mem_ok((void*)p, chunk)) memcpy(buf, (void*)p, chunk);
            else memset(buf, 0, chunk);
            DWORD w2 = 0;
            WriteFile(f, buf, chunk, &w2, 0);
            if (w2 != chunk) { lg("memdump: write fail\n"); CloseHandle(f); return; }
        }
    }
    CloseHandle(f);
    lg("memdump: memdump_at_abort.bin written\n");
}

void install_hooks(void) {
    for (int i = 0; i < H_COUNT; i++) {
        HOOKT* h = &g_hk[i];
        if (h->installed) continue;
        HMODULE m = GetModuleHandleA(h->mod);
        if (!m) continue;
        void* p = (void*)GetProcAddress(m, h->fn);
        if (!p) { lg("hook: %s!%s not found\n", h->mod, h->fn); h->installed = 3; continue; }
        DWORD old;
        if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &old)) { lg("hook: VP fail %s!%s\n", h->mod, h->fn); continue; }
        memcpy(h->orig, p, 5);
        h->addr = p;
        BYTE jb[5];
        DWORD rel = (DWORD)h->handler - ((DWORD)p + 5);
        jb[0] = 0xE9; memcpy(jb + 1, &rel, 4);
        memcpy(p, jb, 5);
        VirtualProtect(p, 5, old, &old);
        h->installed = 1;
        lg("hook: %s!%s @%08x patched (orig %02x %02x %02x %02x %02x)\n",
           h->mod, h->fn, (DWORD)p, h->orig[0], h->orig[1], h->orig[2], h->orig[3], h->orig[4]);
    }
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        g_hinst = h;
        char cmd[512];
        strncpy(cmd, GetCommandLineA(), sizeof(cmd) - 1); cmd[sizeof(cmd) - 1] = 0;
        lg("local: === attach === cmdline: %s\n", cmd);
        // CPUID probe: verify what the game's own CPUID check would see
        {
            unsigned ea, eb, ec, ed;
            char vendor[13];
            __get_cpuid(0, &ea, &eb, &ec, &ed);
            memcpy(vendor, &eb, 4); memcpy(vendor + 4, &ed, 4); memcpy(vendor + 8, &ec, 4);
            vendor[12] = 0;
            lg("local: CPUID.0 maxleaf=%08x vendor=%s (%08x %08x %08x)\n", ea, vendor, eb, ed, ec);
            if (__get_cpuid(1, &ea, &eb, &ec, &ed))
                lg("local: CPUID.1 eax=%08x edx=%08x (bit10 SEP=%d)\n", ea, ed, (ed >> 10) & 1);
            if (__get_cpuid(3, &ea, &eb, &ec, &ed))
                lg("local: CPUID.3 ecx=%08x edx=%08x\n", ec, ed);
        }
        AddVectoredExceptionHandler(1, veh);
        lg("local: vectored exception handler installed\n");
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
        install_hooks();
        install_gai_hook_dllmain();
    }
    return TRUE;
}
