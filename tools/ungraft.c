// ungraft.c — graft DLL: on inject, recreate the donor's private heap regions
// at their original VAs and fill them with the dumped content, so the shell's
// runtime finds its stub-built tables. Skips VAs already committed in the
// target (its own stacks/heap/PEB etc.).
// Reads oepdump_out\index.txt + region files, relative to process CWD.
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

static FILE* g_lf;
static void lg(const char* fmt, ...) {
    if (!g_lf) { g_lf = fopen("ungraft.log", "a"); if (g_lf) setvbuf(g_lf, 0, _IONBF, 0); }
    if (!g_lf) return;
    va_list ap; va_start(ap, fmt); vfprintf(g_lf, fmt, ap); va_end(ap);
}

static void graft_all(void) {
    FILE* idx = fopen("oepdump_out\\index.txt", "r");
    if (!idx) { lg("ungraft: no index.txt\n"); return; }
    char line[128];
    int ok = 0, skip = 0, fail = 0;
    while (fgets(line, sizeof(line), idx)) {
        DWORD base, size, prot;
        if (sscanf(line, "%x %x prot=%x", &base, &size, &prot) != 3) continue;
        char fn[96]; sprintf(fn, "oepdump_out\\region_%08x.bin", base);
        FILE* f = fopen(fn, "rb");
        if (!f) { fail++; continue; }
        void* p = VirtualAlloc((void*)base, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (p != (void*)base) {
            if (p) VirtualFree(p, 0, MEM_RELEASE);
            // already committed in the target. The rebuilt's OWN runtime allocated
            // these VAs itself - but with ITS OWN (differently-built) content.
            // For high regions (shell tables live > 0x10000000), force-overwrite
            // with the donor's stub-built content. Skip low regions (stacks/heap).
            if (base >= 0x10000000) {
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery((void*)base, &mbi, sizeof(mbi)) &&
                    mbi.State == MEM_COMMIT && mbi.RegionSize >= size) {
                    DWORD old;
                    if (VirtualProtect((void*)base, size, PAGE_EXECUTE_READWRITE, &old)) {
                        DWORD off = 0;
                        while (off < size) {
                            DWORD chunk = size - off; if (chunk > 0x100000) chunk = 0x100000;
                            fread((BYTE*)base + off, 1, chunk, f);
                            off += chunk;
                        }
                        lg("ungraft: OVERWROTE %08x (%lu bytes) with donor content\n", base, size);
                        ok++;
                    } else skip++;
                } else skip++;
            } else skip++;
            fclose(f);
            continue;
        }
        DWORD off = 0;
        while (off < size) {
            DWORD chunk = size - off; if (chunk > 0x100000) chunk = 0x100000;
            fread((BYTE*)base + off, 1, chunk, f);
            off += chunk;
        }
        fclose(f);
        ok++;
    }
    fclose(idx);
    lg("ungraft: grafted %d regions, skipped %d (already committed), failed %d\n", ok, skip, fail);
}

static DWORD WINAPI worker(LPVOID) {
    graft_all();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        lg("ungraft: === attach ===\n");
        // graft synchronously on this thread: we are on the injector's remote
        // thread, the game's main thread is still early in its own startup.
        graft_all();
    }
    return TRUE;
}
