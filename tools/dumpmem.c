// dumpmem.c — consistent full-state snapshot of a 32-bit process (no debugger):
// suspend all threads, then dump:
//   dumpmem_out\image.bin          flat bytes of VA 0x400000..0xFF17000 (0 fill if uncommitted)
//   dumpmem_out\region_<base>.bin  every committed MEM_PRIVATE region OUTSIDE the image
//   dumpmem_out\index.txt          base size prot per region
// usage: dumpmem <pid>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

#define IMG_LO 0x400000
#define IMG_HI 0xFF17000

static HANDLE g_hp;

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: dumpmem <pid>\n"); return 1; }
    DWORD pid = strtoul(argv[1], 0, 10);
    g_hp = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, 0, pid);
    if (!g_hp) { printf("OpenProcess fail %lu\n", GetLastError()); return 1; }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te; te.dwSize = sizeof(te);
    int nt = 0;
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid) continue;
        HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID);
        if (ht) { SuspendThread(ht); CloseHandle(ht); nt++; }
    }
    CloseHandle(snap);
    printf("suspended %d threads\n", nt);

    CreateDirectoryA("dumpmem_out", NULL);

    // flat image dump
    FILE* fi = fopen("dumpmem_out\\image.bin", "wb");
    if (fi) {
        static BYTE buf[0x100000];
        for (DWORD a = IMG_LO; a < IMG_HI; a += sizeof(buf)) {
            DWORD chunk = IMG_HI - a; if (chunk > sizeof(buf)) chunk = sizeof(buf);
            SIZE_T got = 0;
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(g_hp, (void*)a, &mbi, sizeof(mbi)) &&
                mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
                ReadProcessMemory(g_hp, (void*)a, buf, chunk, &got);
            else got = 0;
            fwrite(buf, 1, got, fi);
            for (DWORD k = got; k < chunk; k++) fputc(0, fi);
        }
        fclose(fi);
        printf("image.bin written (%d bytes)\n", IMG_HI - IMG_LO);
    }

    // private regions outside the image
    FILE* idx = fopen("dumpmem_out\\index.txt", "w");
    DWORD addr = 0x10000;
    int n = 0;
    while (addr < 0x7FFE0000) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(g_hp, (void*)addr, &mbi, sizeof(mbi))) break;
        DWORD base = (DWORD)mbi.BaseAddress, size = (DWORD)mbi.RegionSize;
        DWORD end = base + size;
        int in_img = (base >= IMG_LO && end <= IMG_HI);
        int keep = (mbi.State == MEM_COMMIT) && (mbi.Type == MEM_PRIVATE) &&
                   !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) && !in_img;
        if (keep && size <= 0x8000000) {
            char fn[80]; sprintf(fn, "dumpmem_out\\region_%08x.bin", base);
            FILE* f = fopen(fn, "wb");
            if (f) {
                DWORD off = 0;
                static BYTE buf[0x100000];
                while (off < size) {
                    DWORD chunk = size - off; if (chunk > sizeof(buf)) chunk = sizeof(buf);
                    SIZE_T got = 0;
                    ReadProcessMemory(g_hp, (void*)(base + off), buf, chunk, &got);
                    fwrite(buf, 1, got, f);
                    if (got < chunk) { BYTE z = 0; for (DWORD k = got; k < chunk; k++) fwrite(&z, 1, 1, f); }
                    off += chunk;
                }
                fclose(f);
                if (idx) fprintf(idx, "%08x %08x prot=%08x\n", base, size, mbi.Protect);
                n++;
            }
        }
        addr = end;
    }
    if (idx) fclose(idx);
    printf("dumped %d private regions\n", n);
    TerminateProcess(g_hp, 0);
    return 0;
}
