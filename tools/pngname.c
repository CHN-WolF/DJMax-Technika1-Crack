// pngname.c — match memory-carved PNGs (valid, game-fixed) to tpk-extracted
// PNG entries (real names) via a shared IDAT-content signature; write properly
// named valid PNGs to the output dir.
// usage: pngname <carvedir> <extracted_root> <outdir>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// get signature: 16 bytes from 8 bytes after the LAST "IDAT" tag occurrence's
// first 64KB... actually use first IDAT payload bytes after the BIGGEST idat
static int getsig(const char* path, unsigned char* sig, int n) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* b = malloc(sz);
    fread(b, 1, sz, f); fclose(f);
    // find longest-IDAT: scan for "IDAT", take payload of the one with biggest len
    long bestoff = -1; long bestlen = -1;
    for (long i = 4; i + 8 < sz; i++) {
        if (!memcmp(b + i, "IDAT", 4)) {
            long clen = ((long)b[i-4] << 24) | (b[i-3] << 16) | (b[i-2] << 8) | b[i-1];
            if (clen > bestlen && i + 4 + clen <= sz) { bestlen = clen; bestoff = i + 4; }
        }
    }
    if (bestoff < 0 || bestoff + n > sz) { free(b); return 0; }
    memcpy(sig, b + bestoff, n);
    free(b);
    return 1;
}

int main(int argc, char** argv) {
    if (argc < 4) { printf("usage: pngname <carvedir> <extracted_root> <outdir>\n"); return 1; }
    CreateDirectoryA(argv[3], NULL);

    // index extracted pngs: (sig -> name)
    WIN32_FIND_DATAA fd;
    static struct { unsigned char sig[16]; char path[MAX_PATH]; } EX[4096];
    int nex = 0;
    // walk subdirs manually
    char pat[MAX_PATH], pat1[MAX_PATH];
    _snprintf(pat1, MAX_PATH, "%s\\*", argv[2]);
    HANDLE h1 = FindFirstFileA(pat1, &fd);
    nex = 0;
    while (h1 != INVALID_HANDLE_VALUE) {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) goto next1;
        if (fd.cFileName[0] == '.') goto next1;
        char subpat[MAX_PATH];
        _snprintf(subpat, MAX_PATH, "%s\\%s\\*.png", argv[2], fd.cFileName);
        WIN32_FIND_DATAA fd2;
        HANDLE h2 = FindFirstFileA(subpat, &fd2);
        while (h2 != INVALID_HANDLE_VALUE) {
            if (nex < 4096) {
                char fp[MAX_PATH];
                _snprintf(fp, MAX_PATH, "%s\\%s\\%s", argv[2], fd.cFileName, fd2.cFileName);
                if (getsig(fp, EX[nex].sig, 16)) {
                    _snprintf(EX[nex].path, MAX_PATH, "%s\\%s", fd.cFileName, fd2.cFileName);
                    nex++;
                }
            }
            if (!FindNextFileA(h2, &fd2)) { FindClose(h2); break; }
        }
        next1:;
        if (!FindNextFileA(h1, &fd)) { FindClose(h1); break; }
    }
    printf("indexed %d extracted pngs\n", nex);

    // for each carved png: match
    HANDLE h;
    _snprintf(pat, MAX_PATH, "%s\\*.png", argv[1]);
    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return 1;
    int matched = 0, total = 0;
    do {
        total++;
        char fp[MAX_PATH];
        _snprintf(fp, MAX_PATH, "%s\\%s", argv[1], fd.cFileName);
        unsigned char sig[16];
        if (!getsig(fp, sig, 16)) continue;
        int hit = -1;
        for (int i = 0; i < nex; i++)
            if (!memcmp(EX[i].sig, sig, 16)) { hit = i; break; }
        char op[MAX_PATH];
        if (hit >= 0) {
            _snprintf(op, MAX_PATH, "%s\\%s", argv[3], EX[hit].path);
        } else {
            _snprintf(op, MAX_PATH, "%s\\_unmatched\\%s", argv[3], fd.cFileName);
        }
        // ensure subdir
        char* sl = strrchr(op, '\\');
        if (sl) { char t[MAX_PATH]; memcpy(t, op, sl - op); t[sl - op] = 0;
                  char* sl2 = strrchr(t, '\\'); if (sl2) { char t2[MAX_PATH]; memcpy(t2, t, sl2 - t); t2[sl2 - t] = 0; CreateDirectoryA(t2, NULL);} CreateDirectoryA(t, NULL); }
        CopyFileA(fp, op, FALSE);
        if (hit >= 0) matched++;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    printf("matched %d / %d carved pngs\n", matched, total);
    return 0;
}
