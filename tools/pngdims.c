// pngdims.c — list PNGs in a dir with their IHDR dimensions
// usage: pngdims <dir> [filterwidth]
#include <windows.h>
#include <stdio.h>

int main(int argc, char** argv) {
    char pat[MAX_PATH];
    _snprintf(pat, MAX_PATH, "%s\\*.png", argv[1]);
    int fw = argc > 2 ? atoi(argv[2]) : -1;
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return 1;
    do {
        char fp[MAX_PATH];
        _snprintf(fp, MAX_PATH, "%s\\%s", argv[1], fd.cFileName);
        FILE* f = fopen(fp, "rb");
        if (!f) continue;
        unsigned char b[33];
        int n = fread(b, 1, 33, f);
        fclose(f);
        if (n < 33 || b[0] != 0x89) continue;
        int w = (b[16] << 24) | (b[17] << 16) | (b[18] << 8) | b[19];
        int hh = (b[20] << 24) | (b[21] << 16) | (b[22] << 8) | b[23];
        if (w <= 0 || w > 8192 || hh <= 0 || hh > 8192) {
            printf("%s BAD-IHDR w=%d h=%d size=%ld\n", fd.cFileName, w, hh, (long)fd.nFileSizeLow);
            continue;
        }
        if (fw < 0 || w == fw)
            printf("%s %dx%d size=%ld\n", fd.cFileName, w, hh, (long)fd.nFileSizeLow);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return 0;
}
