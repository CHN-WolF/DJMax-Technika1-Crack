// memcarve.c — carve known file types from memory dump files (dumpmem_out).
// Scans region_*.bin / image.bin, extracts PNG / JPG / OGG / WAV / DDS / BMP
// with proper end-boundary detection, dedupes by (size+hash), writes to
// <outdir>/<type>/<n>.<ext>.
// usage: memcarve <dumpdir> <outdir>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char* g_buf;
static long g_len;

static int at(long i, unsigned char v) { return i < g_len && g_buf[i] == v; }

// ---- PNG: chunks len(4BE)+type(4)+data+crc(4) until IEND ----
static long png_end(long s) {
    long p = s + 8;
    while (p + 12 <= g_len) {
        long clen = ((long)g_buf[p] << 24) | (g_buf[p+1] << 16) | (g_buf[p+2] << 8) | g_buf[p+3];
        if (clen < 0 || p + 12 + clen > g_len) return -1;
        if (!memcmp(g_buf + p + 4, "IEND", 4)) return p + 12 + 0;  // IEND len=0
        p += 12 + clen;
        if (p - s > 64 * 1024 * 1024) return -1;
    }
    return -1;
}

// ---- JPG: FFD8 .. FFD9 ----
static long jpg_end(long s) {
    for (long p = s + 4; p + 1 < g_len && p - s < 32 * 1024 * 1024; p++)
        if (g_buf[p] == 0xFF && g_buf[p + 1] == 0xD9) return p + 2;
    return -1;
}

// ---- OGG: pages until EOS (header_type & 4) of same serial ----
static long ogg_end(long s) {
    long p = s;
    DWORD serial = 0;
    for (int pages = 0; pages < 100000; pages++) {
        if (p + 27 > g_len || memcmp(g_buf + p, "OggS", 4)) return -1;
        unsigned char htype = g_buf[p + 5];
        DWORD ser = *(DWORD*)(g_buf + p + 14);
        int nseg = g_buf[p + 26];
        if (p + 27 + nseg > g_len) return -1;
        long body = 0;
        for (int i = 0; i < nseg; i++) body += g_buf[p + 27 + i];
        long next = p + 27 + nseg + body;
        if (next > g_len) return -1;
        if (pages == 0) serial = ser;
        if (ser == serial && (htype & 4)) return next;
        p = next;
    }
    return -1;
}

// ---- RIFF/WAVE: size at +4 ----
static long wav_end(long s) {
    if (s + 12 > g_len) return -1;
    long rsz = *(DWORD*)(g_buf + s + 4);
    if (rsz < 36 || s + 8 + rsz > g_len) return -1;
    return s + 8 + rsz;
}

// ---- BMP: 'BM' + size at +2, strict header validation (DIB sanity) ----
static long bmp_end(long s) {
    if (s + 54 > g_len) return -1;
    long bsz = *(DWORD*)(g_buf + s + 2);
    DWORD reserved = *(DWORD*)(g_buf + s + 6);
    DWORD pixoff = *(DWORD*)(g_buf + s + 10);
    DWORD dibsz = *(DWORD*)(g_buf + s + 14);
    DWORD planes = *(WORD*)(g_buf + s + 26);
    long w = *(long*)(g_buf + s + 18), h = *(long*)(g_buf + s + 22);
    if (reserved != 0) return -1;
    if (dibsz != 40 && dibsz != 52 && dibsz != 56 && dibsz != 108 && dibsz != 124) return -1;
    if (planes != 1) return -1;
    if (w <= 0 || w > 8192 || h == 0 || h > 8192 || h < -8192) return -1;
    if (pixoff < 54 || pixoff >= (DWORD)bsz) return -1;
    if (bsz < 100 || s + bsz > g_len) return -1;
    return s + bsz;
}

// ---- DDS: header 124B after magic; compute size from header ----
static long dds_end(long s) {
    if (s + 128 > g_len) return -1;
    DWORD hsz = *(DWORD*)(g_buf + s + 4);
    if (hsz != 124) return -1;
    DWORD h = *(DWORD*)(g_buf + s + 12), w = *(DWORD*)(g_buf + s + 16);
    DWORD pitch = *(DWORD*)(g_buf + s + 20);
    DWORD mip = *(DWORD*)(g_buf + s + 28) & 0x7fffffff;
    DWORD pf_flags = *(DWORD*)(g_buf + s + 80);
    DWORD fourcc = *(DWORD*)(g_buf + s + 84);
    if (!h || !w || h > 8192 || w > 8192) return -1;
    long base;
    if (pf_flags & 4) {  // FOURCC compressed
        (void)fourcc;
        base = ((w + 3) / 4) * ((h + 3) / 4) * 8;   // DXT1-ish min
        DWORD fc = fourcc;
        if (fc == 0x35545844 || fc == 0x33545844) base = ((w + 3) / 4) * ((h + 3) / 4) * 8;
        else base = ((w + 3) / 4) * ((h + 3) / 4) * 16;  // DXT3/5
    } else if (pitch) {
        base = (long)pitch * h;
    } else return -1;
    long total = 128 + base;
    if (mip > 1 && mip < 20) total = 128 + base * 4 / 3;  // approx mip chain
    if (s + total > g_len) total = g_len - s;
    return total > 128 ? s + total : -1;
}

static FILE* g_log;
static long g_seen[4096][2];  // (size, hash) dedupe table
static int g_nseen;

static unsigned int shash(const unsigned char* b, long n) {
    unsigned int h = 5381;
    for (long i = 0; i < n; i += 997) h = h * 33 ^ b[i];
    if (n > 8) h = h * 33 ^ *(unsigned int*)(b + n - 4);
    return h;
}

static void carve_one(const char* outdir, const char* type, const char* ext,
                      const char* srcname, long off, long len) {
    unsigned int h = shash(g_buf + off, len);
    for (int i = 0; i < g_nseen; i++)
        if (g_seen[i][0] == len && (unsigned)g_seen[i][1] == h) return;
    if (g_nseen < 4096) { g_seen[g_nseen][0] = len; g_seen[g_nseen][1] = h; g_nseen++; }
    static int seq[16];
    int tidx = 0;
    const char* types[] = { "png","jpg","ogg","wav","bmp","dds" };
    for (int i = 0; i < 6; i++) if (!strcmp(type, types[i])) { tidx = i; break; }
    char dir[MAX_PATH], path[MAX_PATH];
    _snprintf(dir, MAX_PATH, "%s\\%s", outdir, type);
    CreateDirectoryA(dir, NULL);
    _snprintf(path, MAX_PATH, "%s\\%04d.%s", dir, seq[tidx]++, ext);
    FILE* f = fopen(path, "wb");
    if (!f) return;
    fwrite(g_buf + off, 1, len, f); fclose(f);
    fprintf(g_log, "%s  %10ld  %s+%ld\n", path, len, srcname, off);
    printf("%s (%ld bytes)\n", path, len);
}

static void scan(const char* path, const char* outdir) {
    FILE* f = fopen(path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END); g_len = ftell(f); fseek(f, 0, SEEK_SET);
    g_buf = malloc(g_len);
    if (fread(g_buf, 1, g_len, f) != g_len) { fclose(f); free(g_buf); return; }
    fclose(f);
    const char* base = strrchr(path, '\\'); base = base ? base + 1 : path;
    for (long i = 0; i + 8 < g_len; i++) {
        unsigned char c = g_buf[i];
        long e = -1;
        if (c == 0x89 && at(i+1,'P') && at(i+2,'N') && at(i+3,'G') && at(i+4,0x0D) && at(i+5,0x0A)) {
            e = png_end(i);
            if (e > 0) { carve_one(outdir, "png", "png", base, i, e - i); i = e - 1; }
        } else if (c == 0xFF && at(i+1,0xD8) && at(i+2,0xFF)) {
            e = jpg_end(i);
            if (e > 0) { carve_one(outdir, "jpg", "jpg", base, i, e - i); i = e - 1; }
        } else if (c == 'O' && at(i+1,'g') && at(i+2,'g') && at(i+3,'S')) {
            e = ogg_end(i);
            if (e > 0) { carve_one(outdir, "ogg", "ogg", base, i, e - i); i = e - 1; }
        } else if (c == 'R' && at(i+1,'I') && at(i+2,'F') && at(i+3,'F') && at(i+8,'W') && at(i+9,'A') && at(i+10,'V') && at(i+11,'E')) {
            e = wav_end(i);
            if (e > 0) { carve_one(outdir, "wav", "wav", base, i, e - i); i = e - 1; }
        } else if (c == 'B' && at(i+1,'M')) {
            e = bmp_end(i);
            if (e > 0) { carve_one(outdir, "bmp", "bmp", base, i, e - i); i = e - 1; }
        } else if (c == 'D' && at(i+1,'D') && at(i+2,'S') && at(i+3,' ')) {
            e = dds_end(i);
            if (e > 0) { carve_one(outdir, "dds", "dds", base, i, e - i); i = e - 1; }
        }
    }
    free(g_buf);
}

int main(int argc, char** argv) {
    if (argc < 3) { printf("usage: memcarve <dumpdir> <outdir>\n"); return 1; }
    CreateDirectoryA(argv[2], NULL);
    char logp[MAX_PATH];
    _snprintf(logp, MAX_PATH, "%s\\carve_log.txt", argv[2]);
    g_log = fopen(logp, "w");

    char pat[MAX_PATH];
    _snprintf(pat, MAX_PATH, "%s\\*.bin", argv[1]);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) { printf("no bin files in %s\n", argv[1]); return 1; }
    int nf = 0;
    do {
        char fp[MAX_PATH];
        _snprintf(fp, MAX_PATH, "%s\\%s", argv[1], fd.cFileName);
        scan(fp, argv[2]);
        nf++;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    printf("scanned %d files\n", nf);
    fclose(g_log);
    return 0;
}
