// tpkx.c — DJMax Technika 1 .tpk extractor (full offline unpacker)
//
// TPK format (fully reversed 2026-10-07):
//   +0x00  u32 magic 0x0014CEDE, u16 ver, u16 entry count, u32 size
//   +0x0C  body: AES-128-ECB, 16-byte blocks on the offset-12 grid,
//          key = ASCII "Shit!DontTouchMe"
//   decrypted body = entries back to back (stride = 144 + blobSize):
//          name[128] (zero-padded ascii) + u32 hash + u32 blobSize + u32 field2 +
//          u32 reserved + blob[blobSize]
//   blob = ver 0100: raw file bytes;  ver 0101: LZO1X stream (CLZOWrapper/Zipper)
// Key dumped at runtime via PAGE_GUARD on the ciphertext buffer (tpkdump.dll).
// usage: tpkx <file.tpk> [outdir]   (no outdir = list only)
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned int u32;

// ---------- AES-128 (runtime-generated tables) ----------
static u8 sbox[256], isbox[256];
static u8 gmul(u8 a, u8 b) {
    u8 r = 0;
    for (; b; b >>= 1) { if (b & 1) r ^= a; a = (a << 1) ^ ((a & 0x80) ? 0x1b : 0); }
    return r;
}
static u8 ginv(u8 a) {
    if (!a) return 0;
    u8 r = 1;
    for (int i = 0; i < 254; i++) r = gmul(r, a);
    return r;
}
static void init_tables(void) {
    for (int i = 0; i < 256; i++) {
        u8 x = ginv((u8)i);
        u8 s = x ^ ((x << 1) | (x >> 7)) ^ ((x << 2) | (x >> 6)) ^ ((x << 3) | (x >> 5)) ^ ((x << 4) | (x >> 4)) ^ 0x63;
        sbox[i] = s; isbox[s] = (u8)i;
    }
}
static u8 rk[176];
static void key_exp(const u8* key) {
    static const u8 rcon[10] = { 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };
    memcpy(rk, key, 16);
    for (int i = 16; i < 176; i += 4) {
        u8 t[4] = { rk[i-4], rk[i-3], rk[i-2], rk[i-1] };
        if ((i & 15) == 0) {
            u8 x = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = x;
            for (int j = 0; j < 4; j++) t[j] = sbox[t[j]];
            t[0] ^= rcon[(i >> 4) - 1];
        }
        for (int j = 0; j < 4; j++) rk[i + j] = rk[i - 16 + j] ^ t[j];
    }
}
static void shift_rows(u8* s, int inv) {
    for (int row = 1; row < 4; row++) {
        u8 t[4];
        for (int c = 0; c < 4; c++) t[c] = inv ? s[((c - row) & 3) * 4 + row] : s[((c + row) & 3) * 4 + row];
        for (int c = 0; c < 4; c++) s[c * 4 + row] = t[c];
    }
}
static void mix_columns(u8* s, int inv) {
    for (int c = 0; c < 4; c++) {
        u8* p = s + c * 4;
        u8 a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        if (!inv) {
            p[0] = gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3;
            p[1] = a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3;
            p[2] = a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3);
            p[3] = gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2);
        } else {
            p[0] = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9);
            p[1] = gmul(a0,9) ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13);
            p[2] = gmul(a0,13) ^ gmul(a1,9) ^ gmul(a2,14) ^ gmul(a3,11);
            p[3] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9) ^ gmul(a3,14);
        }
    }
}
static void aes_dec(const u8 in[16], u8 out[16]) {
    u8 s[16]; memcpy(s, in, 16);
    for (int i = 0; i < 16; i++) s[i] ^= rk[160 + i];
    for (int r = 9; r >= 1; r--) {
        shift_rows(s, 1);
        for (int i = 0; i < 16; i++) s[i] = isbox[s[i]];
        for (int i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
        mix_columns(s, 1);
    }
    shift_rows(s, 1);
    for (int i = 0; i < 16; i++) s[i] = isbox[s[i]];
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
    memcpy(out, s, 16);
}

static const u8 TPK_KEY[16] = { 'S','h','i','t','!','D','o','n','t','T','o','u','c','h','M','e' };

// ---- LZO1X decompressor (ported from Linux lib/lzo/lzo1x_decompress_safe.c,
//      matching the game's CLZOWrapper@Zipper) ----
static long lzo_dec(const u8* in, long in_len, u8* out, long outcap) {
    const u8* ip = in;
    const u8* const ip_end = in + in_len;
    u8* op = out;
    u8* const op_end = out + outcap;
    long t, state = 0, next;
    const u8* m_pos;

#define TPX_NEED_IP(x) if (ip_end - ip < (x)) return -1
#define TPX_NEED_OP(x) if (op_end - op < (x)) return -2
#define TPX_TEST_LB(mp) if ((mp) < out) return -3

    if (in_len < 3) return -1;
    if (in_len >= 5 && *ip == 17) ip += 2;
    if (*ip > 17) {
        t = *ip++ - 17;
        if (t < 4) { next = t; goto match_next; }
        goto copy_literal_run;
    }
    for (;;) {
        t = *ip++;
        if (t < 16) {
            if (state == 0) {
                if (t == 0) {
                    long offset = 0;
                    while (*ip == 0) { ip++; TPX_NEED_IP(1); offset += 255; }
                    t += offset + 15 + *ip++;
                }
                t += 3;
copy_literal_run:
                TPX_NEED_OP(t); TPX_NEED_IP(t + 3);
                do { *op++ = *ip++; } while (--t > 0);
                state = 4;
                continue;
            } else if (state != 4) {
                next = t & 3;
                m_pos = op - 1;
                m_pos -= t >> 2;
                m_pos -= *ip++ << 2;
                TPX_TEST_LB(m_pos);
                TPX_NEED_OP(2);
                op[0] = m_pos[0]; op[1] = m_pos[1];
                op += 2;
                goto match_next;
            } else {
                next = t & 3;
                m_pos = op - (1 + 0x0800);
                m_pos -= t >> 2;
                m_pos -= *ip++ << 2;
                t = 3;
            }
        } else if (t >= 64) {
            next = t & 3;
            m_pos = op - 1;
            m_pos -= (t >> 2) & 7;
            m_pos -= *ip++ << 3;
            t = (t >> 5) + 1;
        } else if (t >= 32) {
            t = (t & 31) + 2;
            if (t == 2) {
                long offset = 0;
                while (*ip == 0) { ip++; TPX_NEED_IP(1); offset += 255; }
                t += offset + 31 + *ip++;
                TPX_NEED_IP(2);
            }
            m_pos = op - 1;
            next = ip[0] | (ip[1] << 8);
            ip += 2;
            m_pos -= next >> 2;
            next &= 3;
        } else {
            TPX_NEED_IP(2);
            next = ip[0] | (ip[1] << 8);
            m_pos = op;
            m_pos -= (t & 8) << 11;
            t = (t & 7) + 2;
            if (t == 2) {
                long offset = 0;
                while (*ip == 0) { ip++; TPX_NEED_IP(1); offset += 255; }
                t += offset + 7 + *ip++;
                TPX_NEED_IP(2);
                next = ip[0] | (ip[1] << 8);
            }
            ip += 2;
            m_pos -= next >> 2;
            next &= 3;
            if (m_pos == op) {
                if (t != 3) return -4;
                return op - out;
            }
            m_pos -= 0x4000;
        }
        TPX_TEST_LB(m_pos);
        {
            u8* oe = op + t;
            TPX_NEED_OP(t);
            do { *op++ = *m_pos++; } while (op < oe);
        }
match_next:
        state = next;
        t = next;
        TPX_NEED_IP(t + 3); TPX_NEED_OP(t);
        while (t-- > 0) *op++ = *ip++;
    }
}

static int name_ok(const u8* p) {
    // allow GBK high bytes (>=0x80) in names; reject control/garbage
    if (p[0] < 32) return 0;
    int n = 0;
    for (int i = 0; i < 128; i++) {
        if (!p[i]) break;
        if (p[i] < 32) return 0;
        if (p[i] == 0x7f) return 0;
        n++;
    }
    return n >= 4 && n < 120;
}

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: tpkx <file.tpk> [outdir]\n"); return 1; }
    FILE* f = fopen(argv[1], "rb");
    if (!f) { printf("open fail\n"); return 1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    u8* buf = malloc(sz);
    fread(buf, 1, sz, f); fclose(f);
    if (*(DWORD*)buf != 0x0014cede) { printf("bad magic\n"); return 1; }
    int cnt = *(u8*)(buf + 6) | (*(u8*)(buf + 7) << 8);
    printf("count=%d filesize=%ld\n", cnt, sz);

    init_tables();
    key_exp(TPK_KEY);
    for (long i = 12; i + 16 <= sz; i += 16)
        aes_dec(buf + i, buf + i);
    u8* d = buf + 12;
    long len = sz - 12;

    if (argc >= 3) {
        CreateDirectoryA(argv[2], NULL);
        // CreateDirectoryA 不建父目录:补一层
        char parent[MAX_PATH];
        _snprintf(parent, MAX_PATH, "%s", argv[2]);
        char* sl = strrchr(parent, '\\');
        if (sl) { *sl = 0; CreateDirectoryA(parent, NULL); CreateDirectoryA(argv[2], NULL); }
    }
    if (argc < 3) {
        // list mode also drops the raw decrypted body for inspection
        char dp[MAX_PATH];
        _snprintf(dp, MAX_PATH, "%s.dec", argv[1]);
        FILE* df = fopen(dp, "wb");
        if (df) { fwrite(d, 1, len, df); fclose(df); printf("wrote %s\n", dp); }
    }

    long pos = 0;
    int n = 0, anomalies = 0;
    while (pos + 146 < len) {
        if (!name_ok(d + pos)) {
            // resync: scan forward for the next plausible entry name
            long q = pos + 1;
            for (; q + 146 < len; q++)
                if (name_ok(d + q) && !memcmp(d + q, "resource", 8)) break;
            if (q + 146 >= len) break;
            printf("  [resync %ld -> %ld (%ld bytes skipped)]\n", pos, q, q - pos);
            anomalies++;
            pos = q;
        }
        char name[128];
        memcpy(name, d + pos, 127); name[127] = 0;
        u32 hash = *(u32*)(d + pos + 128);
        u32 f1 = *(u32*)(d + pos + 132);
        long bpos = pos + 144;            // blob = [bpos, bpos+f1)
        long blen = f1;
        long next = pos + 144 + f1;       // entry stride
        if ((long)f1 < 0 || next > len) {
            // size unreliable: bound by next name
            long q = bpos;
            for (; q + 146 < len; q++)
                if (name_ok(d + q) && !memcmp(d + q, "resource", 8)) break;
            next = q;
            blen = next - bpos;
            anomalies++;
        }
        // blob: ver 0101 = LZO1X stream; ver 0100 = raw file bytes.
        // Try LZO first; fall back to raw when it errors or fails sanity.
        u8* dec = NULL;
        long dn = 0;
        {
            long cap = blen * 8 + 65536;
            dec = malloc(cap);
            dn = lzo_dec(d + bpos, blen, dec, cap);
            if (dn <= 0) { free(dec); dec = NULL; }
        }
        int islzo = dec != NULL;
        const u8* out = islzo ? dec : d + bpos;
        long olen = islzo ? dn : blen;
        printf("%4d %-40s hash=%08x %s size=%ld\n", n, name, hash,
               islzo ? "LZO" : "raw", olen);
        if (argc >= 3) {
            char op[MAX_PATH];
            const char* bn = strrchr(name, '/'); bn = bn ? bn + 1 : name;
            _snprintf(op, MAX_PATH, "%s\\%s", argv[2], bn);
            FILE* o = fopen(op, "wb");
            if (o) { fwrite(out, 1, olen, o); fclose(o); }
        }
        free(dec);
        n++;
        pos = next;
    }
    printf("extracted %d entries (%d anomalies)\n", n, anomalies);
    return 0;
}
