// aestest.c — verify TPK inner cipher = AES-128. Tables computed
// algorithmically; self-check with FIPS-197 known-answer test, then test
// candidate keys: decrypt the zero-pad ciphertext block, expect zeros.
#include <stdio.h>
#include <string.h>

typedef unsigned char u8;

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
        sbox[i] = s;
        isbox[s] = (u8)i;
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

static void aes_enc(const u8 in[16], u8 out[16]) {
    u8 s[16]; memcpy(s, in, 16);
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
    for (int r = 1; r < 10; r++) {
        for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];
        shift_rows(s, 0);
        mix_columns(s, 0);
        for (int i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
    }
    for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];
    shift_rows(s, 0);
    for (int i = 0; i < 16; i++) s[i] ^= rk[160 + i];
    memcpy(out, s, 16);
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

static void p16(const u8* b) { for (int i = 0; i < 16; i++) printf("%02x", b[i]); }

int main(void) {
    init_tables();
    // FIPS-197 known answer: key 2b7e...f3, pt 0011...ee -> ct 69c4e0d8...
    const u8 tk[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    const u8 tp[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const u8 te[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    u8 out[16];
    key_exp(tk); aes_enc(tp, out);
    printf("FIPS enc: "); p16(out); printf(memcmp(out, te, 16) ? "  FAIL\n" : "  OK\n");
    aes_dec(te, out);
    printf("FIPS dec: "); p16(out); printf(memcmp(out, tp, 16) ? "  FAIL\n" : "  OK\n");

    const u8 padblock[16] = { 0x72,0x0d,0xe1,0xe4,0xb8,0x47,0x76,0x4a,
                              0x79,0x7f,0x37,0x1b,0x57,0x9d,0x31,0xdb };
    const char* keys[] = { "tihSnoD!uoTteMhc", "Shit!DontTouchMe", 0 };
    const u8 keyc[16] = { 0xc0,0x07,0x92,0xce,0xce,0x09,0x3d,0xa0,
                          0xf5,0xfe,0x61,0x3c,0x01,0x64,0xa7,0xc2 };
    for (int k = 0; k < 3; k++) {
        const u8* key = k < 2 ? (const u8*)keys[k] : keyc;
        key_exp(key);
        aes_dec(padblock, out);
        printf("key%d dec(padblock)=", k); p16(out);
        int allz = 1; for (int i = 0; i < 16; i++) if (out[i]) allz = 0;
        printf(allz ? "  *** ZEROS => KEY FOUND ***\n" : "\n");
        aes_enc((const u8*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", out);
        printf("     enc(0)="); p16(out); printf("\n");
    }
    return 0;
}
