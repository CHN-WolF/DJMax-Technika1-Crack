// mtptff4.c — full PTFF decrypt:
//   v64 = {sum24, crc32} of header[24]; ks = MT19937 init_by_array(header 6 dwords);
//   block i (8 bytes): plain = cipher ^ fk ^ mtblock;
//   fk_0 = v64;  fk_{j+1} = XTEA_encrypt(fk_j, key = plainblock_j duplicated)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned int u32;

static u32 mt[624];
static int mti;
static void init_genrand(u32 s) {
    mt[0] = s;
    for (mti = 1; mti < 624; mti++)
        mt[mti] = 1812433253UL * (mt[mti-1] ^ (mt[mti-1] >> 30)) + mti;
}
static void init_by_array(const u32* key, int klen) {
    int i, j, k;
    init_genrand(19650218UL);
    i = 1; j = 0;
    k = (624 > klen ? 624 : klen);
    for (; k; k--) {
        mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525UL)) + key[j] + j;
        i++; j++;
        if (i >= 624) { mt[0] = mt[623]; i = 1; }
        if (j >= klen) j = 0;
    }
    for (k = 623; k; k--) {
        mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941UL)) - i;
        i++;
        if (i >= 624) { mt[0] = mt[623]; i = 1; }
    }
    mt[0] = 0x80000000UL;
}
static u32 genrand(void) {
    u32 y;
    static const u32 mag[2] = { 0, 0x9908b0dfUL };
    if (mti >= 624) {
        int kk;
        if (mti == 625) init_genrand(5489UL);
        for (kk = 0; kk < 227; kk++) {
            y = (mt[kk] & 0x80000000UL) | (mt[kk+1] & 0x7fffffffUL);
            mt[kk] = mt[kk+397] ^ (y >> 1) ^ mag[y & 1];
        }
        for (; kk < 623; kk++) {
            y = (mt[kk] & 0x80000000UL) | (mt[kk+1] & 0x7fffffffUL);
            mt[kk] = mt[kk+(397-624)] ^ (y >> 1) ^ mag[y & 1];
        }
        y = (mt[623] & 0x80000000UL) | (mt[0] & 0x7fffffffUL);
        mt[623] = mt[396] ^ (y >> 1) ^ mag[y & 1];
        mti = 0;
    }
    y = mt[mti++];
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);
    return y;
}

static void xtea_enc(u32 v[2], const u32 k[4]) {
    u32 v0 = v[0], v1 = v[1], sum = 0, delta = 0x9e3779b9UL;
    for (int i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    v[0] = v0; v[1] = v1;
}

static u32 crc32b(const u8* p, long n) {
    u32 c = 0xFFFFFFFF;
    for (long i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320 : c >> 1;
    }
    return ~c;
}

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    u8* b = malloc(sz);
    fread(b, 1, sz, f); fclose(f);
    u8* out = malloc(sz);

    u32 sum = 0;
    for (int i = 0; i < 24; i++) sum += b[i];
    u32 crc = crc32b(b, 24);
    u32 fk[2] = { sum, crc };

    init_by_array((const u32*)b, 6);

    long boff = 0x18;
    for (long i = boff; i + 8 <= sz; i += 8) {
        u32 ks[2] = { genrand(), genrand() };
        u32* ct = (u32*)(b + i);
        u32* pt = (u32*)(out + i);
        pt[0] = ct[0] ^ fk[0] ^ ks[0];
        pt[1] = ct[1] ^ fk[1] ^ ks[1];
        // feedback: fk = XTEA_encrypt(fk, key = {pt0, pt1, pt0, pt1})
        u32 k[4] = { pt[0], pt[1], pt[0], pt[1] };
        xtea_enc(fk, k);
    }
    // trailing partial block
    if (sz > boff && (sz - boff) % 8) {
        long i = sz - ((sz - boff) % 8);
        u32 ks[2] = { genrand(), genrand() };
        u8 fk8[8], ks8[8];
        memcpy(fk8, fk, 8); memcpy(ks8, ks, 8);
        for (long j = i; j < sz; j++) out[j] = b[j] ^ fk8[(j - i) & 7] ^ ks8[(j - i) & 7];
    }

    long z = 0, asc = 0;
    for (long i = boff; i < sz; i++) { if (!out[i]) z++; if (out[i] >= 32 && out[i] < 127) asc++; }
    printf("zeros=%ld ascii=%ld (of %ld)\n", z, asc, sz - boff);
    printf("head: ");
    for (int i = 0; i < 48 && boff + i < sz; i++) {
        if (out[boff+i] >= 32 && out[boff+i] < 127) printf("%c", out[boff+i]); else printf("\\x%02x", out[boff+i]);
    }
    printf("\n");
    FILE* o = fopen(argv[2], "wb"); memcpy(out, b, boff);
    fwrite(out, 1, sz, o); fclose(o);
    return 0;
}
