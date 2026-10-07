// ptref.c — 1:1 C port of the reference PtCipher (DMTQ-Tools pt_to_text).
// For cross-checking my mtptff implementation against ground truth.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef int i32;

static u32 mt_state[625];
static u8 key1_bytes[8];
static u8 key2_bytes[8];
static u32 key_1_state[2];

static void FillData(const u8* header) {
    mt_state[0] = 0x12BD6AA;
    for (mt_state[624] = 1; mt_state[624] < 624; mt_state[624]++) {
        u32 prev = mt_state[mt_state[624] - 1];
        mt_state[mt_state[624]] = mt_state[624] + 1812433253u * (prev ^ (prev >> 30));
    }
    int v9 = 1, v6 = 0;
    for (int i = 624; i > 0; i--) {
        u32 header_val;
        memcpy(&header_val, header + 4 * v6, 4);
        u32 prev = mt_state[v9 - 1];
        mt_state[v9] = (u32)v6 + header_val + (mt_state[v9] ^ (1664525u * (prev ^ (prev >> 30))));
        v9++; v6++;
        if (v9 >= 624) { mt_state[0] = mt_state[623]; v9 = 1; }
        if (v6 >= 6) v6 = 0;
    }
    for (int j = 623; j > 0; j--) {
        u32 prev = mt_state[v9 - 1];
        mt_state[v9] = (mt_state[v9] ^ (1566083941u * (prev ^ (prev >> 30)))) - (u32)v9;
        v9++;
        if (v9 >= 624) { mt_state[0] = mt_state[623]; v9 = 1; }
    }
    mt_state[0] = 0x80000000u;
}

static u32 CalcParam2(void) {
    static const u32 MA[2] = { 0, 0x9908B0DFu };
    if (mt_state[624] >= 624) {
        int i;
        for (i = 0; i < 227; ++i) {
            u32 v1 = (mt_state[i + 1] & 0x7FFFFFFFu) | (mt_state[i] & 0x80000000u);
            mt_state[i] = MA[v1 & 1] ^ mt_state[i + 397] ^ (v1 >> 1);
        }
        while (i < 623) {
            u32 v2 = (mt_state[i + 1] & 0x7FFFFFFFu) | (mt_state[i] & 0x80000000u);
            mt_state[i] = MA[v2 & 1] ^ mt_state[i - 227] ^ (v2 >> 1);
            ++i;
        }
        u32 v3 = (mt_state[0] & 0x7FFFFFFFu) | (mt_state[623] & 0x80000000u);
        mt_state[623] = MA[v3 & 1] ^ mt_state[396] ^ (v3 >> 1);
        mt_state[624] = 0;
    }
    u32 v4 = mt_state[mt_state[624]++];
    u32 v5 = v4 ^ (v4 >> 11);
    v5 ^= (v5 << 7) & 0x9D2C5680u;
    v5 ^= (v5 << 15) & 0xEFC60000u;
    v5 ^= v5 >> 18;
    return v5;
}

static u32 GetCrc32(const u8* data) {
    static u32 table[256];
    static int init = 0;
    if (!init) {
        for (u32 i = 0; i < 256; i++) {
            u32 t = i;
            for (int j = 0; j < 8; j++) t = (t & 1) ? (t >> 1) ^ 0xEDB88320u : t >> 1;
            table[i] = t;
        }
        init = 1;
    }
    u32 crc = 0xFFFFFFFFu;
    for (int i = 0; i < 24; i++) {
        u8 idx = (u8)((crc & 0xFF) ^ data[i]);
        crc = (crc >> 8) ^ table[idx];
    }
    return ~crc;
}

static u32 GetChecksum(const u8* data) {
    u32 sum = 0;
    for (int i = 0; i < 24; i++) sum += data[i];
    return sum;
}

static void UpdateParam(const u8* pt_block) {
    u32 v8 = key_1_state[0];
    u32 v5 = key_1_state[1];
    u32 v6 = 0;
    u32 pt0, pt1;
    memcpy(&pt0, pt_block, 4);
    memcpy(&pt1, pt_block + 4, 4);
    for (int i = 0; i < 32; i++) {
        v6 = v6 - 1640531527u;
        v8 = v8 + ((pt1 + (v5 >> 5)) ^ (v6 + v5) ^ (pt0 + (v5 << 4)));
        v5 = v5 + ((pt1 + (v8 >> 5)) ^ (v6 + v8) ^ (pt0 + (v8 << 4)));
    }
    key_1_state[0] = v8;
    key_1_state[1] = v5;
    memcpy(key1_bytes, &v8, 4);
    memcpy(key1_bytes + 4, &v5, 4);
}

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    u8* input = malloc(sz);
    fread(input, 1, sz, f); fclose(f);

    u8 header[24];
    memcpy(header, input, 24);
    long dlen = sz - 24;
    u8* data = malloc(dlen);
    memcpy(data, input + 24, dlen);

    u32 decFlag;
    memcpy(&decFlag, data, 4);
    int isEncode = (decFlag <= 10);

    FillData(header);
    u32 k2_0 = CalcParam2();
    u32 k2_1 = CalcParam2();
    memcpy(key2_bytes, &k2_0, 4);
    memcpy(key2_bytes + 4, &k2_1, 4);

    key_1_state[1] = GetCrc32(header);
    key_1_state[0] = GetChecksum(header);
    memcpy(key1_bytes, &key_1_state[0], 4);
    memcpy(key1_bytes + 4, &key_1_state[1], 4);

    u8 pt_block[8];
    int y = 0;
    for (long x = 0; x < dlen; x++) {
        u8 orig = data[x];
        if (isEncode) pt_block[y] = orig;
        data[x] ^= (u8)(key2_bytes[y] ^ key1_bytes[y]);
        if (!isEncode) pt_block[y] = data[x];
        y++;
        if (y == 8) {
            UpdateParam(pt_block);
            k2_0 = CalcParam2();
            k2_1 = CalcParam2();
            memcpy(key2_bytes, &k2_0, 4);
            memcpy(key2_bytes + 4, &k2_1, 4);
            y = 0;
        }
    }

    // write header + data
    FILE* o = fopen(argv[2], "wb");
    fwrite(header, 1, 24, o);
    fwrite(data, 1, dlen, o);
    fclose(o);
    printf("done, isEncode=%d\n", isEncode);
    return 0;
}
