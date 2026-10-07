// gai_test.c — reproduce the game's exact GetAdaptersInfo(648) call
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>

int main(void) {
    BYTE buf[0x288];
    DWORD sz = sizeof(buf);
    DWORD r = GetAdaptersInfo((PIP_ADAPTER_INFO)buf, &sz);
    printf("GetAdaptersInfo(648): ret=%lu (0=OK 111=BUFFER_OVERFLOW 232=NO_DATA), needed=%lu\n", r, sz);
    // full list
    BYTE big[16384];
    DWORD sz2 = sizeof(big);
    DWORD r2 = GetAdaptersInfo((PIP_ADAPTER_INFO)big, &sz2);
    if (r2 == 0) {
        int n = 0;
        PIP_ADAPTER_INFO p = (PIP_ADAPTER_INFO)big;
        printf("entry size=%lu (sizeof(IP_ADAPTER_INFO)=%u)\n", sz2 ? 0UL : 0UL, (unsigned)sizeof(IP_ADAPTER_INFO));
        while (p) {
            printf("  adapter %d: %s  MAC %02X:%02X:%02X:%02X:%02X:%02X  addrLen=%u\n", n, p->Description,
                   p->Address[0], p->Address[1], p->Address[2], p->Address[3], p->Address[4], p->Address[5],
                   p->AddressLength);
            n++;
            p = p->Next;
        }
        printf("total adapters: %d, bytes needed: %lu\n", n, sz2);
    } else {
        printf("GetAdaptersInfo(big): ret=%lu\n", r2);
    }
    return 0;
}
