// gai_hooktest.c — verify the GetAdaptersInfo hook plumbing:
// load iphlpapi, load diag dll (hooks GAI), then call GAI with the game's
// exact 648-byte buffer and with a deliberately tiny 100-byte buffer.
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>

static void try_call(DWORD sz) {
    BYTE buf[2048];
    DWORD n = sz;
    DWORD r = GetAdaptersInfo((PIP_ADAPTER_INFO)buf, &n);
    PIP_ADAPTER_INFO p = (PIP_ADAPTER_INFO)buf;
    printf("GAI(bufsize=%lu): ret=%lu outlen=%lu", (unsigned long)sz, (unsigned long)r, (unsigned long)n);
    if (r == 0 && n >= 640)
        printf("  first MAC=%02X:%02X:%02X:%02X:%02X:%02X addrLen=%lu",
               p->Address[0], p->Address[1], p->Address[2], p->Address[3], p->Address[4], p->Address[5],
               (unsigned long)p->AddressLength);
    printf("\n");
}

int main(void) {
    LoadLibraryA("iphlpapi.dll");               // present before dll DllMain
    HMODULE m = LoadLibraryA("RC_GrandLocal_diag.dll");
    if (!m) { printf("dll load fail %lu\n", GetLastError()); return 1; }
    try_call(648);   // the game's exact call
    try_call(100);   // forced overflow -> hook must rescue
    try_call(2048);  // big buffer passthrough
    return 0;
}
