// attach.c — inject a DLL into an ALREADY-RUNNING process (remote thread).
// usage: attach <pid> <dll-full-path>
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 3) { printf("usage: attach <pid> <dll-full-path>\n"); return 1; }
    DWORD pid = atoi(argv[1]);
    const char* dll = argv[2];
    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("OpenProcess fail %lu\n", GetLastError()); return 1; }
    int len = strlen(dll) + 1;
    void* mem = VirtualAllocEx(h, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    SIZE_T wr;
    WriteProcessMemory(h, mem, dll, len, &wr);
    void* ll = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE t = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)ll, mem, 0, NULL);
    if (!t) { printf("CreateRemoteThread fail %lu\n", GetLastError()); return 1; }
    WaitForSingleObject(t, 10000);
    DWORD rc = 0; GetExitCodeThread(t, &rc);
    printf("injected %s -> pid %lu (hmod=%08x)\n", dll, pid, rc);
    CloseHandle(t);
    CloseHandle(h);
    return 0;
}
