// inject.c — start a process and immediately LoadLibrary our DLL into it.
// usage: inject <dll-full-path> <exe> [args...]
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 3) { printf("usage: inject <dll> <exe> [args]\n"); return 1; }
    const char* dll = argv[1];
    char cmd[1024] = { 0 };
    for (int i = 2; i < argc; i++) { strcat(cmd, argv[i]); strcat(cmd, " "); }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    int suspend_first = (getenv("INJECT_SUSPENDED") != NULL);
    DWORD flags = suspend_first ? CREATE_SUSPENDED : 0;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi)) {
        printf("CreateProcess fail %lu\n", GetLastError()); return 1;
    }
    printf("pid=%lu%s, injecting %s\n", pi.dwProcessId, suspend_first ? " (suspended)" : "", dll);
    if (!suspend_first) Sleep(50);  // let the loader finish mapping the image

    int len = strlen(dll) + 1;
    void* p = VirtualAllocEx(pi.hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) { printf("VirtualAllocEx fail\n"); return 1; }
    SIZE_T wr;
    WriteProcessMemory(pi.hProcess, p, dll, len, &wr);
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    void* ll = (void*)GetProcAddress(k32, "LoadLibraryA");
    HANDLE t = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)ll, p, 0, NULL);
    if (!t) { printf("CreateRemoteThread fail %lu\n", GetLastError()); return 1; }
    WaitForSingleObject(t, 5000);
    DWORD rc = 0; GetExitCodeThread(t, &rc);
    printf("LoadLibrary returned %08x\n", rc);
    CloseHandle(t);
    if (suspend_first) {
        printf("resuming main thread\n");
        ResumeThread(pi.hThread);
    }
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}
