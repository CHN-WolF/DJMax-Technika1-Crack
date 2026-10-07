// run_unpacked.c — final launcher for the unpacked client: starts the rebuilt
// exe CREATE_SUSPENDED, injects selfredir.dll, resumes. That's all it takes:
// the shell's self-read then gets the original client.exe's bytes.
// usage: run_unpacked.exe [server]   (default 127.0.0.1:4723)
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

// remote-thread exit code is unreliable this early (process suspended before
// init): verify by enumerating the child's 32-bit modules instead.
static int check_injected(DWORD pid) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (s == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    int found = 0;
    if (Module32First(s, &me)) do {
        if (strstr(me.szModule, "selfredir")) found = 1;
    } while (Module32Next(s, &me));
    CloseHandle(s);
    return found;
}

int main(int argc, char** argv) {
    char dir[MAX_PATH];
    GetModuleFileNameA(NULL, dir, MAX_PATH);
    char* p = strrchr(dir, '\\');
    if (p) *p = 0;  // dir = our dir (game root)

    char dll[MAX_PATH], cmd[MAX_PATH * 2];
    _snprintf(dll, MAX_PATH, "%s\\selfredir.dll", dir);
    const char* server = argc > 1 ? argv[1] : "127.0.0.1:4723";
    _snprintf(cmd, sizeof(cmd), "\"%s\\client_unpacked.exe\" 1 %s", dir, server);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, dir, &si, &pi)) {
        printf("CreateProcess fail %lu\n", GetLastError()); return 1;
    }
    int len = strlen(dll) + 1;
    void* mem = VirtualAllocEx(pi.hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    SIZE_T wr;
    WriteProcessMemory(pi.hProcess, mem, dll, len, &wr);
    void* ll = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE t = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)ll, mem, 0, NULL);
    if (t) { WaitForSingleObject(t, 10000); CloseHandle(t); }
    printf("selfredir %s, resuming\n", check_injected(pi.dwProcessId) ? "loaded" : "FAILED");
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
