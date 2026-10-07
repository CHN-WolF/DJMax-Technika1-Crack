# Minimal 32-bit debugger for unpacking client_renamed.exe (Themida)
# Reaches OEP (0xfa59700) with anti-anti-debug handling.
import ctypes, sys, struct
from ctypes import wintypes as w

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = w.HANDLE

DEBUG_PROCESS = 0x1
DEBUG_ONLY_THIS_PROCESS = 0x2

class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPSTR), ("lpDesktop", w.LPSTR),
                ("lpTitle", w.LPSTR), ("dwX", w.DWORD), ("dwY", w.DWORD),
                ("dwXSize", w.DWORD), ("dwYSize", w.DWORD), ("dwXCountChars", w.DWORD),
                ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD), ("dwFlags", w.DWORD),
                ("wShowWindow", w.WORD), ("cbReserved2", w.WORD), ("lpReserved2", w.LPVOID),
                ("hStdInput", w.HANDLE), ("hStdOutput", w.HANDLE), ("hStdError", w.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE),
                ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]

class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [("ExceptionCode", w.DWORD), ("ExceptionFlags", w.DWORD),
                ("ExceptionRecord", ctypes.c_void_p), ("ExceptionAddress", ctypes.c_void_p),
                ("NumberParameters", w.DWORD), ("ExceptionInformation", w.ULONG * 15)]

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", w.DWORD)]

class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hThread", w.HANDLE), ("lpThreadLocalBase", ctypes.c_void_p),
                ("lpStartAddress", ctypes.c_void_p)]

class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", w.HANDLE), ("hProcess", w.HANDLE), ("hThread", w.HANDLE),
                ("lpBaseOfImage", ctypes.c_void_p), ("dwDebugInfoFileOffset", w.DWORD),
                ("nDebugInfoSize", w.DWORD), ("lpThreadLocalBase", ctypes.c_void_p),
                ("lpStartAddress", ctypes.c_void_p), ("lpImageName", ctypes.c_void_p),
                ("fUnicode", w.WORD)]

class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", w.DWORD)]

class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", w.HANDLE), ("lpBaseOfDll", ctypes.c_void_p),
                ("dwDebugInfoFileOffset", w.DWORD), ("nDebugInfoSize", w.DWORD),
                ("lpImageName", ctypes.c_void_p), ("fUnicode", w.WORD)]

class UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p)]

class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = [("lpDebugStringData", ctypes.c_void_p), ("fUnicode", w.WORD), ("nDebugStringLength", w.WORD)]

class RIP_INFO(ctypes.Structure):
    _fields_ = [("dwError", w.DWORD), ("dwType", w.DWORD)]

class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO),
                ("CreateThread", CREATE_THREAD_DEBUG_INFO),
                ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
                ("ExitThread", EXIT_PROCESS_DEBUG_INFO),
                ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
                ("LoadDll", LOAD_DLL_DEBUG_INFO),
                ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
                ("DebugString", OUTPUT_DEBUG_STRING_INFO),
                ("RipInfo", RIP_INFO)]

class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", w.DWORD), ("dwProcessId", w.DWORD),
                ("dwThreadId", w.DWORD), ("u", DEBUG_EVENT_UNION)]

class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [("ControlWord", w.DWORD), ("StatusWord", w.DWORD), ("TagWord", w.DWORD),
                ("ErrorOffset", w.DWORD), ("ErrorSelector", w.DWORD),
                ("DataOffset", w.DWORD), ("DataSelector", w.DWORD),
                ("RegisterArea", w.BYTE * 80), ("Cr0NpxState", w.DWORD)]

class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [("ContextFlags", w.DWORD),
                ("Dr0", w.DWORD), ("Dr1", w.DWORD), ("Dr2", w.DWORD),
                ("Dr3", w.DWORD), ("Dr6", w.DWORD), ("Dr7", w.DWORD),
                ("FloatSave", WOW64_FLOATING_SAVE_AREA),
                ("SegGs", w.DWORD), ("SegFs", w.DWORD), ("SegEs", w.DWORD), ("SegDs", w.DWORD),
                ("Edi", w.DWORD), ("Esi", w.DWORD), ("Ebx", w.DWORD), ("Edx", w.DWORD),
                ("Ecx", w.DWORD), ("Eax", w.DWORD),
                ("Ebp", w.DWORD), ("Eip", w.DWORD), ("SegCs", w.DWORD), ("EFlags", w.DWORD),
                ("Esp", w.DWORD), ("SegSs", w.DWORD),
                ("ExtendedRegisters", w.BYTE * 512)]

WOW64_CONTEXT_FULL = 0x00010007

def rpm(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
        return None
    return buf.raw[:got.value]

def wpm(h, addr, data):
    wrote = ctypes.c_size_t(0)
    old = w.DWORD(0)
    k32.VirtualProtectEx(h, ctypes.c_void_p(addr), len(data), 0x40, ctypes.byref(old))
    ok = k32.WriteProcessMemory(h, ctypes.c_void_p(addr), data, len(data), ctypes.byref(wrote))
    k32.VirtualProtectEx(h, ctypes.c_void_p(addr), len(data), old.value, ctypes.byref(old))
    return ok and wrote.value == len(data)

def get_ctx(ht):
    ctx = WOW64_CONTEXT()
    ctx.ContextFlags = WOW64_CONTEXT_FULL
    if not k32.Wow64GetThreadContext(ht, ctypes.byref(ctx)):
        return None
    return ctx

def set_ctx(ht, ctx):
    return k32.Wow64SetThreadContext(ht, ctypes.byref(ctx))

def main():
    si = STARTUPINFO(); si.cb = ctypes.sizeof(STARTUPINFO)
    pi = PROCESS_INFORMATION()
    cmd = "client_renamed.exe 1 127.0.0.1:4723"
    if not k32.CreateProcessA(b"client_renamed.exe", cmd.encode(), None, None, False,
                              DEBUG_ONLY_THIS_PROCESS, None, None,
                              ctypes.byref(si), ctypes.byref(pi)):
        print("CreateProcess failed", k32.GetLastError()); return 1
    print("pid", pi.dwProcessId)
    hp, ht = pi.hProcess, pi.hThread

    OEP = 0xfa59700
    peb_patched = False
    oep_bp_set = False
    oep_reached = False
    n_hide_fix = 0
    threads = {pi.dwThreadId: ht}
    ev = DEBUG_EVENT()
    steps = 0

    while True:
        if not k32.WaitForDebugEvent(ctypes.byref(ev), 10000):
            print("timeout waiting debug event"); break
        code = ev.dwDebugEventCode
        cont = 0x80010001  # DBG_CONTINUE
        tid = ev.dwThreadId
        th = threads.get(tid)

        if code == 3:  # CREATE_PROCESS
            base = ev.u.CreateProcessInfo.lpBaseOfImage
            print(f"create_process base={base:#x}")
            # patch PEB: BeingDebugged(+2), NtGlobalFlag(+0x68)
            peb_d = rpm(hp, 0x7ffdf000 if False else 0, 0)  # placeholder
            # get PEB from thread? use NtQueryInformationProcess
            class PBI(ctypes.Structure):
                _fields_ = [("Reserved1", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                            ("Reserved2", ctypes.c_void_p * 2), ("UniqueProcessId", ctypes.c_void_p),
                            ("Reserved3", ctypes.c_void_p)]
            ntdll = ctypes.windll.ntdll
            pbi = PBI()
            retlen = w.ULONG(0)
            ntdll.NtQueryInformationProcess(hp, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(retlen))
            peb = ctypes.cast(pbi.PebBaseAddress, ctypes.c_void_p).value
            print(f"peb={peb:#x}")
            wpm(hp, peb + 2, b"\x00")
            wpm(hp, peb + 0x68, struct.pack("<I", 0))
            # heap flags: PEB+0x18 = ProcessHeap; Flags at +0xC, ForceFlags +0x10 (32-bit)
            ph = rpm(hp, peb + 0x18, 4)
            if ph:
                heap = struct.unpack("<I", ph)[0]
                wpm(hp, heap + 0x0C, struct.pack("<I", 2))
                wpm(hp, heap + 0x10, struct.pack("<I", 0))
            peb_patched = True
            k32.CloseHandle(ev.u.CreateProcessInfo.hFile)
        elif code == 1:  # EXCEPTION
            er = ev.u.Exception.ExceptionRecord
            ec = er.ExceptionCode
            ea = er.ExceptionAddress
            if ec in (0x80000003, 0x4000001f):  # breakpoint / wow64 initial bp
                if not oep_bp_set:
                    # initial system breakpoint: set OEP bp now
                    d = rpm(hp, OEP, 1)
                    if d is not None:
                        wpm(hp, OEP, b"\xcc")
                        oep_bp_set = True
                        print("OEP bp set")
                    else:
                        print("cannot read OEP addr yet")
                elif ea == OEP:
                    print("=== OEP REACHED ===")
                    wpm(hp, OEP, b"\x55")  # restore push ebp
                    ctx = get_ctx(th)
                    ctx.Eip = OEP
                    set_ctx(th, ctx)
                    oep_reached = True
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
                    break
                else:
                    # int3 planted by Themida? restore not tracked; just skip
                    print(f"int3 at {ea:#x}")
                    ctx = get_ctx(th); ctx.Eip += 1; set_ctx(th, ctx)
            elif ec == 0x80000004:  # single step
                pass
            elif ec == 0x8000002d:  # int2d anti-debug
                ctx = get_ctx(th); ctx.Eip += 1; set_ctx(th, ctx)
                cont = 0x80010001
            else:
                print(f"exception {ec:#x} at {ea:#x} first={ev.u.Exception.dwFirstChance}")
                cont = 0x80010002 if ev.u.Exception.dwFirstChance else 0x80010002  # DBG_EXCEPTION_NOT_HANDLED
                if ev.u.Exception.dwFirstChance == 0:
                    print("second chance, giving up"); break
        elif code == 2:  # CREATE_THREAD
            threads[tid] = ev.u.CreateThread.hThread
        elif code == 4:  # EXIT_THREAD
            pass
        elif code == 6:  # LOAD_DLL
            k32.CloseHandle(ev.u.LoadDll.hFile)
        elif code == 5:  # EXIT_PROCESS
            print(f"exit_process code={ev.u.ExitProcess.dwExitCode:#x}")
            break
        elif code == 8:  # OUTPUT_DEBUG_STRING
            pass

        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

    print("oep_reached:", oep_reached)
    return 0

if __name__ == "__main__":
    sys.exit(main())
