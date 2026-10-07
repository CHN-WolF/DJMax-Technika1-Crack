import ctypes, struct, sys
from ctypes import wintypes as w
exec(open('unpack_tools/minidbg.py').read().split('def main()')[0])
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = sys.argv[1] if len(sys.argv) > 1 else "client.exe"
si = STARTUPINFO(); si.cb = ctypes.sizeof(STARTUPINFO)
pi = PROCESS_INFORMATION()
cmd = (EXE + " 1 127.0.0.1:4723").encode()
k32.CreateProcessA(EXE.encode(), cmd, None, None, False,
                   DEBUG_ONLY_THIS_PROCESS, None, None, ctypes.byref(si), ctypes.byref(pi))
hp, ht = pi.hProcess, pi.hThread
threads = {pi.dwThreadId: ht}
ev = DEBUG_EVENT()
md = Cs(CS_ARCH_X86, CS_MODE_32)
watch_dll = None  # base of RCGrandDogW32.dll once loaded

def read_str_remote(addr, unicode_):
    out = b""
    for _ in range(64):
        if unicode_:
            c = rpm(hp, addr, 2)
            if not c or c == b"\x00\x00": break
            out += c[:1]
            addr += 2
        else:
            c = rpm(hp, addr, 1)
            if not c or c == b"\x00": break
            out += c
            addr += 1
    return out.decode(errors="replace")

while True:
    if not k32.WaitForDebugEvent(ctypes.byref(ev), 60000):
        print("timeout"); break
    code = ev.dwDebugEventCode
    cont = 0x80010001
    tid = ev.dwThreadId
    if code == 1:
        er = ev.u.Exception.ExceptionRecord
        ec, ea = er.ExceptionCode, er.ExceptionAddress
        if ec in (0x80000003, 0x4000001f, 0x80000004):
            pass
        else:
            print(f"EXC {ec:#x} at {ea:#x} first={ev.u.Exception.dwFirstChance}")
            if not ev.u.Exception.dwFirstChance: break
            cont = 0x80010002
    elif code == 2:
        threads[tid] = ev.u.CreateThread.hThread
    elif code == 3:
        k32.CloseHandle(ev.u.CreateProcessInfo.hFile)
        class PBI(ctypes.Structure):
            _fields_ = [("R1", ctypes.c_void_p), ("Peb", ctypes.c_void_p),
                        ("R2", ctypes.c_void_p * 2), ("Pid", ctypes.c_void_p), ("R3", ctypes.c_void_p)]
        ntdll = ctypes.windll.ntdll
        pbi = PBI(); rl = w.ULONG(0)
        ntdll.NtQueryInformationProcess(hp, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(rl))
        peb = ctypes.cast(pbi.Peb, ctypes.c_void_p).value
        wpm(hp, peb + 2, bytes([0]))
        wpm(hp, peb + 0x68, struct.pack("<I", 0))
        ph = rpm(hp, peb + 0x18, 4)
        if ph:
            heap = struct.unpack("<I", ph)[0]
            wpm(hp, heap + 0x0C, struct.pack("<I", 2))
            wpm(hp, heap + 0x10, struct.pack("<I", 0))
        print("created, peb patched")
    elif code == 5:
        print(f"exit code={ev.u.ExitProcess.dwExitCode:#x}")
        break
    elif code == 6:
        li = ev.u.LoadDll
        name = ""
        if li.lpImageName:
            p = rpm(hp, li.lpImageName, 4)
            if p:
                ptr = struct.unpack("<I", p)[0]
                if ptr: name = read_str_remote(ptr, li.fUnicode)
        print(f"load_dll: {name or hex(li.lpBaseOfDll)}")
        if "RCGrand" in name or "rcgrand" in name.lower():
            watch_dll = li.lpBaseOfDll
            print(f"  >>> RCGrandDog base={watch_dll:#x}")
        k32.CloseHandle(li.hFile)
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
