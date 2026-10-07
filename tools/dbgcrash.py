import ctypes, struct
from ctypes import wintypes as w
exec(open('unpack_tools/minidbg.py').read().split('def main()')[0])
si = STARTUPINFO(); si.cb = ctypes.sizeof(STARTUPINFO)
pi = PROCESS_INFORMATION()
import sys
EXE = sys.argv[1] if len(sys.argv)>1 else "client.exe"
cmd = (EXE + " 1 127.0.0.1:4723").encode()
k32.CreateProcessA(EXE.encode(), cmd, None, None, False,
                   DEBUG_ONLY_THIS_PROCESS, None, None, ctypes.byref(si), ctypes.byref(pi))
hp, ht = pi.hProcess, pi.hThread
threads = {pi.dwThreadId: ht}
ev = DEBUG_EVENT()
while True:
    if not k32.WaitForDebugEvent(ctypes.byref(ev), 10000):
        print("timeout"); break
    code = ev.dwDebugEventCode
    cont = 0x80010001
    tid = ev.dwThreadId
    if code == 1:
        er = ev.u.Exception.ExceptionRecord
        ec, ea = er.ExceptionCode, er.ExceptionAddress
        if ec in (0x80000003, 0x4000001f, 0x80000004): pass
        else:
            th = threads.get(tid)
            ctx = get_ctx(th) if th else None
            print(f"EXC {ec:#x} at {ea:#x} first={ev.u.Exception.dwFirstChance}")
            if ctx:
                print(f"eip={ctx.Eip:#x} esp={ctx.Esp:#x} ebp={ctx.Ebp:#x}")
                st = rpm(hp, ctx.Esp, 0x40)
                if st:
                    vals = struct.unpack('<16I', st)
                    for i,v in enumerate(vals):
                        mark = ''
                        if 0x400000 <= v < 0xff1a000: mark = '<- image'
                        print(f"  esp+{i*4:02x}: {v:08x} {mark}")
            if not ev.u.Exception.dwFirstChance: break
            cont = 0x80010002
    elif code == 2: threads[tid] = ev.u.CreateThread.hThread

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
        print(f"process created, peb patched peb={peb:#x}")

    elif code == 5:
        print(f"exit code={ev.u.ExitProcess.dwExitCode:#x}")
        th = threads.get(ev.dwThreadId)
        if th:
            ctx = get_ctx(th)
            if ctx:
                st = rpm(hp, ctx.Esp, 0x60)
                if st:
                    vals = struct.unpack('<24I', st)
                    for i,v in enumerate(vals):
                        if 0x400000 <= v < 0xff20000:
                            print(f"  esp+{i*4:02x}: {v:08x} <- image")
        break
    elif code == 6: k32.CloseHandle(ev.u.LoadDll.hFile)
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
