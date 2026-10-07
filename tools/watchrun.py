# watchrun.py — run target under debugger, report exceptions/exit, no breakpoints
import ctypes, sys, struct, os
from ctypes import wintypes as w
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from minidbg import (STARTUPINFO, PROCESS_INFORMATION, DEBUG_EVENT, rpm, wpm,
                     get_ctx, set_ctx, WOW64_CONTEXT_FULL, k32)

GAME = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
exe = os.path.join(GAME, sys.argv[1] if len(sys.argv) > 1 else "client_test.exe")

si = STARTUPINFO(); si.cb = ctypes.sizeof(STARTUPINFO)
pi = PROCESS_INFORMATION()
if not k32.CreateProcessA(exe.encode(), exe.encode() + b" 1 127.0.0.1:4723", None, None, False,
                          0x2, None, GAME.encode(), ctypes.byref(si), ctypes.byref(pi)):
    print("CreateProcess failed", k32.GetLastError()); sys.exit(1)
print("pid", pi.dwProcessId, flush=True)
hp, ht = pi.hProcess, pi.hThread
threads = {pi.dwThreadId: ht}
ev = DEBUG_EVENT()
last_eips = []
peb_done = False

while True:
    if not k32.WaitForDebugEvent(ctypes.byref(ev), 20000):
        print("timeout", flush=True)
        break
    code = ev.dwDebugEventCode
    cont = 0x80010001
    tid = ev.dwThreadId
    th = threads.get(tid)
    if code == 3:
        class PBI(ctypes.Structure):
            _fields_ = [("R1", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                        ("R2", ctypes.c_void_p * 2), ("UP", ctypes.c_void_p), ("R3", ctypes.c_void_p)]
        ntdll = ctypes.windll.ntdll
        pbi = PBI(); retlen = w.ULONG(0)
        ntdll.NtQueryInformationProcess(hp, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(retlen))
        peb = ctypes.cast(pbi.PebBaseAddress, ctypes.c_void_p).value
        wpm(hp, peb + 2, b"\x00")
        wpm(hp, peb + 0x68, struct.pack("<I", 0))
        ph = rpm(hp, peb + 0x18, 4)
        if ph:
            heap = struct.unpack("<I", ph)[0]
            wpm(hp, heap + 0x0C, struct.pack("<I", 2))
            wpm(hp, heap + 0x10, struct.pack("<I", 0))
        k32.CloseHandle(ev.u.CreateProcessInfo.hFile)
    elif code == 1:
        er = ev.u.Exception.ExceptionRecord
        ec, ea = er.ExceptionCode, er.ExceptionAddress
        ctx = get_ctx(th) if th else None
        if ec not in (0x80000003, 0x80000004, 0x4000001f, 0x8000002d):
            print(f"EXC {ec:#010x} at {ea:#x} first={ev.u.Exception.dwFirstChance}", flush=True)
            if ctx:
                print("  eip=%08x esp=%08x ebp=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x" %
                      (ctx.Eip, ctx.Esp, ctx.Ebp, ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx), flush=True)
                last_eips.append(ctx.Eip)
            cont = 0x80010002
            if ev.u.Exception.dwFirstChance == 0:
                print("second chance -> fatal", flush=True)
                break
    elif code == 2:
        threads[tid] = ev.u.CreateThread.hThread
    elif code == 6:
        k32.CloseHandle(ev.u.LoadDll.hFile)
    elif code == 5:
        print(f"exit_process code={ev.u.ExitProcess.dwExitCode:#x} last_eips={['%08x' % e for e in last_eips[-5:]]}", flush=True)
        break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

k32.TerminateProcess(hp, 0)
