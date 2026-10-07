# dump_full.py — run client.exe from game root to OEP, dump sections + modules,
# keep running ~15s into demo mode, dump again for comparison. All artifacts to analysis/.
import ctypes, sys, struct, time, os, json
from ctypes import wintypes as w

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from minidbg import (STARTUPINFO, PROCESS_INFORMATION, DEBUG_EVENT, rpm, wpm,
                     get_ctx, set_ctx, WOW64_CONTEXT_FULL, k32)

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analysis")
GAME = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OEP = 0xFA59700

def dump(hp, base, size, name):
    data = b""
    addr = base
    while addr < base + size:
        n = min(0x100000, base + size - addr)
        d = rpm(hp, addr, n)
        if d is None:
            d = b"\x00" * n
        data += d
        addr += n
    path = os.path.join(OUT, name)
    open(path, "wb").write(data)
    print(f"dumped {name}: {len(data)} bytes", flush=True)
    return data

def module_list(hp, pid):
    mods = []
    k32.CreateToolhelp32Snapshot.restype = w.HANDLE
    snap = k32.CreateToolhelp32Snapshot(0x18, pid)  # SNAPMODULE | SNAPMODULE32
    if snap == w.HANDLE(-1).value or snap is None:
        print("snapshot failed", flush=True)
        return mods
    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", w.DWORD), ("th32ModuleID", w.DWORD),
                    ("th32ProcessID", w.DWORD), ("GlblcntUsage", w.DWORD),
                    ("ProccntUsage", w.DWORD), ("modBaseAddr", ctypes.c_void_p),
                    ("modBaseSize", w.DWORD), ("hModule", w.HANDLE),
                    ("szModule", ctypes.c_char * 256), ("szExePath", ctypes.c_char * 260)]
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    ok = k32.Module32First(snap, ctypes.byref(me))
    while ok:
        mods.append({"name": me.szModule.decode('latin-1'),
                     "base": me.modBaseAddr if me.modBaseAddr else 0,
                     "size": me.modBaseSize,
                     "path": me.szExePath.decode('latin-1')})
        ok = k32.Module32Next(snap, ctypes.byref(me))
    k32.CloseHandle(snap)
    return mods

def main():
    si = STARTUPINFO(); si.cb = ctypes.sizeof(STARTUPINFO)
    pi = PROCESS_INFORMATION()
    exe = os.path.join(GAME, "client.exe")
    if not k32.CreateProcessA(exe.encode(), b"client.exe 1 127.0.0.1:4723", None, None, False,
                              0x2, None, GAME.encode(), ctypes.byref(si), ctypes.byref(pi)):
        print("CreateProcess failed", k32.GetLastError()); return 1
    print("pid", pi.dwProcessId, flush=True)
    hp, ht = pi.hProcess, pi.hThread
    threads = {pi.dwThreadId: ht}
    oep_bp_set = False
    phase = 0
    t_oep = None
    ev = DEBUG_EVENT()

    while True:
        if not k32.WaitForDebugEvent(ctypes.byref(ev), 20000):
            print("timeout", flush=True); break
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
            if ec in (0x80000003, 0x4000001f):
                if not oep_bp_set:
                    if rpm(hp, OEP, 1) is not None:
                        wpm(hp, OEP, b"\xcc")
                        oep_bp_set = True
                        print("OEP bp set", flush=True)
                elif ea == OEP and phase == 0:
                    print("=== OEP REACHED ===", flush=True)
                    wpm(hp, OEP, b"\x55")
                    ctx = get_ctx(th); ctx.Eip = OEP; set_ctx(th, ctx)
                    dump(hp, 0x401000, 0x75D000 - 0x401000, "img_lo_oep.bin")
                    dump(hp, 0xF9E2000, 0xFF17000 - 0xF9E2000, "img_hi_oep.bin")
                    mods = module_list(hp, pi.dwProcessId)
                    json.dump(mods, open(os.path.join(OUT, "modules_oep.json"), "w"), indent=1)
                    print("modules:", len(mods), flush=True)
                    phase = 1
                    t_oep = time.time()
                else:
                    ctx = get_ctx(th)
                    if ctx: ctx.Eip += 1; set_ctx(th, ctx)
            elif ec == 0x80000004:
                pass
            elif ec == 0x8000002d:
                ctx = get_ctx(th)
                if ctx: ctx.Eip += 1; set_ctx(th, ctx)
            else:
                cont = 0x80010002
                if ev.u.Exception.dwFirstChance == 0:
                    print("second chance, stop", flush=True)
                    phase = 2
        elif code == 2:
            threads[tid] = ev.u.CreateThread.hThread
        elif code == 6:
            k32.CloseHandle(ev.u.LoadDll.hFile)
        elif code == 5:
            print(f"exit_process code={ev.u.ExitProcess.dwExitCode:#x}", flush=True)
            if phase == 1:
                phase = 2
            else:
                break

        if phase == 1 and time.time() - t_oep > 15:
            print("=== +15s: dumping late state ===", flush=True)
            for h in list(threads.values()):
                k32.SuspendThread(h)
            dump(hp, 0x400000, 0xFC0000, "img_late.bin")  # unused
            mods = module_list(hp, pi.dwProcessId)
            json.dump(mods, open(os.path.join(OUT, "modules_late.json"), "w"), indent=1)
            print("late modules:", len(mods), flush=True)
            phase = 2
            break

        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

    k32.TerminateProcess(hp, 0)
    print("done", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
