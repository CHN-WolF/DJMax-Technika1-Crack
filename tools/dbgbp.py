import ctypes, struct, sys, time, subprocess
from ctypes import wintypes as w
exec(open('crack_work/tools/minidbg.py', encoding='utf-8').read().split('def main()')[0])

subprocess.Popen(["client.exe", "1", "127.0.0.1:4723"])
pid = None
t0 = time.time()
while time.time() - t0 < 20:
    out = subprocess.run(["tasklist", "/NH", "/FI", "IMAGENAME eq client.exe"],
                         capture_output=True, text=True, errors="replace").stdout
    pids = [int(l.split()[1]) for l in out.splitlines() if l.lower().startswith("client.exe")]
    if pids:
        pid = pids[-1]
        if time.time() - t0 > 4 and k32.DebugActiveProcess(pid):
            print("attached to", pid)
            break
    time.sleep(0.5)
if not pid:
    sys.exit(1)

hp = k32.OpenProcess(0x1F0FFF, False, pid)
# unhide all threads
ntdll = ctypes.windll.ntdll
class TE32(ctypes.Structure):
    _fields_ = [("dwSize", w.DWORD),("cntUsage", w.DWORD),("th32ThreadID", w.DWORD),
                ("th32OwnerProcessID", w.DWORD),("tpBasePri", w.LONG),("tpDeltaPri", w.LONG),("dwFlags", w.DWORD)]
snap = k32.CreateToolhelp32Snapshot(4, 0)
te = TE32(); te.dwSize = ctypes.sizeof(TE32)
ok = k32.Thread32First(snap, ctypes.byref(te))
cnt = 0
while ok:
    if te.th32OwnerProcessID == pid:
        ht2 = k32.OpenThread(0x0020 | 0x0040, False, te.th32ThreadID)  # SET_INFORMATION|GET_CONTEXT
        if ht2:
            r = ntdll.NtSetInformationThread(ht2, 0x11, None, 0)
            cnt += 1
            k32.CloseHandle(ht2)
    ok = k32.Thread32Next(snap, ctypes.byref(te))
k32.CloseHandle(snap)
print("unhid", cnt, "threads")
BP = None
orig = rpm(hp, BP, 1)
wpm(hp, BP, b"\xcc")
print(f"bp set at {BP:#x}")

ev = DEBUG_EVENT()
threads = {}
while True:
    if not k32.WaitForDebugEvent(ctypes.byref(ev), 10000):
            import subprocess as _sp
            out = _sp.run(["tasklist","/NH","/FI",f"PID eq {pid}"],capture_output=True,text=True,errors="replace").stdout
            print("tick, proc:", " ".join(out.split()[:5]) if out.strip() else "gone")
            if "client" not in out.lower(): break
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, 0x80010001) if False else None
            continue
            continue
    code = ev.dwDebugEventCode
    cont = 0x80010001
    tid = ev.dwThreadId
    if code == 1:
        er = ev.u.Exception.ExceptionRecord
        ec, ea = er.ExceptionCode, er.ExceptionAddress
        if ec in (0x80000003, 0x4000001f):
            if ea == BP:
                ht = threads.get(tid) or k32.OpenThread(0x1F03FF, False, tid)
                ctx = get_ctx(ht)
                wpm(hp, BP, orig)
                ctx.Eip = BP
                set_ctx(ht, ctx)
                print(f"=== hit bp, eax={ctx.Eax:#x} ecx={ctx.Ecx:#x}")
                arg = rpm(hp, ctx.Ebp + 8, 0x40)
                print("arg[ebp+8..]:", arg.hex() if arg else None)
                # try as std::string (SSO buffer at offset 0x10? try direct char*)
                for off in (0, 4, 0x10):
                    if arg:
                        ptr = struct.unpack("<I", arg[off:off+4])[0]
                        if 0x400000 <= ptr < 0x7f000000:
                            s = rpm(hp, ptr, 64)
                            if s:
                                print(f"  *arg+{off:#x} -> {ptr:#x}: {s.split(bytes([0]))[0]!r}")
                local = rpm(hp, ctx.Ebp - 0x40, 0x80)
                print("locals:", local.hex() if local else None)
                break
        elif ec == 0x80000004:
            pass
        else:
            print(f"EXC {ec:#x} at {ea:#x}")
            if not er.dwFirstChance if hasattr(er,'dwFirstChance') else not ev.u.Exception.dwFirstChance:
                break
            cont = 0x80010002
    elif code == 2:
        threads[tid] = ev.u.CreateThread.hThread
    elif code == 3:
        k32.CloseHandle(ev.u.CreateProcessInfo.hFile)
    elif code == 5:
        print("exit"); break
    elif code == 6:
        k32.CloseHandle(ev.u.LoadDll.hFile)
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
