import ctypes, struct, sys
from ctypes import wintypes as w
exec(open('crack_work/tools/minidbg.py', encoding='utf-8').read().split('def main()')[0])

EXE = sys.argv[1] if len(sys.argv) > 1 else "client.exe"
ARGS = sys.argv[2] if len(sys.argv) > 2 else "1 127.0.0.1:4723"

si = STARTUPINFO(); si.cb = ctypes.sizeof(STARTUPINFO)
pi = PROCESS_INFORMATION()
cmd = (EXE + " " + ARGS).encode()
if not k32.CreateProcessA(EXE.encode(), cmd, None, None, False,
                          DEBUG_ONLY_THIS_PROCESS, None, None, ctypes.byref(si), ctypes.byref(pi)):
    print("CreateProcess failed"); sys.exit(1)
hp, ht = pi.hProcess, pi.hThread
threads = {pi.dwThreadId: ht}
ev = DEBUG_EVENT()

def find_export_rva(mod_base, want):
    hdr = rpm(hp, mod_base, 0x1000)
    if not hdr or hdr[:2] != b"MZ": return None
    pe = struct.unpack("<I", hdr[0x3c:0x40])[0]
    er, es = struct.unpack("<II", hdr[pe+24+96:pe+24+104])
    if not er: return None
    exp = rpm(hp, mod_base+er, es)
    if not exp: return None
    nf, nn = struct.unpack("<II", exp[20:28])
    af, an, ao = struct.unpack("<III", exp[28:40])
    fa = rpm(hp, mod_base+af, nf*4)
    na = rpm(hp, mod_base+an, nn*4)
    oa = rpm(hp, mod_base+ao, nn*2)
    if not (fa and na and oa): return None
    for i in range(nn):
        no = struct.unpack("<I", na[4*i:4*i+4])[0]
        nmb = rpm(hp, mod_base+no, 64)
        if not nmb: continue
        if nmb.split(b"\x00")[0] == want:
            oi = struct.unpack("<H", oa[2*i:2*i+2])[0]
            return struct.unpack("<I", fa[4*oi:4*oi+4])[0]
    return None

hooks = {}  # va -> (name, orig_byte, kind)

def add_hook(base, fn, kind):
    rva = find_export_rva(base, fn)
    if rva is None: return
    va = base + rva
    if va in hooks: return
    ob = rpm(hp, va, 1)
    hooks[va] = (fn.decode(), ob, kind)
    wpm(hp, va, b"\xcc")
    print(f"hooked {fn.decode()} @ {va:#x}")

last_dlls = []
while True:
    if not k32.WaitForDebugEvent(ctypes.byref(ev), 120000):
        print("timeout"); break
    code = ev.dwDebugEventCode
    cont = 0x80010001
    tid = ev.dwThreadId
    th = threads.get(tid)
    if code == 1:
        er = ev.u.Exception.ExceptionRecord
        ec, ea = er.ExceptionCode, er.ExceptionAddress
        if ec in (0x80000003, 0x4000001f):
            if ea in hooks:
                name, ob, kind = hooks[ea]
                ctx = get_ctx(th)
                sp = rpm(hp, ctx.Esp, 0x60)
                if kind == "exit":
                    ret = struct.unpack("<I", sp[:4])[0]
                    args = struct.unpack("<4I", sp[4:20])
                    print(f">>> {name} called! ret={ret:#x} args={[hex(a) for a in args]}")
                    big = rpm(hp, ctx.Esp, 0x400)
                    vals = struct.unpack("<256I", big)
                    for i, v in enumerate(vals):
                        if 0xfa50000 <= v < 0xff20000:
                            print(f"   esp+{i*4:03x}: {v:08x} <- sec7+{v-0xfa50000:x}")
                    print("   caller:", (rpm(hp, ret-10, 15) or b"").hex())
                    ctx2 = rpm(hp, ret-0x60, 0x60)
                    print("   code before caller:", ctx2.hex() if ctx2 else None)
                    break
                elif kind == "nqip":
                    ret, hdl, iclass, iptr, ilen, iret = struct.unpack("<6I", sp[:24])
                    wpm(hp, ea, ob)
                    if iclass == 7:  # ProcessDebugPort
                        wpm(hp, iptr, struct.pack("<I", 0))
                        ctx.Esp += 24; ctx.Eip = ret; ctx.Eax = 0
                        set_ctx(th, ctx); print("nqip: DebugPort masked")
                        wpm(hp, ea, b"\xcc")
                    elif iclass == 0x1f:  # ProcessDebugFlags
                        wpm(hp, iptr, struct.pack("<I", 1))
                        ctx.Esp += 24; ctx.Eip = ret; ctx.Eax = 0
                        set_ctx(th, ctx); print("nqip: DebugFlags masked")
                        wpm(hp, ea, b"\xcc")
                    elif iclass == 0x1e:  # ProcessDebugObjectHandle
                        ctx.Esp += 24; ctx.Eip = ret; ctx.Eax = 0xc0000353
                        set_ctx(th, ctx); print("nqip: DebugObjectHandle masked")
                        wpm(hp, ea, b"\xcc")
                    else:
                        ctx.Eip = ea; ctx.EFlags |= 0x100
                        set_ctx(th, ctx)
                elif kind == "hide":
                    ret, hthr, iclass = struct.unpack("<III", sp[:12])
                    wpm(hp, ea, ob)
                    if iclass == 0x11:
                        ctx.Esp += 20
                        ctx.Eip = ret
                        ctx.Eax = 0
                        set_ctx(th, ctx)
                        print(f"BLOCKED ThreadHideFromDebugger tid={tid}")
                        wpm(hp, ea, b"\xcc")
                    else:
                        ctx.Eip = ea
                        ctx.EFlags |= 0x100
                        set_ctx(th, ctx)
            else:
                pass
        elif ec == 0x80000004:
            for va, (n, ob, kd) in hooks.items():
                if kd == "hide":
                    wpm(hp, va, b"\xcc")
        elif ec == 0x8000002d:
            ctx = get_ctx(th); ctx.Eip += 1; set_ctx(th, ctx)
        else:
            print(f"EXC {ec:#x} at {ea:#x} first={ev.u.Exception.dwFirstChance}")
            cont = 0x80010002
            if not ev.u.Exception.dwFirstChance:
                break
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
                if ptr:
                    out = b""; a = ptr
                    for _ in range(128):
                        c = rpm(hp, a, 2 if li.fUnicode else 1)
                        if not c or c[:1] == b"\x00": break
                        out += c[:1]; a += 2 if li.fUnicode else 1
                    name = out.decode(errors="replace")
        short = name.split("\\")[-1] if name else hex(li.lpBaseOfDll)
        last_dlls.append(short)
        sl = short.lower()
        if sl == "ntdll.dll" and li.lpBaseOfDll < 0x80000000:
            add_hook(li.lpBaseOfDll, b"NtSetInformationThread", "hide")
            add_hook(li.lpBaseOfDll, b"NtTerminateProcess", "exit")
            add_hook(li.lpBaseOfDll, b"NtQueryInformationProcess", "nqip")
        if sl in ("kernel32.dll", "kernelbase.dll"):
            add_hook(li.lpBaseOfDll, b"ExitProcess", "exit")
            add_hook(li.lpBaseOfDll, b"TerminateProcess", "exit")
        if "rcgrand" in sl:
            print(f">>> DOG DLL LOADED: {short} @ {li.lpBaseOfDll:#x}")
        k32.CloseHandle(li.hFile)
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

print("last dlls:", last_dlls[-8:])
