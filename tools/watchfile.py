# watchfile.py — log CreateFile*/ReadFile/GetFileSize calls, then break at MessageBoxA
import ctypes, sys, struct, os, json, pefile
from ctypes import wintypes as w
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from minidbg import (STARTUPINFO, PROCESS_INFORMATION, DEBUG_EVENT, rpm, wpm,
                     get_ctx, set_ctx, WOW64_CONTEXT_FULL, k32)

GAME = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
exe = os.path.join(GAME, sys.argv[1] if len(sys.argv) > 1 else "client_test.exe")
mods = json.load(open(os.path.join(GAME, "crack_work", "analysis", "modules_oep.json")))

def exp_rva(dll, names):
    m = [x for x in mods if x['name'].lower() == dll.lower()]
    if not m: return None, None
    pe = pefile.PE(m[0]['path'], fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    out = {}
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if e.name in names:
            out[e.name.decode()] = m[0]['base'] + e.address
    return m[0]['base'], out

WATCH = {}
for dll, names in [("KERNEL32.DLL", [b"CreateFileA", b"CreateFileW", b"ReadFile", b"GetFileSize", b"GetModuleFileNameA", b"GetModuleFileNameW", b"VirtualAlloc", b"VirtualFree"]),
                   ("USER32.dll", [b"MessageBoxA"])]:
    base, exps = exp_rva(dll, names)
    for n, a in exps.items():
        WATCH[a] = n
print("watching:", {hex(a): n for a, n in WATCH.items()}, flush=True)

si = STARTUPINFO(); si.cb = ctypes.sizeof(STARTUPINFO)
pi = PROCESS_INFORMATION()
if not k32.CreateProcessA(exe.encode(), exe.encode() + b" 1 127.0.0.1:4723", None, None, False,
                          0x2, None, GAME.encode(), ctypes.byref(si), ctypes.byref(pi)):
    print("CreateProcess failed", k32.GetLastError()); sys.exit(1)
print("pid", pi.dwProcessId, flush=True)
hp, ht = pi.hProcess, pi.hThread
threads = {pi.dwThreadId: ht}
ev = DEBUG_EVENT()
bps_done = set()
orig = {}

def readstr(hp, va, uni=False):
    out = b""
    for i in range(260):
        d = rpm(hp, va + i * (2 if uni else 1), 2 if uni else 1)
        if not d: break
        out += d
        if (uni and d == b"\x00\x00") or (not uni and d == b"\x00"):
            break
    if uni:
        try: return out.decode('utf-16-le', 'replace')
        except: return repr(out)
    return out.split(b'\0')[0].decode('latin-1', 'replace')

hits = 0
while True:
    if not k32.WaitForDebugEvent(ctypes.byref(ev), 25000):
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
        if ec in (0x80000003, 0x4000001f):
            if len(bps_done) < len(WATCH):
                for a, n in WATCH.items():
                    if a in bps_done: continue
                    if rpm(hp, a, 1) is not None:
                        orig[a] = rpm(hp, a, 1)
                        wpm(hp, a, b"\xcc")
                        bps_done.add(a)
                print("bps set:", len(bps_done), flush=True)
            elif ea in WATCH:
                n = WATCH[ea]
                ctx = get_ctx(th)
                esp = ctx.Esp if ctx else 0
                sp = rpm(hp, esp, 0x20) or b"\x00" * 0x20
                ret = struct.unpack_from('<I', sp, 0)[0]
                info = ""
                if n in ("CreateFileA", "CreateFileW"):
                    fn = struct.unpack_from('<I', sp, 4)[0]
                    info = readstr(hp, fn, n.endswith("W"))
                elif n == "ReadFile":
                    info = "h=%x" % struct.unpack_from('<I', sp, 4)[0]
                elif n in ("GetModuleFileNameA", "GetModuleFileNameW"):
                    info = "hmod=%x" % struct.unpack_from('<I', sp, 4)[0]
                print(f"HIT {n} ret={ret:#x} {info}", flush=True)
                if n == "MessageBoxA":
                    print("=== MessageBox shown, stack:", flush=True)
                    for i in range(0, 0x40, 4):
                        val = struct.unpack_from('<I', sp, i)[0]
                        tag = " <- WL" if 0xFA50000 <= val < 0xFF17000 else ""
                        print("  [esp+%02x]=%08x%s" % (i, val, tag), flush=True)
                    break
                # restore & single-step then re-set bp
                wpm(hp, ea, orig[ea])
                ctx.Eip = ea
                set_ctx(th, ctx)
                wpm(hp, ea, b"\xcc")
                hits += 1
            else:
                ctx = get_ctx(th)
                if ctx: ctx.Eip += 1; set_ctx(th, ctx)
        elif ec == 0x80000004:
            pass
        else:
            cont = 0x80010002
            if ev.u.Exception.dwFirstChance == 0:
                print("second chance -> fatal at", hex(ea), flush=True)
                break
    elif code == 2:
        threads[tid] = ev.u.CreateThread.hThread
    elif code == 6:
        k32.CloseHandle(ev.u.LoadDll.hFile)
    elif code == 5:
        print(f"exit_process code={ev.u.ExitProcess.dwExitCode:#x}", flush=True)
        break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

k32.TerminateProcess(hp, 0)
