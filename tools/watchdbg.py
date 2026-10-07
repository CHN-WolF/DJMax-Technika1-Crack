# watchdbg.py — hardened harness: PEB patch + anti-anti-debug forging + file API log + MessageBox break
import ctypes, sys, struct, os, json, pefile
from ctypes import wintypes as w
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from minidbg import (STARTUPINFO, PROCESS_INFORMATION, DEBUG_EVENT, rpm, wpm,
                     get_ctx, set_ctx, WOW64_CONTEXT_FULL, k32)

GAME = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
exe = os.path.join(GAME, sys.argv[1] if len(sys.argv) > 1 else "client_test.exe")
mods = json.load(open(os.path.join(GAME, "crack_work", "analysis", "modules_oep.json")))

def exp(dll):
    m = [x for x in mods if x['name'].lower() == dll.lower()]
    if not m: return {}
    pe = pefile.PE(m[0]['path'], fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    return {e.name: m[0]['base'] + e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}

K = exp("KERNEL32.DLL")
N = exp("ntdll.dll")
U = exp("USER32.dll")
BPS = {}
for src, names in [(K, [b"CheckRemoteDebuggerPresent", b"IsDebuggerPresent", b"OutputDebugStringA",
                        b"CreateFileA", b"CreateFileW", b"GetModuleFileNameA", b"GetFileSize", b"ReadFile",
                        b"ExitProcess", b"TerminateProcess", b"FatalExit", b"GetCurrentProcessId"]),
                   (N, [b"NtQueryInformationProcess", b"NtSetInformationThread", b"NtClose", b"NtQueryObject",
                        b"NtTerminateProcess", b"NtTerminateThread"]),
                   (U, [b"MessageBoxA", b"FindWindowA", b"FindWindowW", b"EnumWindows"])]:
    for n in names:
        if n in src:
            BPS[src[n]] = n.decode()
print("bps:", {hex(a): n for a, n in BPS.items()}, flush=True)

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
LOG = []

def ret_forge(name, hp, th, sp):
    # returns action: (skip_call, forged_retval or None, extra)
    if name in ("IsDebuggerPresent",):
        return 0
    if name == "CheckRemoteDebuggerPresent":
        buf = struct.unpack_from('<I', sp, 8)[0]
        wpm(hp, buf, struct.pack("<I", 0))
        return 1
    if name == "NtQueryInformationProcess":
        cls = struct.unpack_from('<I', sp, 8)[0]
        buf = struct.unpack_from('<I', sp, 12)[0]
        if cls == 7:    # ProcessDebugPort
            wpm(hp, buf, struct.pack("<I", 0))
        elif cls == 0x1F:  # ProcessDebugFlags
            wpm(hp, buf, struct.pack("<I", 1))
        elif cls == 0x1E:  # ProcessDebugObjectHandle
            wpm(hp, buf, struct.pack("<I", 0))
        return 0
    if name == "NtSetInformationThread":
        infocls = struct.unpack_from('<I', sp, 12)[0]
        return 0
    if name in ("NtClose", "NtQueryObject"):
        return 0
    if name in ("FindWindowA", "FindWindowW"):
        return 0
    if name == "OutputDebugStringA":
        return 1
    return None

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
            if len(bps_done) < len(BPS):
                for a, n in BPS.items():
                    if a in bps_done: continue
                    d = rpm(hp, a, 1)
                    if d is not None:
                        orig[a] = d
                        wpm(hp, a, b"\xcc")
                        bps_done.add(a)
                print("bps set:", len(bps_done), flush=True)
            elif ea in BPS:
                n = BPS[ea]
                ctx = get_ctx(th)
                esp = ctx.Esp
                sp = rpm(hp, esp, 0x20) or b"\x00" * 0x20
                ret = struct.unpack_from('<I', sp, 0)[0]
                if n in ("CreateFileA", "CreateFileW", "GetModuleFileNameA", "GetFileSize", "ReadFile", "MessageBoxA"):
                    info = ""
                    if n in ("CreateFileA", "CreateFileW"):
                        fn = struct.unpack_from('<I', sp, 4)[0]
                        raw = rpm(hp, fn, 520) or b""
                        if n.endswith("W"):
                            info = raw.decode('utf-16-le', 'replace').split('\x00')[0]
                        else:
                            info = raw.split(b'\0')[0].decode('latin-1', 'replace')
                    print(f"HIT {n} ret={ret:#x} {info}", flush=True)
                    LOG.append((n, ret, info))
                    if n == "MessageBoxA":
                        print("=== MessageBox; recent log:", LOG[-12:], flush=True)
                        for i in range(0, 0x40, 4):
                            val = struct.unpack_from('<I', sp, i)[0]
                            tag = " <- WL" if 0xFA50000 <= val < 0xFF17000 else ""
                            print("  [esp+%02x]=%08x%s" % (i, val, tag), flush=True)
                        break
                    wpm(hp, ea, orig[ea]); ctx.Eip = ea; set_ctx(th, ctx); wpm(hp, ea, b"\xcc")
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
                    continue
                if n in ("ExitProcess", "TerminateProcess", "NtTerminateProcess", "FatalExit"):
                    print(f"=== {n} called, stack:", flush=True)
                    for i in range(0, 0x60, 4):
                        val = struct.unpack_from('<I', sp, i)[0]
                        tag = " <- WL" if 0xFA50000 <= val < 0xFF17000 else (" <- img" if 0x401000 <= val < 0xFF17000 else "")
                        print("  [esp+%02x]=%08x%s" % (i, val, tag), flush=True)
                    break
                forged = ret_forge(n, hp, th, sp)
                if forged is not None:
                    # skip the call: set eip to ret address, pop args? we simply emulate "ret N"
                    wpm(hp, ea, orig[ea])
                    args_pop = {"IsDebuggerPresent": 0, "CheckRemoteDebuggerPresent": 8, "NtQueryInformationProcess": 0x14,
                                "NtSetInformationThread": 0x10, "NtClose": 4, "NtQueryObject": 0x10,
                                "FindWindowA": 8, "FindWindowW": 8, "OutputDebugStringA": 4}.get(n, 0)
                    ctx.Esp = esp + 4 + args_pop
                    ctx.Eip = ret
                    if forged:
                        ctx.Eax = forged
                    else:
                        ctx.Eax = 0
                    set_ctx(th, ctx)
                    print(f"FORGED {n} -> eax={ctx.Eax:#x}", flush=True)
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
                    continue
                wpm(hp, ea, orig[ea]); ctx.Eip = ea; set_ctx(th, ctx); wpm(hp, ea, b"\xcc")
            else:
                ctx = get_ctx(th)
                if ctx: ctx.Eip += 1; set_ctx(th, ctx)
        elif ec == 0x80000004:
            pass
        elif ec == 0x4000001f:
            cont = 0x80010001
        else:
            print(f"EXC {ec:#010x} at {ea:#x} first={ev.u.Exception.dwFirstChance}", flush=True)
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
        print("recent:", LOG[-10:], flush=True)
        break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

k32.TerminateProcess(hp, 0)
