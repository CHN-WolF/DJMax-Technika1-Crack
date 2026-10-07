# watchmb.py — run target, break at MessageBoxA, dump stack + nearby return addresses
import ctypes, sys, struct, os
from ctypes import wintypes as w
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from minidbg import (STARTUPINFO, PROCESS_INFORMATION, DEBUG_EVENT, rpm, wpm,
                     get_ctx, set_ctx, WOW64_CONTEXT_FULL, k32)

GAME = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
exe = os.path.join(GAME, sys.argv[1] if len(sys.argv) > 1 else "client_test.exe")
import json, pefile
mods = json.load(open(os.path.join(GAME, "crack_work", "analysis", "modules_oep.json")))
u32 = [x for x in mods if x['name'].lower() == 'user32.dll'][0]
pe = pefile.PE(u32['path'], fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
rva = next(e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name == b'MessageBoxA')
MB = 0xFA5D422 if os.environ.get("BPADDR") else u32['base'] + rva
print("MessageBoxA(32) at", hex(MB), flush=True)

si = STARTUPINFO(); si.cb = ctypes.sizeof(STARTUPINFO)
pi = PROCESS_INFORMATION()
if not k32.CreateProcessA(exe.encode(), exe.encode() + b" 1 127.0.0.1:4723", None, None, False,
                          0x2, None, GAME.encode(), ctypes.byref(si), ctypes.byref(pi)):
    print("CreateProcess failed", k32.GetLastError()); sys.exit(1)
print("pid", pi.dwProcessId, flush=True)
hp, ht = pi.hProcess, pi.hThread
threads = {pi.dwThreadId: ht}
ev = DEBUG_EVENT()
bp_set = False
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
            if not bp_set:
                d = rpm(hp, MB, 1)
                if d is not None:
                    wpm(hp, MB, b"\xcc")
                    bp_set = True
                    print("bp set on MessageBoxA", flush=True)
            elif ea == MB:
                hits += 1
                ctx = get_ctx(th)
                print(f"=== MessageBoxA hit #{hits} ===", flush=True)
                if ctx:
                    print("  esp=%08x ebp=%08x eip=%08x" % (ctx.Esp, ctx.Ebp, ctx.Eip), flush=True)
                    sp = rpm(hp, ctx.Esp, 0x80)
                    for i in range(0, 0x80, 4):
                        val = struct.unpack_from('<I', sp, i)[0]
                        tag = ""
                        if 0xFA50000 <= val < 0xFF17000: tag = "<- WL code"
                        elif 0x401000 <= val < 0xFF17000: tag = "<- image"
                        print("  [esp+%02x] = %08x %s" % (i, val, tag), flush=True)
                    # args of MessageBoxA: [esp+8]=text [esp+0xC]=caption
                    txt = rpm(hp, struct.unpack_from('<I', sp, 8)[0], 64)
                    cap = rpm(hp, struct.unpack_from('<I', sp, 12)[0], 64)
                    print("  caption:", cap, flush=True)
                    print("  text:", txt, flush=True)
                k32.TerminateProcess(hp, 0)
                break
            else:
                ctx = get_ctx(th)
                if ctx: ctx.Eip += 1; set_ctx(th, ctx)
        elif ec == 0x80000004:
            pass
        else:
            cont = 0x80010002
            if ev.u.Exception.dwFirstChance == 0:
                print("second chance AV -> fatal at", hex(ea), flush=True)
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
