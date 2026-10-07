import ctypes, struct, sys, time, subprocess
from ctypes import wintypes as w
exec(open('crack_work/tools/minidbg.py', encoding='utf-8').read().split('def main()')[0])

# find client.exe pid
def find_pid():
    out = subprocess.run(["tasklist", "/NH", "/FI", "IMAGENAME eq client.exe"],
                         capture_output=True, text=True, errors="replace").stdout
    pids = [int(l.split()[1]) for l in out.splitlines() if l.lower().startswith("client.exe")]
    return pids[-1] if pids else None

wait = float(sys.argv[1]) if len(sys.argv) > 1 else 7.0
subprocess.Popen(["client.exe", "1", "127.0.0.1:4723"])
pid = None
attached = False
t0 = time.time()
while time.time() - t0 < wait:
    out = subprocess.run(["tasklist", "/NH", "/FI", "IMAGENAME eq client.exe"],
                         capture_output=True, text=True, errors="replace").stdout
    pids = [int(l.split()[1]) for l in out.splitlines() if l.lower().startswith("client.exe")]
    if pids:
        pid = pids[-1]
        if time.time() - t0 > 3 and k32.DebugActiveProcess(pid):
            print("attached to", pid)
            attached = True
            break
    time.sleep(0.5)
if not attached:
    print("could not attach"); sys.exit(1)


ev = DEBUG_EVENT()
threads = {}
while True:
    if not k32.WaitForDebugEvent(ctypes.byref(ev), 30000):
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
            ht = threads.get(tid)
            if ht is None:
                ht = k32.OpenThread(0x1F03FF, False, tid)
            ctx = get_ctx(ht) if ht else None
            if ctx:
                print(f"eip={ctx.Eip:#x} esp={ctx.Esp:#x} ebp={ctx.Ebp:#x} eax={ctx.Eax:#x} ebx={ctx.Ebx:#x} ecx={ctx.Ecx:#x} edx={ctx.Edx:#x} esi={ctx.Esi:#x} edi={ctx.Edi:#x}")
                cb = rpm(hp, ctx.Eip, 16) if (hp := k32.OpenProcess(0x410, False, pid)) else None
                print("code:", cb.hex() if cb else None)
                sp = rpm(hp, ctx.Esp, 0x80)
                if sp:
                    vals = struct.unpack("<32I", sp)
                    for i, v in enumerate(vals):
                        if 0x400000 <= v < 0xff20000:
                            print(f"   esp+{i*4:02x}: {v:08x} <- image+{v-0x400000:x}")
                try:
                    ebp = ctx.Ebp
                    print("--- frame walk")
                    for _ in range(12):
                        fr = rpm(hp, ebp, 8)
                        if not fr or len(fr) < 8: break
                        prev, ret = struct.unpack("<II", fr)
                        if ret and 0x400000 <= ret < 0xff20000:
                            print(f"   ret {ret:#x} (image+{ret-0x400000:x})")
                        if not prev or prev <= ebp or prev - ebp > 0x10000: break
                        ebp = prev
                except Exception as e:
                    print("walk err", e)
                try:
                    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
                    md = Cs(CS_ARCH_X86, CS_MODE_32)
                    for i, v in enumerate(struct.unpack("<32I", sp or bytes(128))):
                        if 0x401000 <= v < 0x4291000:
                            cb = rpm(hp, v-0x40, 0x50)
                            if cb:
                                print(f"--- disasm caller near {v:#x}")
                                for insn in md.disasm(cb, v-0x40):
                                    mark = " <<<" if insn.address == v else ""
                                    print(f"   {insn.address:08x}  {insn.mnemonic:8} {insn.op_str}{mark}")
                                    if insn.address > v: break
                            break
                except Exception as e:
                    print("disasm err", e)
            if not ev.u.Exception.dwFirstChance:
                cb = rpm(hp, 0x652000, 0x2000)
                if cb: open("crack_work/analysis/crashfunc.bin","wb").write(cb); print("crash region dumped")
                cb2 = rpm(hp, 0x412500, 0x200)
                if cb2: open("crack_work/analysis/crashfunc_412500.bin","wb").write(cb2)
                cb3 = rpm(hp, 0x50bb00, 0x200)
                if cb3: open("crack_work/analysis/findfunc.bin","wb").write(cb3)
                break
            cont = 0x80010002
    elif code == 2:
        threads[tid] = ev.u.CreateThread.hThread
    elif code == 3:
        k32.CloseHandle(ev.u.CreateProcessInfo.hFile)
    elif code == 5:
        print(f"exit code={ev.u.ExitProcess.dwExitCode:#x}"); break
    elif code == 6:
        k32.CloseHandle(ev.u.LoadDll.hFile)
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
