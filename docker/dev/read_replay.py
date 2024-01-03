import cffi
from pandare import Panda, panda_expect
from utility import EntropyAnalysis, PEInformations, DynamicLoadedDLL, SearchDLL, DLLCallAnalysis, SectionPermissionCheck
from syscalls import SysCallsInterpreter
import os
import sys
import pickle
import hashlib

ffi = cffi.FFI()
syscalls = list()
panda = Panda(generic='i386')
panda.load_plugin("syscalls2", {"load-info": True})


@panda.ppp("syscalls2", "on_all_sys_enter2", autoload=False)
def on_all_sys_enter2(env, pc, call, rp):
    syscall_name = panda.ffi.string(call.name).decode()
    proc = panda.plugins['osi'].get_current_process(env)
    procname = panda.ffi.string(proc.name).decode() if proc != panda.ffi.NULL else "error"
    if malware_sample in procname:
        args = []
        for i in range(call.nargs):
            args.append(rp.args[i])
        syscalls.append(f"ENTER {rp.no} {syscall_name} {procname} {proc.pid} {hex(rp.retaddr)} {args}")
        print("ENTER", rp.no, syscall_name, procname, proc.pid, hex(rp.retaddr), args)


@panda.ppp("syscalls2", "on_all_sys_return2", autoload=False)
def on_all_sys_return2(env, pc, call, rp):
    syscall_name = panda.ffi.string(call.name).decode()
    proc = panda.plugins['osi'].get_current_process(env)
    procname = panda.ffi.string(proc.name).decode() if proc != panda.ffi.NULL else "error"
    if malware_sample in procname:
        syscalls.append(f"RETURN {syscall_name} {procname} {proc.pid}")
        print("RETURN", syscall_name, procname, proc.pid)


if __name__ == "__main__":
    if len(sys.argv) > 2:
        malware_sample_path = sys.argv[1]
        malware_sample = sys.argv[2]
        malware_hash = hashlib.sha256(malware_sample.encode()).hexdigest()
        try:
            panda.run_replay(f"/replay/{malware_hash}")
        except KeyboardInterrupt:
            panda.end_replay()
        result = {"syscalls": syscalls}
        with open(f"{malware_hash}_result.pickle", "wb") as f:
            pickle.dump(result, f, protocol=pickle.HIGHEST_PROTOCOL)
        sys.exit(0)
    else:
        sys.exit(1)
