import cffi
from pandare import Panda, panda_expect
from utility import SearchDLL
import os
import sys
import pickle

ffi = cffi.FFI()
panda = Panda(qcow='/root/.panda/vm.qcow2', mem="3G", os_version="windows-32-7sp0", extra_args="-nographic -loadvm 1")

sample_asid = None
malware_pid = set()

dll_granularity = int(os.getenv("panda_dll_discover_granularity", default=1000))
dll_max_failed = int(os.getenv("panda_max_dll_discover_fail", default=10000))
dll_force_rebuild = os.getenv("panda_force_dll_rediscover", default=False) == "True"

block_num = dll_granularity
not_found_count = 0
discovered_dll = None

@panda.cb_before_block_exec(enabled=False)
def before_block_exec(env, tb):
    global block_num, not_found_count
    if not_found_count > dll_max_failed:
        try:
            panda.end_replay()
        except:
            pass

    if block_num > dll_granularity and not panda.in_kernel(env) and panda.current_asid(env) == sample_asid:
        found = discovered_dll.search_dlls(env)
        if not found:
            not_found_count += 1
        else:
            not_found_count = 0
        block_num = 0
    block_num += 1

@panda.cb_asid_changed()
def asid_changed(env, old_asid, new_asid):
    global malware_pid, sample_asid
    for process in panda.get_processes(env):
        process_name = ffi.string(process.name)
        if "sample" in process_name.decode() or "cmd" in process_name.decode():
            if process.pid not in malware_pid:
                print(f"SAMPLE FOUND: {process_name} ({process.pid})", flush=True)
                malware_pid.add(process.pid)
                if not panda.is_callback_enabled("before_block_exec") and "sample" in process_name.decode():
                    sample_asid = new_asid
                    panda.enable_callback("before_block_exec")

    # TODO: Take into account possible subprocess of sample.exe
    if len(malware_pid) >= 2:
        panda.disable_callback("asid_changed")
    return 0

if __name__ == "__main__":
    discovered_dll = SearchDLL(panda)
    if not discovered_dll.is_savefile_exist() or dll_force_rebuild:
        try:
            panda.run_replay("/replay/sample")
            discovered_dll.save_discovered_dlls()
        except Exception as e:
            print(e)