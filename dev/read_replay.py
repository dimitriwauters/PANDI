import cffi
from argparse import ArgumentParser
from pandare import Panda, panda_expect

ffi = cffi.FFI()

malware_pid = set()
memory_write_exe_list = {}
memory_write_list = {}
panda = Panda(qcow='/root/.panda/vm.qcow2', mem="3G", os_version="windows-32-7sp0", extra_args="-nographic -loadvm 1")

parser = ArgumentParser()
parser.add_argument("--debug", action='store_true', help="activate verbose mode", default=False)
parser.add_argument("--force_complete_replay", type=bool, help="read the replay until the end", default=False)
parser.add_argument("--max_memory_write_exe_list_length", type=int, help="maximum length of the returned list before exiting", default=1000)
args = parser.parse_args()

force_complete_replay = args.force_complete_replay
max_memory_write_exe_list_length = args.max_memory_write_exe_list_length
is_debug = args.debug


@panda.cb_virt_mem_after_write(enabled=False)
def virt_mem_after_write(env, pc, addr, size, buf):
    global memory_write_list
    current_process = panda.plugins['osi'].get_current_process(env)
    if current_process.pid in malware_pid:
        # FIXME: How to use correctly the size parameter ?
        for i in range(size - 1):
            current_addr = addr + i
            if current_addr not in memory_write_list:
                if len(memory_write_list) == 0:
                    panda.enable_callback("before_block_exec")
                memory_write_list[current_addr] = []
            # print(f"(VIRT_MEM_WRITE) ADDR WRITTEN: {current_addr} | PC DOING WRITE: {pc} ({ffi.string(current_process.name).decode()})", flush=True)
            memory_write_list[current_addr].append(pc)

        """if addr not in memory_write_list:
            if len(memory_write_list) == 0:
                panda.enable_callback("before_block_exec")
            memory_write_list[addr] = []
        # print(f"(VIRT_MEM_WRITE) ADDR WRITTEN: {current_addr} | PC DOING WRITE: {pc}", flush=True)
        memory_write_list[addr].append(pc)"""


@panda.cb_before_block_exec(enabled=False)
def before_block_exec(env, tb):
    # TODO : Use current_process to detect DLL ? (hint if process taskhost.exe is called)
    global memory_write_list, memory_write_exe_list
    pc = panda.arch.get_pc(env)
    if pc in memory_write_list:
        pc_json = str(pc)
        if pc_json not in memory_write_exe_list:
            memory_write_exe_list[pc_json] = []
        for addr in memory_write_list[pc]:
            memory_write_exe_list[pc_json].append(addr)
        memory_write_list[pc] = []
        if not force_complete_replay and len(memory_write_exe_list) >= max_memory_write_exe_list_length:
            try:
                panda.end_replay()
            except Exception:
                pass
        current_process = panda.plugins['osi'].get_current_process(env)
        if is_debug:
            print("(FOUND BLOCK_EXEC) PC BEING EXECUTED: {} ({}) - Length before cutting analysis: {})".format(
                pc, ffi.string(current_process.name).decode(), max_memory_write_exe_list_length - len(memory_write_exe_list)
            ), flush=True)


@panda.cb_asid_changed()
def asid_changed(env, old_asid, new_asid):
    global malware_pid
    for process in panda.get_processes(env):
        process_name = ffi.string(process.name)
        if "sample" in process_name.decode() or "cmd" in process_name.decode():
            if process.pid not in malware_pid:
                print(f"SAMPLE FOUND: {process_name} ({process.pid})", flush=True)
                malware_pid.add(process.pid)
                if not panda.is_callback_enabled("virt_mem_after_write") and "sample" in process_name.decode():
                    panda.enable_memcb()
                    panda.enable_callback("virt_mem_after_write")

    # TODO: Take into account possible subprocess of sample.exe
    if len(malware_pid) >= 2:
        panda.disable_callback("asid_changed")
    return 0


if __name__ == "__main__":
    panda.run_replay("/replay/sample")
    print(memory_write_exe_list)
