import cffi
from pandare import Panda, panda_expect
from utility import EntropyAnalysis
import os

ffi = cffi.FFI()
panda = Panda(qcow='/root/.panda/vm.qcow2', mem="3G", os_version="windows-32-7sp0", extra_args="-nographic -loadvm 1")

sample_asid = None
malware_pid = set()
memory_write_exe_list = {}
memory_write_list = {}

force_complete_replay = os.getenv("panda_force_complete_replay", default=False) == "True"
max_memory_write_exe_list_length = int(os.getenv("panda_max_memory_write_exe_list_length", default=1000))
entropy_granularity = int(os.getenv("panda_entropy_granularity", default=1000))
max_entropy_list_length = int(os.getenv("panda_max_entropy_list_length", default=0))
is_debug = os.getenv("panda_debug", default=False) == "True"
entropy_activated = os.getenv("panda_entropy", default=False) == "True"
memcheck_activated = os.getenv("panda_memcheck", default=False) == "True"

block_num = entropy_granularity
entropy_analysis = EntropyAnalysis(panda)
last_section_executed = None


@panda.cb_virt_mem_after_write(enabled=False)
def virt_mem_after_write(env, pc, addr, size, buf):
    global memory_write_list
    current_process = panda.plugins['osi'].get_current_process(env)
    if current_process.pid in malware_pid:
        for i in range(size - 1):
            current_addr = addr + i
            if current_addr not in memory_write_list:
                memory_write_list[current_addr] = []
            if is_debug:
                print(f"(VIRT_MEM_WRITE) ADDR WRITTEN: {current_addr} | PC DOING WRITE: {pc} ({ffi.string(current_process.name).decode()})", flush=True)
            memory_write_list[current_addr].append(pc)


@panda.cb_before_block_exec(enabled=False)
def before_block_exec(env, tb):
    global entropy_activated, memcheck_activated
    if not panda.in_kernel(env):
        # =================================== ENTROPY CHECK ===================================
        if entropy_activated:
            global block_num, last_section_executed
            if panda.current_asid(env) == sample_asid:
                if not entropy_analysis.headers:
                    entropy_analysis.init_headers(env)
                if entropy_analysis.headers and block_num > entropy_granularity:
                    memory = entropy_analysis.read_memory(env)
                    if memory:
                        pc = panda.arch.get_pc(env)
                        current_section = None
                        entropy_analysis.analyse_entropy(env, memory)
                        for header_name in entropy_analysis.headers:
                            header = entropy_analysis.headers[header_name]
                            if header[0] <= pc <= header[1]:
                                current_section = header_name
                                break
                        # Update entry point of unpacked code
                        if entropy_analysis.unpacked_EP_section[1] == 0 and current_section is not None \
                                and last_section_executed == entropy_analysis.initial_EP_section[0] \
                                and current_section != entropy_analysis.initial_EP_section[0]:
                            entropy_analysis.unpacked_EP_section = [current_section, env.rr_guest_instr_count]
                        # Update entry point of the packer
                        if entropy_analysis.initial_EP_section[1] == 0 and current_section is not None \
                                and last_section_executed is None:
                            entropy_analysis.initial_EP_section[1] = env.rr_guest_instr_count
                        if pc <= entropy_analysis.get_higher_section_addr():
                            last_section_executed = current_section
                        block_num = 0
                        if max_entropy_list_length != 0 and len(entropy_analysis.entropy) >= max_entropy_list_length:
                            entropy_activated = False
                        if is_debug:
                            print(f"(BLOCK_EXEC) MEASURED ENTROPY AT PC {hex(pc)} (Section: {current_section} - Inital EP Section: {entropy_analysis.initial_EP_section[0]})", flush=True)
                block_num += 1
        # =============================== EXEC WRITE DETECTION ===============================
        if memcheck_activated:
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
                if max_memory_write_exe_list_length != 0 and len(memory_write_exe_list) >= max_memory_write_exe_list_length:
                    memcheck_activated = False
                if is_debug:
                    print(f"(BLOCK_EXEC) FOUND PREVIOUSLY WRITTEN ADDR BEING EXECUTED! PC: {hex(pc)}", flush=True)

        if not force_complete_replay and not entropy_activated and not memcheck_activated:
            try:
                panda.end_replay()
            except:
                pass


@panda.cb_asid_changed()
def asid_changed(env, old_asid, new_asid):
    global malware_pid, sample_asid
    for process in panda.get_processes(env):
        process_name = ffi.string(process.name)
        if "sample" in process_name.decode() or "cmd" in process_name.decode():
            if process.pid not in malware_pid:
                print(f"SAMPLE FOUND: {process_name} ({process.pid})", flush=True)
                malware_pid.add(process.pid)
                if not panda.is_callback_enabled("virt_mem_after_write") and "sample" in process_name.decode():
                    sample_asid = new_asid
                    if memcheck_activated:
                        panda.enable_memcb()
                        panda.enable_callback("virt_mem_after_write")
                    panda.enable_callback("before_block_exec")

    # TODO: Take into account possible subprocess of sample.exe
    if len(malware_pid) >= 2:
        panda.disable_callback("asid_changed")
    return 0


if __name__ == "__main__":
    result = {"memory_write_exe_list": "", "entropy": "", "entropy_initial_oep": "", "entropy_unpacked_oep": ""}
    if entropy_activated or memcheck_activated:
        panda.run_replay("/replay/sample")
        result["memory_write_exe_list"] = memory_write_exe_list
        result["entropy"] = entropy_analysis.entropy
        result["entropy_initial_oep"] = entropy_analysis.initial_EP_section
        result["entropy_unpacked_oep"] = entropy_analysis.unpacked_EP_section
    with open("replay_result.txt", "w") as file:
        file.write(str(result))
