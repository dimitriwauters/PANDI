import cffi
from pandare import Panda, panda_expect
from utility import EntropyAnalysis, PEInformations, DynamicLoadedDLL
from syscalls import SysCallsInterpreter
import os
import sys

ffi = cffi.FFI()
panda = Panda(qcow='/root/.panda/vm.qcow2', mem="3G", os_version="windows-32-7sp0", extra_args="-nographic -loadvm 1") # -panda syscalls2:load-info=true
panda.load_plugin("syscalls2", {"load-info": True})

malware_sample = ""
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
entropy_analysis = None
syscall_interpreter = SysCallsInterpreter(panda)
last_section_executed = None

dynamic_dll = None
pe_infos = None


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
                if not pe_infos.headers:
                    pe_infos.init_headers(entropy_analysis.initial_entropy, dynamic_dll.initial_iat)
                pc = panda.arch.get_pc(env)
                if pe_infos.headers and (block_num > entropy_granularity or pc in pe_infos.imports.values() or pc in dynamic_dll.dynamic_dll_methods.values()):
                    current_position = "Unknown"
                    if pc in pe_infos.imports.values():  # If current addr correspond to a DLL method call addr
                        function_name = pe_infos.get_import_name_from_addr(pc).decode()
                        dynamic_dll.increase_call_nbr(function_name)
                        current_position = f"IAT_DLL({function_name})"
                        print("DIDI", function_name, hex(pc))
                        syscall_result = syscall_interpreter.read_usercall(env, function_name)
                        if type(syscall_result) != str:
                            print("\t", syscall_result["name"], hex(syscall_result["addr"]))
                        if function_name == "GetProcAddress":
                            dynamic_dll.add_dll_method(syscall_result["name"], syscall_result["addr"])
                        elif function_name == "LoadLibraryA":
                            dynamic_dll.add_dll(syscall_result["name"])
                        """try:
                            for arg_idx in range(10):
                                arg_val = panda.arch.get_arg(env, arg_idx, convention='cdecl')
                                print(arg_val)
                                if arg_val > 0xFFFF:  # TODO: REMOVE BLOCK
                                    try:
                                        mem = panda.virtual_memory_read(env, arg_val, 64)
                                        print(mem)
                                    except ValueError:
                                        pass
                        except ValueError:
                            pass"""
                    elif pc in dynamic_dll.dynamic_dll_methods.values():
                        function_name = dynamic_dll.get_dll_method_name_from_addr(pc)
                        dynamic_dll.increase_call_nbr(function_name)
                        current_position = f"DYNAMIC_DLL({function_name})"

                    memory = entropy_analysis.read_memory(env)
                    if memory:
                        current_section = None
                        entropy_analysis.analyse_entropy(env, memory)
                        for header_name in pe_infos.headers:
                            header = pe_infos.headers[header_name]
                            if header[0] <= pc <= header[1]:
                                current_section = header_name
                                break
                        # Update entry point of unpacked code
                        if pe_infos.unpacked_EP_section[1] == 0 and current_section is not None \
                                and last_section_executed == pe_infos.initial_EP_section[0] \
                                and current_section != pe_infos.initial_EP_section[0]:
                            pe_infos.unpacked_EP_section = [current_section, env.rr_guest_instr_count]
                        # Update entry point of the packer
                        if pe_infos.initial_EP_section[1] == 0 and current_section is not None \
                                and last_section_executed is None:
                            pe_infos.initial_EP_section[1] = env.rr_guest_instr_count
                        if pc <= pe_infos.get_higher_section_addr():
                            last_section_executed = current_section
                        block_num = 0
                        if max_entropy_list_length != 0 and len(entropy_analysis.entropy) >= max_entropy_list_length:
                            entropy_activated = False
                            for name in pe_infos.imports:
                                imp = pe_infos.imports[name]
                                print(name, hex(imp))
                        if current_section is not None:
                            current_position = f"SECTION({current_section})"
                            dynamic_dll.increase_call_nbr(current_section)
                    if is_debug:
                        print(f"(BLOCK_EXEC) MEASURED ENTROPY AT PC {hex(pc)} (Detected position: {current_position})", flush=True)
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


@panda.ppp("syscalls2", "on_all_sys_enter2", autoload=False)
def on_all_sys_enter2(env, pc, call, rp):
    if panda.current_asid(env) == sample_asid:
        if call != panda.ffi.NULL:
            syscall_name = panda.ffi.string(call.name).decode()
            for arg_idx in range(call.nargs):
                try:
                    arg_name = panda.ffi.string(call.argn[arg_idx])
                    arg_val = panda.arch.get_arg(env, arg_idx + 1, convention='cdecl')  # +1 because idx 0 is syscall number
                    print(syscall_name, call.argt[arg_idx], arg_name, arg_val, hex(arg_val), flush=True)
                    syscall_result = syscall_interpreter.read_syscall(env, syscall_name, arg_name.decode(), arg_val)
                    print(f"{syscall_name} {arg_name.decode()}: {syscall_result}")
                    if syscall_name == "NtOpenSection" and arg_name.decode() == "ObjectAttributes":
                        dynamic_dll.add_dll(syscall_result)
                    if arg_val > 0xFFFF:  # TODO: REMOVE BLOCK
                        try:
                            mem = panda.virtual_memory_read(env, arg_val, 64)
                            print(mem)
                        except ValueError:
                            pass
                    else:
                        pass
                except Exception:
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
    if len(sys.argv) > 1:
        malware_sample = sys.argv[1]
        pe_infos = PEInformations(panda, malware_sample)
        entropy_analysis = EntropyAnalysis(panda, pe_infos)
        dynamic_dll = DynamicLoadedDLL(panda, pe_infos)
        result = {"memory_write_exe_list": "", "entropy": "", "entropy_initial_oep": "", "entropy_unpacked_oep": ""}
        try:
            if entropy_activated or memcheck_activated:
                panda.run_replay("/replay/sample")
                dynamic_dll.get_dynamic_dll()
                result["memory_write_exe_list"] = memory_write_exe_list
                result["entropy"] = entropy_analysis.entropy
                result["entropy_initial_oep"] = pe_infos.initial_EP_section
                result["entropy_unpacked_oep"] = pe_infos.unpacked_EP_section
        except Exception as e:
            print(e)
        finally:
            with open("replay_result.txt", "w") as file:
                file.write(str(result))
    else:
        sys.exit(1)
