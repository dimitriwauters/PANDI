import cffi
from pandare import Panda, panda_expect
from utility import EntropyAnalysis, PEInformations, DynamicLoadedDLL, SearchDLL, DLLCallAnalysis, SectionPermissionCheck
from syscalls import SysCallsInterpreter
import os
import sys
import pickle
import hashlib

ffi = cffi.FFI()
panda = Panda(qcow='/root/.panda/vm.qcow2', mem="3G", os_version="windows-32-7sp0", extra_args="-nographic -loadvm 1")
panda.load_plugin("syscalls2", {"load-info": True})

sample_not_found_counter = 0
malware_sample_path = ""
malware_sample = ""
sample_asid = {}
sample_pid = set()
processes = {}
memory_write_exe_list = []
memory_write_list = {}
executed_bytes_list = []
count = [0,0,0,0]
real_ep = -1
pc = 0
old_pc = 0
original_asid = 0
GetProcAddress_ret_addr = 0
GetProcAddress_func_name = ""
LoadLibrary_ret_addr = 0
LoadLibrary_func_name = ""


force_complete_replay = os.getenv("panda_force_complete_replay", default=False) == "True"
max_memory_write_exe_list_length = int(os.getenv("panda_max_memory_write_exe_list_length", default=1000))
entropy_granularity = int(os.getenv("panda_entropy_granularity", default=1000))
max_entropy_list_length = int(os.getenv("panda_max_entropy_list_length", default=0))
is_debug = os.getenv("panda_debug", default=False) == "True"
entropy_activated = os.getenv("panda_entropy", default=False) == "True"
memcheck_activated = os.getenv("panda_memcheck", default=False) == "True"
dll_activated = os.getenv("panda_dll", default=False) == "True"
dll_discover_activated = os.getenv("panda_dll_discover", default=False) == "True"
section_activated = os.getenv("panda_section_perms", default=False) == "True"
first_bytes_activated = os.getenv("panda_first_bytes", default=False) == "True"
count_instr_activated = os.getenv("panda_count_instr", default=False) == "True"

block_num = entropy_granularity
dll_analysis = DLLCallAnalysis()
syscall_interpreter = SysCallsInterpreter(panda)
entropy_analysis = None
last_section_executed = None
section_perms_check = None
dynamic_dll = None
pe_infos = None
discovered_dll = None

@panda.cb_virt_mem_after_write(enabled=False)
def virt_mem_after_write(env, pc, addr, size, buf):
    # =============================== EXEC WRITE DETECTION ===============================
    if memcheck_activated:
        global memory_write_list
        if panda.current_asid(env) in sample_asid:
            for i in range(size):
                current_addr = addr + i
                if current_addr not in memory_write_list:
                    memory_write_list[current_addr] = []
                memory_write_list[current_addr].append(pc)
    # ==================================== PERMS CHECK ====================================
    if section_activated:
        section_name = pe_infos.get_section_from_addr(addr)
        if section_name:
            last_perms = section_perms_check.get_last_section_permission(section_name)
            if not last_perms["write"]:
                section_perms_check.add_section_permission(env.rr_guest_instr_count, section_name, "write", True)


@panda.cb_virt_mem_after_read(enabled=False)
def virt_mem_after_read(env, pc, addr, size, buf):
    # ==================================== PERMS CHECK ====================================
    if section_activated:
        section_name = pe_infos.get_section_from_addr(addr)
        if section_name:
            last_perms = section_perms_check.get_last_section_permission(section_name)
            if not last_perms["read"]:
                section_perms_check.add_section_permission(env.rr_guest_instr_count, section_name, "read", True)


@panda.cb_before_block_exec(enabled=False)
def before_block_exec(env, tb):
    global entropy_activated, memcheck_activated, dll_activated, first_bytes_activated, count_instr_activated
    global last_section_executed, section_perms_check, pc, old_pc, original_asid
    global GetProcAddress_ret_addr, GetProcAddress_func_name, LoadLibrary_ret_addr, LoadLibrary_func_name, GetModuleHandle_ret_addr,GetModuleHandle_func_name
    if not panda.in_kernel(env) and panda.current_asid(env) in sample_asid:
        current_position = "Unknown"
        old_pc = pc
        pc = panda.arch.get_pc(env)
        if not pe_infos.headers:
            sample_base = None
            for mapping in panda.get_mappings(env):
                if mapping.file != panda.ffi.NULL:
                    mapping_name = panda.ffi.string(mapping.file).decode()
                    if "sample.exe" in mapping_name:
                        if mapping.base > 0x10000000:
                            print("SAMPLE_BASE IS TOO HIGH   " + str(mapping.base))
                        sample_base = mapping.base
                        original_asid = panda.current_asid(env)
            if sample_base:
                pe_infos.init_headers(sample_base, entropy_analysis.initial_entropy, dynamic_dll.initial_iat)
                section_perms_check = SectionPermissionCheck(pe_infos.headers_perms)
        elif panda.current_asid(env) == original_asid:
            pe_infos.update_imports_addr(env)
        current_section = pe_infos.get_section_from_addr(pc)
        # Update entry point of unpacked code
        if pe_infos.unpacked_EP_section[1] == 0 and current_section is not None \
                and last_section_executed == pe_infos.initial_EP_section[0] \
                and current_section != pe_infos.initial_EP_section[0]:
            if (dll_activated and len(dll_analysis.functions_generic["dynamic"]) + len(dll_analysis.functions_malicious["dynamic"]) > 0) or not dll_activated:
                pe_infos.unpacked_EP_section = [current_section, env.rr_guest_instr_count]
        # Update entry point of the packer
        if pe_infos.initial_EP_section[1] == 0 and current_section is not None and last_section_executed is None:
            pe_infos.initial_EP_section[1] = env.rr_guest_instr_count
        if pc <= pe_infos.get_higher_section_addr():
            last_section_executed = current_section
        # ==================================== PERMS CHECK ====================================
        if section_activated:
            section_name = pe_infos.get_section_from_addr(pc)
            if section_name:
                last_perms = section_perms_check.get_last_section_permission(section_name)
                if not last_perms["execute"]:
                    section_perms_check.add_section_permission(env.rr_guest_instr_count, section_name, "execute", True)
        # ===================================== DLL CHECK =====================================
        asid = panda.current_asid(env)
        if dll_activated and pe_infos.headers:
            if pc == GetProcAddress_ret_addr:
                func_addr = panda.arch.get_retval(env, convention="syscall")
                dynamic_dll.add_dll_method(GetProcAddress_func_name, func_addr, asid)
                print("GetProcAddress", GetProcAddress_func_name, hex(func_addr))
            elif pc == LoadLibrary_ret_addr:
                func_addr = panda.arch.get_retval(env, convention="syscall")
                dynamic_dll.add_dll(LoadLibrary_func_name, func_addr)
                print("LoadLibrary", LoadLibrary_func_name, hex(func_addr))
            if pc in discovered_dll.dll.keys() and old_pc >> 28 != 0:
                function_name = discovered_dll.get_dll_method_name_from_addr(pc)
                current_position = f"INTERNAL_CALL({function_name})"
                function_name = function_name.split('-')[0]
                dll_analysis.increase_call_nbr("internal", function_name)
            if old_pc >> 28 == 0:
                function_name = ""
                if dynamic_dll.get_dll_from_addr(pc, asid): 
                    function_name = dynamic_dll.get_dll_from_addr(pc, asid)
                    current_position = f"DYNAMIC_CALL({function_name})"
                    dll_analysis.increase_call_nbr("dynamic", function_name)
                elif pc in pe_infos.imports.values() and asid == original_asid:
                    function_name = pe_infos.get_import_name_from_addr(pc)
                    current_position = f"IAT_CALL({function_name})"
                    dll_analysis.increase_call_nbr("iat", function_name)
                elif pc in discovered_dll.dll.keys():
                    function_name = discovered_dll.get_dll_method_name_from_addr(pc)
                    current_position = f"DISCOVERED_CALL({function_name})"
                    function_name = function_name.split('-')[0]
                    dll_analysis.increase_call_nbr("discovered", function_name)
                if "GetProcAddress" in function_name:
                    syscall_result = syscall_interpreter.read_usercall(env, function_name)
                    GetProcAddress_ret_addr = syscall_result["ret"]
                    GetProcAddress_func_name = syscall_result["name"]
                elif "LoadLibrary" in function_name or "GetModuleHandle" in function_name:
                    syscall_result = syscall_interpreter.read_usercall(env, function_name)
                    LoadLibrary_ret_addr = syscall_result["ret"]
                    LoadLibrary_func_name = syscall_result["name"]
                if is_debug and function_name != "":
                    print(f"(BLOCK_EXEC) DETECTED DLL AT PC {hex(pc)} FROM {hex(old_pc)} (Detected position: {current_position})", flush=True)
        # =================================== ENTROPY CHECK ===================================
        if entropy_activated and pe_infos.headers:
            global block_num, entropy_granularity
            if block_num > entropy_granularity:
                block_num = 0
                entropy_granularity += 10
                memory, success = entropy_analysis.read_memory(env)
                if success:
                    entropy_analysis.analyse_entropy(env, memory)
                    if max_entropy_list_length != 0 and len(entropy_analysis.entropy) >= max_entropy_list_length:
                        entropy_activated = False
                    if current_section is not None:
                        current_position = f"SECTION({current_section})"
                    if is_debug:
                        print(f"(BLOCK_EXEC) MEASURED ENTROPY AT PC {hex(pc)} (Detected position: {current_position}, {panda.current_asid(env)})", flush=True)
            block_num += 1
        # ================================ RECORD FIRST BYTES ================================
        if first_bytes_activated:
            global executed_bytes_list, real_ep
            if len(executed_bytes_list) < 64:
                if current_section is not None:
                    if real_ep == -1:
                        real_ep = pc
                    b = panda.virtual_memory_read(env, pc, tb.size)
                    size = min(tb.size, 64 - len(executed_bytes_list))
                    for i in range(size):
                        executed_bytes_list.append(b[i])
            else:
                if is_debug:
                    print(f"(BLOCK_EXEC) DETECTED FIRST BYTES: {[str(hex(elem))[2:] for elem in executed_bytes_list]}", flush=True)
                first_bytes_activated = False
        # ================================ COUNT INSTRUCTIONS ================================
        if count_instr_activated:
            global count
            section_name = pe_infos.get_section_from_addr(pc)
            count[0] += tb.icount
            count[1] += 1
            if section_name:
                count[2] += tb.icount
                count[3] += 1
    # =============================== EXEC WRITE DETECTION ===============================
    if memcheck_activated:
        global memory_write_list, memory_write_exe_list
        pc = panda.arch.get_pc(env)
        if pc in memory_write_list and not is_known_dll_addr(pc):
            if pc not in memory_write_exe_list:
                memory_write_exe_list.append(pc)
            memory_write_list[pc] = []
            if max_memory_write_exe_list_length != 0 and len(memory_write_exe_list) >= max_memory_write_exe_list_length:
                memcheck_activated = False
            if is_debug:
                section_name = pe_infos.get_section_from_addr(pc)
                print(f"(BLOCK_EXEC) FOUND PREVIOUSLY WRITTEN ADDR BEING EXECUTED! PC: {hex(pc)} | Section: {section_name}", flush=True)
    # ====================================================================================
    if not (force_complete_replay or entropy_activated or memcheck_activated or dll_activated or section_activated or first_bytes_activated or count_instr_activated):
        try:
            panda.end_replay()
        except:
            pass


@panda.ppp("syscalls2", "on_all_sys_enter2", autoload=False)
def on_all_sys_enter2(env, pc, call, rp):
    # ===================================== DLL CHECK =====================================
    # ==================================== PERMS CHECK ====================================
    if section_activated:
        if panda.current_asid(env) in sample_asid:
            if call != panda.ffi.NULL:
                syscall_name = panda.ffi.string(call.name).decode()
                for arg_idx in range(call.nargs):
                    try:
                        arg_name = panda.ffi.string(call.argn[arg_idx])
                        arg_val = panda.arch.get_arg(env, arg_idx + 1, convention='cdecl')  # +1 because idx 0 is syscall number
                        syscall_result = syscall_interpreter.read_syscall(env, syscall_name, arg_name.decode(), arg_val)
                        if section_activated:
                            if syscall_name == "NtProtectVirtualMemory":
                                if arg_name.decode() == "BaseAddress":
                                    section_name = pe_infos.get_section_from_addr(syscall_result)
                                    if section_name:
                                        section_perms_check.add_baseaddress(syscall_result)
                                        section_perms_check.add_section(section_name)
                                elif arg_name.decode() == "NewProtectWin32":
                                    section_perms_check.add_permissions(syscall_result)
                                    data = section_perms_check.get_infos()
                                    if data and data["baseaddress"] and data["permissions"] and data["section"]:
                                        last_perms = section_perms_check.get_last_section_permission(data["section"])
                                        for access in ["execute", "read", "write"]:
                                            if last_perms[access] != data["permissions"][access]:
                                                section_perms_check.add_section_permission(env.rr_guest_instr_count, data["section"], access, data["permissions"][access])
                                                if is_debug:
                                                    print(f"(SYSCALLS2) DETECTED PERM CHANGE: {section_perms_check.permissions_modifications}", flush=True)
                    except Exception:
                        pass


@panda.cb_asid_changed()
def asid_changed(env, old_asid, new_asid):
    global sample_pid, sample_asid, sample_not_found_counter, processes
    current_process = panda.plugins['osi'].get_current_process(env)
    process_name = ffi.string(current_process.name).decode()
    if len(sample_pid) == 0:
        if "cmd" in process_name:
            print(f"INITIAL CMD FOUND: {process_name} ({current_process.pid} - {current_process.ppid})", flush=True)
            sample_pid.add(current_process.pid)
    elif current_process.ppid in sample_pid and current_process.pid not in sample_pid:
        sample_pid.add(current_process.pid)
        sample_asid[new_asid] = current_process.pid
        processes[current_process.pid] = process_name
        print(f"SAMPLE FOUND: {process_name} ({current_process.pid} - {current_process.ppid}) ({hex(old_asid)} {hex(new_asid)})", flush=True)
        if not panda.is_callback_enabled("before_block_exec"):
            panda.enable_callback("before_block_exec")
            if memcheck_activated or section_activated:
                panda.enable_memcb()
                panda.enable_callback("virt_mem_after_write")
                if section_activated:
                    panda.enable_callback("virt_mem_after_read")
    if False:
        processes = panda.get_processes(env)
        found = False
        for process in processes:
            if "sample" in ffi.string(process.name).decode(): # changer pour match les pid et pas le nom car le nom peut changer
                found = True
                sample_not_found_counter = 0
                break
        if not found:
            sample_not_found_counter += 1
            if sample_not_found_counter > 50:
                print("SAMPLE NOT FOUND ANYMORE")
                try:
                    panda.end_replay()
                except:
                    pass
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 2:
        malware_sample_path = sys.argv[1]
        malware_sample = sys.argv[2]
        malware_hash = hashlib.sha256(malware_sample.encode()).hexdigest()
        pe_infos = PEInformations(panda, is_debug, malware_sample_path, malware_sample)
        entropy_analysis = EntropyAnalysis(panda, pe_infos)
        dynamic_dll = DynamicLoadedDLL(panda, pe_infos)
        discovered_dll = SearchDLL(panda)
        try:
            if dll_discover_activated:
                discovered_dll.get_discovered_dlls()
            if entropy_activated or memcheck_activated or dll_activated or section_activated or first_bytes_activated or count_instr_activated:
                try:
                    panda.run_replay(f"/replay/{malware_hash}")
                except KeyboardInterrupt:
                    panda.end_replay()
                result = {"memory_write_exe_list": memory_write_exe_list,
                          "section_perms_changed": section_perms_check.permissions_modifications,
                          "entropy": entropy_analysis.entropy,
                          "entropy_initial_oep": pe_infos.initial_EP_section,
                          "entropy_unpacked_oep": pe_infos.unpacked_EP_section,
                          "executed_bytes_list": executed_bytes_list,
                          "count": count,
                          "real_EP": real_ep,
                          "initial_EP": pe_infos.initial_EP,
                          "initial_iat": list(pe_infos.imports.keys()),
                          "initial_dll": dynamic_dll.iat_dll,
                          "LoadLibrary": dynamic_dll.loaded_dll,
                          "GetProcAddress": dynamic_dll.get_dlls_name(),
                          "modified_iat": dynamic_dll.iat_modified,
                          "calls": dll_analysis.get_function_calls()}
                with open(f"{malware_hash}_result.pickle", "wb") as f:
                    pickle.dump(result, f, protocol=pickle.HIGHEST_PROTOCOL)
                sys.exit(0)
        except Exception as e:
            print(e)
            sys.exit(1)
    else:
        sys.exit(1)
