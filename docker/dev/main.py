import os
import subprocess
import json
import sys
import time
import pickle
from utility import write_debug_file, write_output_file

MAX_TRIES = 3

entropy_activated = os.getenv("panda_entropy", default=False) == "True"
memcheck_activated = os.getenv("panda_memcheck", default=False) == "True"
dll_activated = os.getenv("panda_dll", default=False) == "True"
dll_discover_activated = os.getenv("panda_dll_discover", default=False) == "True"
sections_activated = os.getenv("panda_section_perms", default=False) == "True"


def print_info(text):
    if not is_silent:
        print(text, flush=True)


if __name__ == "__main__":
    is_silent = os.getenv("panda_silent", default=False) == "True"
    is_debug = os.getenv("panda_debug", default=False) == "True"
    force_executable = os.getenv("panda_executable", default=None)
    if force_executable == "None":
        force_executable = None

    if is_debug:
        print_info("DEBUGGING ACTIVATED")
    if force_executable is not None:
        print_info(f"MALWARE ANALYSED: {force_executable}")

    print_info("++ Launching")
    result = {True: [], False: []}
    if force_executable is None:
        files_to_analyse = os.listdir("/payload")
    else:
        files_to_analyse = [force_executable]
    for malware_sample in files_to_analyse:
        if ".exe" in malware_sample:
            is_packed = False
            panda_output_dict = None
            print_info(f"  -- Processing file '{malware_sample}'")
            for i in range(MAX_TRIES):
                panda_run_output, panda_dll_output, panda_replay_output = None, None, None
                print_info("    -- Creating ISO")
                subprocess.run(["genisoimage", "-max-iso9660-filenames", "-RJ", "-o", "payload.iso", f"/payload/{malware_sample}"], capture_output=True)
                print_info("    -- Running PANDA")
                try:
                    panda_run_output = subprocess.run(["python3", "/addon/run_panda.py", malware_sample], capture_output=True)
                except subprocess.CalledProcessError as e:
                    print_info("    !! An error occurred when trying to execute PANDA:")
                    print_info(e.stderr.decode())
                    sys.exit(e.returncode)
                time.sleep(2)
                if dll_discover_activated:
                    print_info("    -- Discovering DLLs")
                    try:
                        panda_dll_output = subprocess.run(["python3", "/addon/discover_dlls.py"], capture_output=True)
                    except subprocess.CalledProcessError as e:
                        print_info("    !! An error occurred when trying to discover DLLs:")
                        print_info(e.stderr.decode())
                        sys.exit(e.returncode)
                time.sleep(2)
                print_info("    -- Analysing PANDA recording (might take a while)")
                try:
                    panda_replay_output = subprocess.run(["python3", "/addon/read_replay.py", malware_sample], capture_output=True)
                except subprocess.CalledProcessError as e:
                    print_info("    !! An error occurred when trying to analyse PANDA output:")
                    print_info(e.stderr.decode())
                    sys.exit(e.returncode)

                if is_debug:
                    write_debug_file(malware_sample, "run_panda", panda_run_output.stdout.decode())
                    write_debug_file(malware_sample, "read_replay", panda_replay_output.stdout.decode())
                    if panda_dll_output:
                        write_debug_file(malware_sample, "discover_dlls", panda_dll_output.stdout.decode())

                if os.path.isfile("replay_result.pickle"):
                    with open("replay_result.pickle", "rb") as file:
                        panda_output_dict = pickle.load(file)
                if panda_output_dict is not None:
                    break

                print_info(f"  !! An error occurred when recovering the recording of PANDA, retrying... ({i+1} of {MAX_TRIES})\n")

            if panda_output_dict:
                if memcheck_activated:
                    memory_write_list = panda_output_dict["memory_write_exe_list"]
                    if len(memory_write_list) > 0:
                        # TODO: Check if consecutive
                        """count = 0
                        for elem in memory_write_list:
                            addr = elem[1] % 134  # Modulo x86, the length of an instruction
                            print(addr)"""
                        is_packed = True
                    write_output_file(malware_sample, is_packed, "memcheck", "memcheck", {"memory_write_exe_list": memory_write_list})
                    result[is_packed].append(malware_sample)
                if entropy_activated:
                    entropy = panda_output_dict["entropy"]
                    entropy_initial_oep = panda_output_dict["entropy_initial_oep"]
                    entropy_unpacked_oep = panda_output_dict["entropy_unpacked_oep"]
                    entropy_val = {}
                    for instr_nbr in entropy:
                        current_dict = entropy[instr_nbr]
                        for header_name in current_dict:
                            if header_name not in entropy_val:
                                entropy_val[header_name] = ([], [])
                            entropy_val[header_name][0].append(int(instr_nbr))
                            entropy_val[header_name][1].append(current_dict[header_name])
                    for header_name in entropy_val:
                        has_initial_eop, has_unpacked_eop = False, False
                        if header_name == entropy_initial_oep[0]:
                            has_initial_eop = True
                        if header_name == entropy_unpacked_oep[0]:
                            has_unpacked_eop = True
                        file_dict = {"entropy": [entropy_val[header_name][0], entropy_val[header_name][1]],
                                     "has_inital_eop": has_initial_eop, "initial_eop": entropy_initial_oep[1],
                                     "has_unpacked_eop": has_unpacked_eop, "unpacked_eop": entropy_unpacked_oep[1]}
                        write_output_file(malware_sample, is_packed, "entropy", header_name, file_dict)
                if dll_activated:
                    file_dict = {"initial_iat": panda_output_dict["dll_inital_iat"], "dynamically_loaded_dll": panda_output_dict["dll_dynamically_loaded_dll"],
                                 "calls_nbr": panda_output_dict["dll_call_nbrs"], "GetProcAddress_functions": panda_output_dict["dll_GetProcAddress_returns"]}
                    write_output_file(malware_sample, is_packed, "syscalls", "syscalls", file_dict)
                if sections_activated:
                    file_dict = {"section_perms_changed": panda_output_dict["section_perms_changed"]}
                    write_output_file(malware_sample, is_packed, "sections_perms", "sections_perms", file_dict)
                result[is_packed].append(malware_sample)
                print_info("      -- The result of the analysis is: {}\n".format("PACKED" if is_packed else "NOT-PACKED"))
    print_info("++ Finished")

    # Show results
    total_analyzed = len(result[True])+len(result[False])
    percent_packed = len(result[True])/total_analyzed
    percent_not_packed = len(result[False])/total_analyzed
    print_info("*** % packed: {}\n*** % non-packed: {}".format(percent_packed, percent_not_packed))
    print_info("*** Packed list: {}".format(result[True]))
    print_info("*** Non-Packed list: {}".format(result[False]))

