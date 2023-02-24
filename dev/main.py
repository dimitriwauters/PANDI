import os
import subprocess
import json
import sys
import time
from argparse import ArgumentParser
from utility import write_debug_file

DEBUG = False
FORCE_MALWARE = None
MAX_TRIES = 3

entropy_activated = True
memcheck_activated = False


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--silent", action='store_true', help="only print the result in JSON format", default=False)
    parser.add_argument("--debug", action='store_true', help="activate verbose mode", default=False)
    parser.add_argument("--executable", type=str, help="force the selection of one software", default=None)
    args = parser.parse_args()

    DEBUG = args.debug
    if DEBUG:
        print("DEBUGGING ACTIVATED")
    FORCE_MALWARE = args.executable
    if FORCE_MALWARE is not None:
        print(f"MALWARE ANALYSED: {FORCE_MALWARE}")

    print("++ Launching")
    result = {True: [], False: []}
    if FORCE_MALWARE is None:
        files_to_analyse = os.listdir("/payload")
    else:
        files_to_analyse = [FORCE_MALWARE]
    for malware_sample in files_to_analyse:
        if ".exe" in malware_sample:
            is_packed = False
            panda_output = None
            print(f"  -- Processing file '{malware_sample}'", flush=True)
            for i in range(MAX_TRIES):
                panda_run_output, panda_replay_output = None, None
                print("    -- Creating ISO", flush=True)
                subprocess.run(["genisoimage", "-max-iso9660-filenames", "-RJ", "-o", "payload.iso", f"/payload/{malware_sample}"], capture_output=True)
                try:
                    print("    -- Running PANDA", flush=True)
                    panda_run_output = subprocess.run(["python3", "/addon/run_panda.py", malware_sample], capture_output=True)
                    time.sleep(2)
                    print("    -- Analysing PANDA output (might take a while)", flush=True)
                    replay_cmd = f"python3 /addon/read_replay.py {'--debug' if DEBUG else ''} " \
                                 f"{'--memcheck' if memcheck_activated else ''} " \
                                 f"{'--entropy' if entropy_activated else ''}"
                    panda_replay_output = subprocess.run(replay_cmd.strip().split(), capture_output=True)
                    if DEBUG:
                        write_debug_file(malware_sample, "run_panda", panda_run_output.stdout.decode())
                        write_debug_file(malware_sample, "read_replay", panda_replay_output.stdout.decode())
                except subprocess.CalledProcessError as e:
                    print("    !! An error occurred when trying to execute PANDA:")
                    print(e.stderr.decode())
                    sys.exit(e.returncode)

                with open("replay_result.txt", "r") as file:
                    panda_output = file.read()
                if panda_output != "ERROR":
                    break
                else:
                    print(f"  !! An error occurred when recovering the output of PANDA, retrying... ({i+1} of {MAX_TRIES})\n")

            if panda_output:
                panda_output_dict = json.loads(panda_output.replace("'", "\""))
                if memcheck_activated:
                    memory_write_list = panda_output_dict["memory_write_exe_list"]
                    if len(memory_write_list) > 0:
                        # TODO: Check if consecutive
                        """count = 0
                        for elem in memory_write_list:
                            addr = elem[1] % 134  # Modulo x86, the length of an instruction
                            print(addr)"""
                        is_packed = True
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
                        write_debug_file(malware_sample, f"{header_name}_entropy", f"{entropy_val[header_name][0]}\n{entropy_val[header_name][1]}\n{has_initial_eop}-{entropy_initial_oep[1]}\n{has_unpacked_eop}-{entropy_unpacked_oep[1]}")
                result[is_packed].append(malware_sample)
                print("      -- The result of the analysis is: {}\n".format("PACKED" if is_packed else "NOT-PACKED"))
    print("++ Finished", flush=True)

    # Show results
    total_analyzed = len(result[True])+len(result[False])
    percent_packed = len(result[True])/total_analyzed
    percent_not_packed = len(result[False])/total_analyzed
    print("*** % packed: {}\n*** % non-packed: {}".format(percent_packed, percent_not_packed), flush=True)
    print("*** Packed list: {}".format(result[True]))
    print("*** Non-Packed list: {}".format(result[False]))

