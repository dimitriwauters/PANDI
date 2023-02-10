import os
import subprocess
import json
import sys
import time

DEBUG = False
FORCE_MALWARE = None
MAX_TRIES = 3


def write_debug_file(file_name, process_name, process_output):
    with open(f"/debug/{file_name.split('.exe')[0]}_{process_name}_exec.txt", "w") as file:
        file.write(process_output.decode())


if __name__ == "__main__":
    if len(sys.argv) > 1:
        parameters = sys.argv[1].split(",")
        for parameter in parameters:
            if "debug" in parameter:
                DEBUG = bool(parameter.split("=")[1])
                if DEBUG:
                    print("DEBUGGING ACTIVATED")
            elif "executable" in parameter:
                FORCE_MALWARE = [parameter.split("=")[1]]
                if FORCE_MALWARE is not None:
                    print(f"MALWARE ANALYSED: {FORCE_MALWARE}")

    print("++ Launching")
    result = {True: [], False: []}
    if FORCE_MALWARE is None:
        files_to_analyse = os.listdir("/payload")
    else:
        files_to_analyse = FORCE_MALWARE
    for malware_sample in files_to_analyse:
        if ".exe" in malware_sample:
            is_packed = False
            memory_write_list = None
            print(f"  -- Processing file '{malware_sample}'", flush=True)
            for i in range(MAX_TRIES):
                panda_run_output, panda_replay_output = None, None
                print("    -- Creating ISO", flush=True)
                subprocess.check_call(["genisoimage", "-max-iso9660-filenames", "-RJ", "-o", "payload.iso", f"/payload/{malware_sample}"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                try:
                    print("    -- Running PANDA", flush=True)
                    panda_run_output = subprocess.check_output(["python3", "/addon/run_panda.py", malware_sample], stderr=subprocess.PIPE)
                    time.sleep(2)
                    print("    -- Analysing PANDA output (might take a while)", flush=True)
                    panda_replay_output = subprocess.check_output(["python3", "/addon/read_replay.py", f"{'--debug' if DEBUG else ''}"], stderr=subprocess.PIPE)
                    if DEBUG:
                        write_debug_file(malware_sample, "run_panda", panda_run_output)
                        write_debug_file(malware_sample, "read_replay", panda_replay_output)
                except subprocess.CalledProcessError as e:
                    print("    !! An error occurred when trying to execute PANDA:")
                    print(e.stderr.decode())
                    sys.exit(e.returncode)

                memory_write_list = panda_replay_output.decode().split("\n")[-2]
                if memory_write_list != "ERROR":
                    break
                else:
                    print(f"  !! An error occurred when recovering the output of PANDA, retrying... ({i+1} of {MAX_TRIES})\n")

            memory_write_list = json.loads(memory_write_list.replace("'", "\""))
            if len(memory_write_list) > 0:
                # TODO: Check if consecutive
                """count = 0
                for elem in memory_write_list:
                    addr = elem[1] % 134  # Modulo x86, the length of an instruction
                    print(addr)"""
                is_packed = True
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

