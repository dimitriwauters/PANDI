import os
import subprocess
import json


if __name__ == "__main__":
    print("++ Launching")
    result = {True: [], False: []}
    for malware_sample in os.listdir("/payload"):
        is_packed = False
        memory_write_list = None
        while memory_write_list is None:
            print("  -- Processing file '{}'".format(malware_sample), flush=True)
            print("    -- Creating ISO", flush=True)
            subprocess.check_call(["genisoimage", "-max-iso9660-filenames", "-RJ", "-o", "payload.iso", "/payload/{}".format(malware_sample)], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            print("    -- Running PANDA-RE", flush=True)
            panda_run_output = subprocess.check_output(["python3", "/addon/run_panda.py", malware_sample], stderr=subprocess.PIPE).decode()
            print(panda_run_output[0], panda_run_output[-1])
            memory_write_list = panda_run_output.split("\n")[-2]
            if memory_write_list == "ERROR":
                print("  -- An error occurred, retrying...")
            else:
                memory_write_list = json.loads(memory_write_list)
                print(type(memory_write_list))
                print(len(memory_write_list))
                if len(memory_write_list) > 0:
                    # Check if consecutive
                    count = 0
                    for elem in memory_write_list:
                        addr = elem[1] % 134  # Modulo x86, the length of an instruction
                        print(addr)
                    is_packed = True
        result[is_packed].append(malware_sample)
    print("++ Finished", flush=True)

    # TODO: Show results
    total_analyzed = len(result[True])+len(result[False])
    percent_packed = len(result[True])/total_analyzed
    percent_not_packed = len(result[False])/total_analyzed
    print("*** % packed: {}\n*** % non-packed: {}".format(percent_packed, percent_not_packed), flush=True)

