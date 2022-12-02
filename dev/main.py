from run_panda import runpd
import os
import subprocess
import json
from multiprocessing import Queue, Process


if __name__ == "__main__":
    print("++ Launching")
    result = {True: [], False: []}
    for malware_sample in os.listdir("/payload"):
        is_packed = False
        memory_write_list = None
        while memory_write_list is None:
            print("  -- Processing file '{}'".format(malware_sample), flush=True)
            print("    -- Creating ISO", flush=True)
            subprocess.check_call(["genisoimage", "-max-iso9660-filenames", "-RJ", "-o", "payload.iso", "/payload/{}".format(malware_sample)])
            print("    -- Running PANDA-RE", flush=True)

            """queue = Queue()
            process = Process(target=runpd, args=(queue, malware_sample,))
            process.start()
            memory_write_list = queue.get()
            process.join()"""

            memory_write_list = subprocess.check_output(["python3", "/addon/run_panda.py", malware_sample]).decode()#.split("\n")[-1]
            if memory_write_list is None:
                print("  -- An error occurred, retrying...")
            else:
                #memory_write_list = json.loads(memory_write_list)
                print(type(memory_write_list))
                if len(memory_write_list) > 0:
                    # TODO: Check memory consecutive
                    is_packed = True
        result[is_packed].append(malware_sample)
    print("++ Finished", flush=True)

    # TODO: Show results
    total_analyzed = len(result[True])+len(result[False])
    percent_packed = len(result[True])/total_analyzed
    percent_not_packed = len(result[False])/total_analyzed
    print("*** % packed: {}\n*** % non-packed: {}".format(percent_packed, percent_not_packed), flush=True)

