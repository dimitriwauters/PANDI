import os
import subprocess
import sys
import time
import pickle
import shutil
import re
import hashlib
from queue import Queue
from threading import Thread, Lock
from utility import write_debug_file, write_output_file

NUMBER_OF_PARALLEL_EXECUTION = int(os.getenv("panda_max_parallel_execution", default=4))
MAX_TRIES = 1

entropy_activated = os.getenv("panda_entropy", default=False) == "True"
memcheck_activated = os.getenv("panda_memcheck", default=False) == "True"
dll_activated = os.getenv("panda_dll", default=False) == "True"
dll_discover_activated = os.getenv("panda_dll_discover", default=False) == "True"
sections_activated = os.getenv("panda_section_perms", default=False) == "True"
first_bytes_activated = os.getenv("panda_first_bytes", default=False) == "True"
is_silent = os.getenv("panda_silent", default=False) == "True"
is_debug = os.getenv("panda_debug", default=False) == "True"
force_executable = os.getenv("panda_executable", default=None)
timeout = int(os.getenv("panda_timeout", default=7200))
if force_executable == "None":
    force_executable = None

result = {True: [], False: []}
thread_lock = Lock()
result_lock = Lock()

class ProcessSample:
    def __init__(self, sample_path):
        self.malware_sample_path = os.path.dirname(sample_path)
        self.malware_sample = os.path.basename(sample_path)
        self.malware_hash = hashlib.sha256(self.malware_sample.encode()).hexdigest()
        self.start_time, self.end_time, self.time_took = None, None, None
        self.need_ml = False
        self.is_packed = False

    def launch(self):
        for i in range(MAX_TRIES):
            has_failed = False
            with thread_lock:  # Blocking state when running VM, only one VM can run at anytime
                print_info(f"  -- Starting processing file '{self.malware_sample_path}/{self.malware_sample}'")
                subprocess.run(["genisoimage", "-max-iso9660-filenames", "-RJ", "-o", "/payload.iso"] + [f"{self.malware_sample_path}/{self.malware_sample}", "/dll"], capture_output=True)
                has_failed = has_failed + self.__run_subprocess("run_panda", [self.malware_sample])
            if not has_failed:
                time.sleep(2)
                if dll_discover_activated:
                    has_failed = has_failed + self.__run_subprocess("discover_dlls", [self.malware_hash])
                if not has_failed:
                    time.sleep(2)
                    self.start_time = time.time()
                    has_failed = has_failed + self.__run_subprocess("read_replay", [self.malware_sample_path, self.malware_sample], timeout)
                    if not has_failed:
                        self.end_time = time.time()
                        self.time_took = self.end_time - self.start_time
                        return True
            print_info(f"  !! An error occured when processing file '{self.malware_sample_path}/{self.malware_sample}': try {i+1} of {MAX_TRIES}")
        return False

    def __run_subprocess(self, filename, parameters=[], timeout = None):
        try:
            output = subprocess.run(["python3", f"/addon/{filename}.py"] + parameters, timeout = timeout, capture_output=True, check=True)
            if is_debug:
                write_debug_file(self.malware_sample, filename, output.stdout.decode())
            return False
        except subprocess.CalledProcessError as e:
            if is_debug:
                write_debug_file(self.malware_sample, filename, e.stderr.decode())
            return True
        except subprocess.TimeoutExpired as e:
            self.get_result()
            self.clean()
            return True

    def get_result(self):
        panda_output_dict = None
        error = False
        if os.path.isfile(f"{self.malware_hash}_result.pickle"):
            with open(f"{self.malware_hash}_result.pickle", "rb") as f:
                panda_output_dict = pickle.load(f)
        if panda_output_dict:
            if memcheck_activated:
                self.memcheck(panda_output_dict)
            if entropy_activated:
                self.entropy(panda_output_dict)
                self.need_ml = True
            if dll_activated:
                self.dll(panda_output_dict)
                self.need_ml = True
            if sections_activated:
                self.sections(panda_output_dict)
                self.need_ml = True
            if first_bytes_activated:
                self.first_bytes(panda_output_dict)
                self.need_ml = True
            if self.need_ml:
                self.execute_machine_learning()
        else:
            error = True
        print_info(f"  ** The result of the analysis of {self.malware_sample} is: {'PACKED' if self.is_packed else 'NOT-PACKED'} (Took {self.time_took} seconds to analyse)")
        write_output_file(self.malware_sample, "time", "time", {"start": self.start_time, "end": self.end_time})
        write_output_file(self.malware_sample, "", "result", {"is_packed": self.is_packed, "error_during_analysis": error})
        shutil.move(f"/replay/{self.malware_hash}_screenshot", f"/output/{re.split('.exe', self.malware_sample, flags=re.IGNORECASE)[0]}/screenshot")
        return self.is_packed

    def clean(self):
        try:
            os.remove(f"/replay/{self.malware_hash}-rr-nondet.log")
            os.remove(f"/replay/{self.malware_hash}-rr-snp")
            os.remove(f"{self.malware_hash}_result.pickle")
        except FileNotFoundError:
            pass

    # ==================================================================================================================

    def memcheck(self, panda_output_dict):
        memory_write_list = panda_output_dict["memory_write_exe_list"]
        if len(memory_write_list) > 0:
            # TODO: Check if consecutive
            """count = 0
            for elem in memory_write_list:
                addr = elem[1] % 134  # Modulo x86, the length of an instruction
                print(addr)"""
            self.is_packed = True
        write_output_file(self.malware_sample, "memcheck", "memcheck", {"memory_write_exe_list": memory_write_list})

    def entropy(self, panda_output_dict):
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
            write_output_file(self.malware_sample, "entropy", header_name, file_dict)

    def dll(self, panda_output_dict):
        file_dict = {"initial_iat": panda_output_dict["dll_inital_iat"],
                     "dynamically_loaded_dll": panda_output_dict["dll_dynamically_loaded_dll"],
                     "call_nbrs_generic": panda_output_dict["dll_call_nbrs_generic"],
                     "call_nbrs_malicious": panda_output_dict["dll_call_nbrs_malicious"],
                     "GetProcAddress_functions": panda_output_dict["dll_GetProcAddress_returns"],
                     "function_inital_iat": panda_output_dict["function_inital_iat"]}
        write_output_file(self.malware_sample, "syscalls", "syscalls", file_dict)

    def sections(self, panda_output_dict):
        file_dict = {"section_perms_changed": panda_output_dict["section_perms_changed"]}
        write_output_file(self.malware_sample, "sections_perms", "sections_perms", file_dict)

    def first_bytes(self, panda_output_dict):
        file_dict = {"executed_bytes_list": panda_output_dict["executed_bytes_list"],
                     "initial_EP": panda_output_dict["initial_EP"], "real_EP": panda_output_dict["real_EP"]}
        write_output_file(self.malware_sample, "first_bytes", "first_bytes", file_dict)

    def execute_machine_learning(self):
        # TODO: Implement
        pass
        """subprocess.run(["python3", "create_csv.py", self.malware_sample_path])
        with open("features.csv", 'r') as f:
            pass"""

def print_info(text):
    if not is_silent:
        print(text, flush=True)

def process_sample(q):
    while True:
        sample_path = q.get()
        if sample_path is None:
            break
        process = ProcessSample(sample_path)
        if process.launch():
            is_packed = process.get_result()
            with result_lock:
                result[is_packed].append(process.malware_sample)
            process.clean()
        q.task_done()


if __name__ == "__main__":
    if is_debug:
        print_info("DEBUGGING ACTIVATED")
    if force_executable is not None:
        print_info(f"MALWARE ANALYSED: {force_executable}")

    print_info("++ Launching")
    if force_executable is None:
        already_analysed = [name.lower().split('.exe')[0] for name in os.listdir("/output")]
        files_to_analyse = [os.path.join(root, name) for root, dirs, files in os.walk("/payload") for name in files if name.lower().endswith(".exe") and name not in already_analysed]
    else:
        files_to_analyse = [force_executable]
    q = Queue(len(files_to_analyse))
    NUMBER_OF_PARALLEL_EXECUTION = min(len(files_to_analyse), NUMBER_OF_PARALLEL_EXECUTION)
    for _ in range(NUMBER_OF_PARALLEL_EXECUTION):
        worker = Thread(target=process_sample, args=(q,))
        worker.start()
    for sample in files_to_analyse:
        q.put(sample)
    q.join()

    print_info("++ Finished")
    total_analyzed = len(result[True]) + len(result[False])
    percent_packed, percent_not_packed = 0, 0
    if total_analyzed > 0:
        percent_packed = len(result[True])/total_analyzed
        percent_not_packed = len(result[False])/total_analyzed
        print_info(f"*** % packed: {percent_packed}\n*** % non-packed: {percent_not_packed}")
        print_info(f"*** Packed list: {result[True]}")
        print_info(f"*** Non-Packed list: {result[False]}")
        sys.exit(0)
    else:
        print_info("*** No sample was left to analyse !")
        sys.exit(1)
