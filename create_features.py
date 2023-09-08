import pickle
import os
import statistics
import sys

MALICIOUS_FUNCTIONS = ["GetProcAddress", "LoadLibrary", "Exitprocess", "GetModuleHandle", "VirtualAlloc",
                       "VirtualFree", "GetModuleFilename", "CreateFile", "RegQueryValueEx", "MessageBox",
                       "GetCommandLine", "VirtualProtect", "GetStartupInfo", "GetStdHandle", "RegOpenKeyEx"]


class Features:
    def __init__(self, output_path):
        self.output_path = output_path
        self.features_struct = []

    @staticmethod
    def _generate_features_structure():
        features = {"name": "",
                    "write_execute_size": -1,

                    "number_total_entropy": -1,
                    "max_total_entropy": -1.0,
                    "min_total_entropy": -1.0,
                    "delta_total_entropy": -1.0,
                    "mean_total_entropy": -1.0,
                    "median_total_entropy": -1.0,
                    "variance_total_entropy": -1.0,
                    "stdev_total_entropy": -1.0,

                    "number_oep_section_entropy": -1,
                    "max_oep_section_entropy": -1.0,
                    "min_oep_section_entropy": -1.0,
                    "delta_oep_section_entropy": -1.0,
                    "mean_oep_section_entropy": -1.0,
                    "median_oep_section_entropy": -1.0,
                    "variance_oep_section_entropy": -1.0,
                    "stdev_oep_section_entropy": -1.0,

                    "initial_iat_dll": -1,
                    "initial_iat_func": -1,
                    "initial_iat_malicious_func": 0,

                    "reconstructed_iat_dll": -1,
                    "reconstructed_iat_func": -1,
                    "reconstructed_iat_malicious_func": 0,

                    "initial_iat_called_generic_func": -1,
                    "initial_iat_called_malicious_func": -1,
                    "initial_iat_called_all_func": -1,

                    "dynamic_called_generic_func": -1,
                    "dynamic_called_malicious_func": -1,
                    "dynamic_called_all_func": -1,

                    "discovered_called_generic_func": -1,
                    "discovered_called_malicious_func": -1,
                    "discovered_called_all_func": -1,

                    "number_add_exec_permission": -1,
                    "number_add_write_permisison": -1}
        for i in range(64):
            features[f"executed_byte_{i}"] = -1

        for fun in MALICIOUS_FUNCTIONS:
            features[fun] = 0

        return features

    def _handle_memcheck(self, s, f):
        result = read_file(f"{self.output_path}/{s}/memcheck/memcheck.pickle")
        f["write_execute_size"] = len(result["memory_write_exe_list"])
        return True

    def _handle_sections_perms(self, s, f):
        result = read_file(f"{self.output_path}/{s}/sections_perms/sections_perms.pickle")
        permissions = result["section_perms_changed"]
        if len(permissions) > 1:
            last_known_change = "inital"
            for current in permissions:
                for section in current:
                    if not permissions[last_known_change][section]["execute"] and permissions[current][section]["execute"]:
                        f["number_add_exec_permission"] += 1
                    if not permissions[last_known_change][section]["write"] and permissions[current][section]["write"]:
                        f["number_add_write_permisison"] += 1
                last_known_change = current

    def _handle_first_bytes(self, s, f):
        result = read_file(f"{self.output_path}/{s}/first_bytes/first_bytes.pickle")
        for i in range(len(result["executed_bytes_list"])):
            f[f"executed_byte_{i}"] = result["executed_bytes_list"][i]
        return len(result["executed_bytes_list"]) > 0

    def _handle_syscalls(self, s, f):
        result = read_file(f"{self.output_path}/{s}/syscalls/syscalls.pickle")
        f["initial_iat_dll"] = len(result["initial_iat"])
        f["initial_iat_func"] = len(result["function_inital_iat"])

        f["reconstructed_iat_dll"] = len(result["dynamically_loaded_dll"]["before"]) + len(result["dynamically_loaded_dll"]["after"])
        f["reconstructed_iat_func"] = len(result["GetProcAddress_functions"])

        f["initial_iat_called_generic_func"] = len(result["call_nbrs_generic"]["iat"])
        f["initial_iat_called_malicious_func"] = len(result["call_nbrs_malicious"]["iat"])
        f["initial_iat_called_all_func"] = len(result["call_nbrs_generic"]["iat"]) + len(result["call_nbrs_malicious"]["iat"])

        f["dynamic_called_generic_func"] = len(result["call_nbrs_generic"]["dynamic"])
        f["dynamic_called_malicious_func"] = len(result["call_nbrs_malicious"]["dynamic"])
        f["dynamic_called_all_func"] = len(result["call_nbrs_generic"]["dynamic"]) + len(result["call_nbrs_malicious"]["dynamic"])

        f["discovered_called_generic_func"] = len(result["call_nbrs_generic"]["discovered"])
        f["discovered_called_malicious_func"] = len(result["call_nbrs_malicious"]["discovered"])
        f["discovered_called_all_func"] = len(result["call_nbrs_generic"]["discovered"]) + len(result["call_nbrs_malicious"]["discovered"])

        for fun in MALICIOUS_FUNCTIONS:
            if fun in result["function_inital_iat"]:
                f["initial_iat_malicious_func"] += 1
            if fun in result["GetProcAddress_functions"]:
                f["reconstructed_iat_malicious_func"] += 1
            if fun in result["call_nbrs_malicious"]["iat"]:
                f[fun] += result["call_nbrs_malicious"]["iat"][fun]
            if fun in result["call_nbrs_malicious"]["dynamic"]:
                f[fun] += result["call_nbrs_malicious"]["dynamic"][fun]
            if fun in result["call_nbrs_malicious"]["discovered"]:
                f[fun] += result["call_nbrs_malicious"]["discovered"][fun]

    def _handle_entropy(self, s, f):
        sections = [item for item in os.listdir(f"{self.output_path}/{s}/entropy") if os.path.isfile(os.path.join(f"{self.output_path}/{s}/entropy", item))]
        for section in sections:
            result = read_file(f"{self.output_path}/{s}/entropy/{section}")
            if "TOTAL" not in section:
                if "has_inital_eop" in result and result["has_inital_eop"]:
                    y = result["entropy"][1]
                    f["number_oep_section_entropy"] = len(y)
                    f["max_oep_section_entropy"] = max(y)
                    f["min_oep_section_entropy"] = min(y)
                    f["delta_oep_section_entropy"] = max(y) - min(y)
                    if len(y) > 1:
                        f["mean_oep_section_entropy"] = statistics.mean(y)
                        f["median_oep_section_entropy"] = statistics.median(y)
                        f["variance_oep_section_entropy"] = statistics.variance(y)
                        f["stdev_oep_section_entropy"] = statistics.stdev(y)
            else:
                y = result["entropy"][1]
                f["number_total_entropy"] = len(y)
                f["max_total_entropy"] = max(y)
                f["min_total_entropy"] = min(y)
                f["delta_total_entropy"] = max(y) - min(y)
                if len(y) > 1:
                    f["mean_total_entropy"] = statistics.mean(y)
                    f["median_total_entropy"] = statistics.median(y)
                    f["variance_total_entropy"] = statistics.variance(y)
                    f["stdev_total_entropy"] = statistics.stdev(y)

    def _generate_values(self):
        samples = [item for item in os.listdir(self.output_path) if os.path.isdir(os.path.join(self.output_path, item))]
        for sample in samples:
            features = self._generate_features_structure()
            features["name"] = sample
            options = [item for item in os.listdir(f"{self.output_path}/{sample}") if os.path.isdir(os.path.join(f"{self.output_path}/{sample}", item))]
            for option in options:
                if not getattr(self, f"_handle_{option}")(sample, features):
                    continue
            self.features_struct.append(features)

    def generate_csv(self):
        with open("features/features_" + directory + ".csv", "a") as f:
            f.write(",".join(self.features_struct[0].keys()))
            f.write("\n")
            for features in self.features_struct:
                f.write(",".join(str(x) for x in features.values()))
                f.write("\n")

    def generate_list(self):
        return self.features_struct


def read_file(path):
    try:
        with open(path, "rb") as f:
            result = pickle.load(f)
            return result
    except FileNotFoundError:
        return -1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        directory = "./output"
    else:
        directory = sys.argv[1]
    Features(directory).generate_csv()
