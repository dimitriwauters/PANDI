import pickle
import os
import statistics

MALICIOUS_FUNCTIONS = ["GetProcAddress", "LoadLibrary", "Exitprocess", "GetModuleHandle", "VirtualAlloc",
                                     "VirtualFree", "GetModuleFilename", "CreateFile", "RegQueryValueEx", "MessageBox",
                                     "GetCommandLine", "VirtualProtect", "GetStartupInfo", "GetStdHandle", "RegOpenKeyEx"]
                                     
def read_file(path):
    result = {}
    try:
        with open(path, "rb") as f:
            result = pickle.load(f)
    except:
        return -1
    return result


def create_features():
    features = {"name":"",
                "write_execute_size":0,
                
                "max_total_entropy":0.0,
                "min_total_entropy":0.0,
                "delta_total_entropy":0.0,
                "mean_total_entropy":0.0,
                "median_total_entropy":0.0,
                "variance_total_entropy":0.0,
                "stdev_total_entropy":0.0,
                
                "max_oep_section_entropy":0.0,
                "min_oep_section_entropy":0.0,
                "delta_oep_section_entropy":0.0,
                "mean_oep_section_entropy":0.0,
                "median_oep_section_entropy":0.0,
                "variance_oep_section_entropy":0.0,
                "stdev_oep_section_entropy":0.0,
                
                "initial_iat_dll":0,
                "initial_iat_func":0,
                "initial_iat_malicious_func":0,
                
                "reconstructed_iat_dll":0,
                "reconstructed_iat_func":0,
                "reconstructed_iat_malicious_func":0,
                
                "initial_iat_called_generic_func":0,
                "initial_iat_called_malicious_func":0,
                "initial_iat_called_all_func":0,
                
                "dynamic_called_generic_func":0,
                "dynamic_called_malicious_func":0,
                "dynamic_called_all_func":0,
                
                "discovered_called_generic_func":0,
                "discovered_called_malicious_func":0,
                "discovered_called_all_func":0,
                
                "number_add_exec_permission":0,
                "number_add_write_permisison":0}
                
    for i in range(64):
        features[f"executed_byte_{i}"] = 0
        
    for fun in MALICIOUS_FUNCTIONS:
        features[fun] = 0

    return features
    
    
if __name__ == "__main__":
    # directory = "output/packed"
    directory = "output/not-packed"
    features = create_features()
    with open("features.csv", "w") as f:
        f.write(",".join(features.keys()))
        f.write("\n")
    for sample in os.listdir(directory):
         sample_dir = os.path.join(directory, sample)
         features = create_features()
         features["name"] = sample
         for analysis in os.listdir(sample_dir):
             analysis_dir = os.path.join(sample_dir, analysis)
             for filename in os.listdir(analysis_dir):
                 path = os.path.join(analysis_dir, filename)
                 result = read_file(path)
                 if result != -1:
                 
                     if filename == "sections_perms.pickle":
                         perm = result["section_perms_changed"] 
                         if len(perm) > 1:
                             name1 = "inital"
                             for name2 in perm:
                                 for section in name2:
                                     if perm[name1][section]["execute"]==False and perm[name2][section]["execute"]==True:
                                         features["number_add_exec_permission"] += 1
                                     if perm[name1][section]["write"]==False and perm[name2][section]["write"]==True:
                                         features["number_add_write_permisison"] += 1
                                 name1 = name2
                                 
                     elif filename == "syscalls.pickle":
                         features["initial_iat_dll"] = len(result["initial_iat"])
                         features["initial_iat_func"] = len(result["function_inital_iat"])
                         
                         features["reconstructed_iat_dll"] = len(result["dynamically_loaded_dll"]["before"]) + len(result["dynamically_loaded_dll"]["after"])
                         features["reconstructed_iat_func"] = len(result["GetProcAddress_functions"])
                         
                         features["initial_iat_called_generic_func"] = len(result["call_nbrs_generic"]["iat"])
                         features["initial_iat_called_malicious_func"] = len(result["call_nbrs_malicious"]["iat"])
                         features["initial_iat_called_all_func"] = len(result["call_nbrs_generic"]["iat"]) + len(result["call_nbrs_malicious"]["iat"])
                         
                         features["dynamic_called_generic_func"] = len(result["call_nbrs_generic"]["dynamic"])
                         features["dynamic_called_malicious_func"] = len(result["call_nbrs_malicious"]["dynamic"])
                         features["dynamic_called_all_func"] = len(result["call_nbrs_generic"]["dynamic"]) + len(result["call_nbrs_malicious"]["dynamic"])
                         
                         features["discovered_called_generic_func"] = len(result["call_nbrs_generic"]["discovered"])
                         features["discovered_called_malicious_func"] = len(result["call_nbrs_malicious"]["discovered"])
                         features["discovered_called_all_func"] = len(result["call_nbrs_generic"]["discovered"]) + len(result["call_nbrs_malicious"]["discovered"])
                         
                         for fun in MALICIOUS_FUNCTIONS:
                             if fun in result["function_inital_iat"]:
                                 features["initial_iat_malicious_func"] +=1
                             if fun in result["GetProcAddress_functions"]:
                                 features["reconstructed_iat_malicious_func"] += 1
                             if fun in result["call_nbrs_malicious"]["iat"]:
                                 features[fun] += result["call_nbrs_malicious"]["iat"][fun] 
                             if fun in result["call_nbrs_malicious"]["dynamic"]:
                                 features[fun] += result["call_nbrs_malicious"]["dynamic"][fun]
                             if fun in result["call_nbrs_malicious"]["discovered"]:
                                 features[fun] += result["call_nbrs_malicious"]["discovered"][fun]
                             
                         
                     elif filename == "memcheck.pickle":
                         features["write_execute_size"] = len(result["memory_write_exe_list"])
                         
                     elif filename == "first_bytes.pickle":
                         for i in range(len(result["executed_bytes_list"])):
                             features[f"executed_byte_{i}"] = result["executed_bytes_list"][i]
                             
                     elif filename == "TOTAL.pickle":
                         y = result["entropy"][1]
                         features["max_total_entropy"] = max(y)
                         features["min_total_entropy"] = min(y)
                         features["delta_total_entropy"] = max(y) - min(y)
                         if len(y) > 1:
                             features["mean_total_entropy"] = statistics.mean(y)
                             features["median_total_entropy"] = statistics.median(y)
                             features["variance_total_entropy"] = statistics.variance(y)
                             features["stdev_total_entropy"] = statistics.stdev(y)
                         
                     else:
                         if "has_inital_eop" in result and result["has_inital_eop"]:
                             y = result["entropy"][1]
                             features["max_oep_section_entropy"] = max(y)
                             features["min_oep_section_entropy"] = min(y)
                             features["delta_oep_section_entropy"] = max(y) - min(y)
                             if len(y) > 1:
                                 features["mean_oep_section_entropy"] = statistics.mean(y)
                                 features["median_oep_section_entropy"] = statistics.median(y)
                                 features["variance_oep_section_entropy"] = statistics.variance(y)
                                 features["stdev_oep_section_entropy"] = statistics.stdev(y)
                         
         with open("features.csv", "a") as f:
             f.write(",".join(str(x) for x in features.values()))
             f.write("\n")
                         
                     
