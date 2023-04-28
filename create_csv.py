import pickle
import os
import statistics

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
                "write_execute":False,
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
                "initial_iat_called_generic_func":0,
                "initial_iat_called_malicious_func":0,
                "initial_iat_called_all_func":0,
                
                "reconstructed_iat_dll":0,
                "reconstructed_iat_func":0,
                "reconstructed_iat_called_generic_func":0,
                "reconstructed_iat_called_malicious_func":0,
                "reconstructed_iat_called_all_func":0,
                
                "add_exec_permission":False,
                "number_add_exec_permission":0,
                "add_write_permisison":False,
                "number_add_write_permisison":0,}
    for i in range(64):
        features[f"executed_byte_{i}"] = 0     
    with open("features.csv", "w") as f:
        f.write(",".join(features.keys()))
        f.write("\n")
    return features
    
    
if __name__ == "__main__":
    directory = "output/not-packed"
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
                                         features["add_exec_permission"] = True
                                         features["number_add_exec_permission"] += 1
                                     if perm[name1][section]["write"]==False and perm[name2][section]["write"]==True:
                                         features["add_write_permisison"] = True
                                         features["number_add_write_permisison"] += 1
                                 name1 = name2
                                 
                     elif filename == "syscalls.pickle":
                         features["initial_iat_dll"] = len(result["initial_iat"])
                         features["initial_iat_func"] = len(result["function_inital_iat"])
                         features["initial_iat_called_generic_func"] = len(result["call_nbrs_generic"]["iat"])
                         features["initial_iat_called_malicious_func"] = len(result["call_nbrs_malicious"]["iat"])
                         features["initial_iat_called_all_func"] = features["initial_iat_called_malicious_func"] + features["initial_iat_called_generic_func"]
                         features["reconstructed_iat_dll"] = len(result["dynamically_loaded_dll"]["before"]) + len(result["dynamically_loaded_dll"]["after"])
                         features["reconstructed_iat_func"] = len(result["GetProcAddress_functions"])
                         features["reconstructed_iat_called_generic_func"] = len(result["call_nbrs_generic"]["dynamic"]) + len(result["call_nbrs_generic"]["discovered"])
                         features["reconstructed_iat_called_malicious_func"] = len(result["call_nbrs_malicious"]["dynamic"]) + len(result["call_nbrs_malicious"]["discovered"])
                         features["reconstructed_iat_called_all_func"] = features["reconstructed_iat_called_malicious_func"] + features["reconstructed_iat_called_generic_func"]
                         
                     elif filename == "memcheck.pickle":
                         features["write_execute_size"] = len(result[memory_write_exe_list])
                         features["write_execute"] = len(result[memory_write_exe_list]) != 0
                         
                     elif filename == "first_bytes.pickle":
                         for i in range(len(result["executed_bytes_list"])):
                             features[f"executed_byte_{i}"] = result["executed_bytes_list"][i]
                             
                     elif filename == "total_entropy.pickle":
                         y = result["entropy"][1]
                         features["max_total_entropy"] = max(y)
                         features["min_total_entropy"] = min(y)
                         features["delta_total_entropy"] = max(y) - min(y)
                         features["mean_total_entropy"] = statistics.mean(y)
                         features["median_total_entropy"] = statistics.median(y)
                         features["variance_total_entropy"] = statistics.variance(y)
                         features["stdev_total_entropy"] = statistics.stdev(y)
                         
                     else:
                         if result["has_inital_eop"]:
                             y = result["entropy"][1]
                             features["max_oep_section_entropy"] = max(y)
                             features["min_oep_section_entropy"] = min(y)
                             features["delta_oep_section_entropy"] = max(y) - min(y)
                             features["mean_oep_section_entropy"] = statistics.mean(y)
                             features["median_oep_section_entropy"] = statistics.median(y)
                             features["variance_oep_section_entropy"] = statistics.variance(y)
                             features["stdev_oep_section_entropy"] = statistics.stdev(y)
                         
         with open("features.csv", "a") as f:
             f.write(",".join(str(x) for x in features.values()))
             f.write("\n")
                         
                     
