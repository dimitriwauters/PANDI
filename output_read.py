import matplotlib.pyplot as plt
import os
import sys
import statistics
import time
import pickle

OUTPUT_PATH = "output"

class Analysis:
    def __init__(self, name):
        self.sample_name = name
        self.directories = [x[0].split('/')[-1] for x in os.walk(f"{OUTPUT_PATH}/{name}")][1:]

    def analyse_entropy(self):
        sections = [x for _, _, x in os.walk(f"{OUTPUT_PATH}/{self.sample_name}/entropy")][0]
        for section_file in sections:
            section = section_file.split(".pickle")[0]
            with open(f"{OUTPUT_PATH}/{self.sample_name}/entropy/{section_file}", 'rb') as file:
                data = pickle.load(file)
                x = data["entropy"][0]
                y = data["entropy"][1]
                initial_eop = data["initial_eop"]
                has_initial_oep = data["has_inital_eop"]
                unpacked_eop = data["unpacked_eop"]
                has_unpacked_oep = data["has_unpacked_eop"]

                print(section, "----------------------------------------")
                print(f"Nbr of entropy points: {len(y)} ({len(x)})")
                print(f"Maximum Entropy: {max(y)}")
                print(f"Minimum Entropy: {min(y)}")
                print(f"Delta Maximum-Minimum: {max(y) - min(y)}")
                print(f"Mean Entropy: {statistics.mean(y)}")
                print(f"Median: {statistics.median(y)}")
                if len(y) > 1:
                    print(f"Variance: {statistics.variance(y)}")
                    print(f"Standard deviation: {statistics.stdev(y)}")
                if unpacked_eop != 0:
                    try:
                        pos = x.index(unpacked_eop)
                        print("=========================== AFTER UNPACKED ENTRY POINT")
                        print(f"Delta Maximum-Minimum: {max(y[pos:]) - min(y[pos:])}")
                        print(f"Mean Entropy: {statistics.mean(y[pos:])}")
                        print(f"Median: {statistics.median(y[pos:])}")
                        if len(y[pos:]) > 1:
                            print(f"Variance: {statistics.variance(y[pos:])}")
                            print(f"Standard deviation: {statistics.stdev(y[pos:])}")
                    except ValueError:
                        pass

                plt.plot(x, y, ':x')

                if initial_eop != 0:
                    plt.axvline(x=float("{:.2e}".format(int(initial_eop)).replace('+', '')), color='red', linestyle=':')
                if unpacked_eop != 0:
                    plt.axvline(x=float("{:.2e}".format(int(unpacked_eop)).replace('+', '')), color='green', linestyle=':')
                plt.title(f"{self.sample_name} ({section} - {'INIOEP' if has_initial_oep else 'NOT-INIOEP'} - {'UNPACKOEP' if has_unpacked_oep else 'NOT-UNPACKOEP'})")
                plt.xlabel('Nbr of executed instructions')
                plt.ylabel('Entropy')
                plt.xlim(None, None)
                plt.ylim(0, 8)
                plt.show()

    def analyse_syscalls(self):
        with open(f"{OUTPUT_PATH}/{self.sample_name}/syscalls/syscalls.pickle", 'rb') as file:
            data = pickle.load(file)
            print("Initial DLL in IAT:\n", ", ".join(data["initial_iat"]))
            print("Initial functions in IAT:\n", ", ".join(data["function_inital_iat"]))
            print("Dynamically loaded DLL:\n", data["dynamically_loaded_dll"])
            print("Functions discovered with GetProcAddress:\n", ", ".join(data["GetProcAddress_functions"]))
            print("Nbr call of genuine functions:\n", data["call_nbrs_generic"])
            print("Nbr call of malicious functions:\n", data["call_nbrs_malicious"])

    def analyse_first_bytes(self):
        with open(f"{OUTPUT_PATH}/{self.sample_name}/first_bytes/first_bytes.pickle", 'rb') as file:
            data = pickle.load(file)
            result = ""
            for elem in data["executed_bytes_list"]:
                result += str(hex(elem))[2:] + " "
            print("First bytes:\n", result)

    def analyse_time(self):
        with open(f"{OUTPUT_PATH}/{self.sample_name}/time/time.pickle", 'rb') as file:
            data = pickle.load(file)
            time_took = data["end"] - data["start"]
            print("Time took:", time_took, "seconds")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sample_name = sys.argv[1]
        analysis = Analysis(sample_name)
        if analysis.directories:
            with open(f"{OUTPUT_PATH}/{sample_name}/result.pickle", 'rb') as file:
                print("Is Packed ?", pickle.load(file)["is_packed"])
                print("Available analysis:", ",".join(analysis.directories))
                for directory in analysis.directories:
                    try:
                        print(directory.upper(), "================================================================")
                        getattr(analysis, f"analyse_{directory}")()
                    except AttributeError as e:
                        print(f"An error occured when trying to print '{directory}':\n{e}")
    else:
        print("You have to put in parameter the name of the process you want to analyse the output")