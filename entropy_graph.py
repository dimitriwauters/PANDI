import matplotlib.pyplot as plt
import json
import sys
import statistics
import pickle

if __name__ == "__main__":
    if len(sys.argv) > 1:
        name = sys.argv[1]
        section = sys.argv[2]
        is_packed = sys.argv[3] == "True"

        with open(f"./output/{'packed' if is_packed else 'not-packed'}/{name}/entropy/{section}.pickle", 'rb') as file:
            data = pickle.load(file)
            x = data["entropy"][0]
            y = data["entropy"][1]
            initial_eop = data["initial_oep"]
            has_initial_oep = data["has_inital_eop"]
            unpacked_eop = data["unpacked_oep"]
            has_unpacked_oep = data["has_unpacked_eop"]

        print(f"Nbr of entropy points: {len(y)} ({len(x)})")
        print(f"Maximum Entropy: {max(y)}")
        print(f"Minimum Entropy: {min(y)}")
        print(f"Delta Maximum-Minimum: {max(y) - min(y)}")
        print(f"Mean Entropy: {statistics.mean(y)}")
        print(f"Median: {statistics.median(y)}")
        print(f"Variance: {statistics.variance(y)}")
        print(f"Standard deviation: {statistics.stdev(y)}")
        if unpacked_eop != 0:
            try:
                pos = x.index(unpacked_eop)
                print("=========================== AFTER UNPACKED ENTRY POINT")
                print(f"Delta Maximum-Minimum: {max(y[pos:]) - min(y[pos:])}")
                print(f"Mean Entropy: {statistics.mean(y[pos:])}")
                print(f"Median: {statistics.median(y[pos:])}")
                print(f"Variance: {statistics.variance(y[pos:])}")
                print(f"Standard deviation: {statistics.stdev(y[pos:])}")
            except ValueError:
                pass

        plt.plot(x, y, ':x')

        if initial_eop != 0:
            plt.axvline(x=float("{:.2e}".format(int(initial_eop)).replace('+', '')), color='red', linestyle=':')
        if unpacked_eop != 0:
            plt.axvline(x=float("{:.2e}".format(int(unpacked_eop)).replace('+', '')), color='green', linestyle=':')
        plt.title(f"{name}.exe ({section} - {'INIOEP' if has_initial_oep else 'NOT-INIOEP'} - {'UNPACKOEP' if has_unpacked_oep else 'NOT-UNPACKOEP'})")
        plt.xlabel('Nbr of executed instructions')
        plt.ylabel('Entropy')
        plt.xlim(None, None)
        plt.ylim(0, 8)
        plt.show()
