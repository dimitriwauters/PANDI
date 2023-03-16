import matplotlib.pyplot as plt
import json
import sys
import statistics

if __name__ == "__main__":
    if len(sys.argv) > 1:
        name = sys.argv[1]
        section = sys.argv[2]
        is_packed = sys.argv[3] == "True"

        with open(f"./output/{'packed' if is_packed else 'not-packed'}/{name}/{section}_entropy.txt", 'r') as file:
            x = json.loads(file.readline().replace("'", ""))
            y = json.loads(file.readline())
            initial_eop = file.readline().split('-')
            has_initial_oep = initial_eop[0] == "True"
            oep_initial_instr = initial_eop[1]
            unpacked_eop = file.readline().split('-')
            has_unpacked_oep = unpacked_eop[0] == "True"
            oep_unpacked_instr = unpacked_eop[1]

        print(f"Nbr of entropy points: {len(y)} ({len(x)})")
        print(f"Maximum Entropy: {max(y)}")
        print(f"Minimum Entropy: {min(y)}")
        print(f"Delta Maximum-Minimum: {max(y) - min(y)}")
        print(f"Mean Entropy: {statistics.mean(y)}")
        print(f"Median: {statistics.median(y)}")
        print(f"Variance: {statistics.variance(y)}")
        print(f"Standard deviation: {statistics.stdev(y)}")
        if oep_unpacked_instr != "0":
            try:
                pos = x.index(int(oep_unpacked_instr))
                print("=========================== AFTER UNPACKED ENTRY POINT")
                print(f"Delta Maximum-Minimum: {max(y[pos:]) - min(y[pos:])}")
                print(f"Mean Entropy: {statistics.mean(y[pos:])}")
                print(f"Median: {statistics.median(y[pos:])}")
                print(f"Variance: {statistics.variance(y[pos:])}")
                print(f"Standard deviation: {statistics.stdev(y[pos:])}")
            except ValueError:
                pass

        plt.plot(x, y, ':x')

        if oep_initial_instr != "0":
            plt.axvline(x=float("{:.2e}".format(int(oep_initial_instr)).replace('+', '')), color='red', linestyle=':')
        if oep_unpacked_instr != "0":
            plt.axvline(x=float("{:.2e}".format(int(oep_unpacked_instr)).replace('+', '')), color='green', linestyle=':')
        plt.title(f"{name}.exe ({section} - {'INIOEP' if has_initial_oep else 'NOT-INIOEP'} - {'UNPACKOEP' if has_unpacked_oep else 'NOT-UNPACKOEP'})")
        plt.xlabel('Nbr of executed instructions')
        plt.ylabel('Entropy')
        plt.xlim(None, None)
        plt.ylim(0, 8)
        plt.show()
