import json

if __name__ == "__main__":
    #with open("output.log", 'r') as file:
    with open("output.log", 'r') as file:
        is_packed = False
        text = file.read().split("\n")[-2]
        memory_write_list = json.loads(text[text.find("0m ")+3:])
        if len(memory_write_list) > 0:
            # Check if consecutive
            count = 0
            for elem in memory_write_list:
                addr = elem[1] % 134  # Modulo x86, the length of an instruction
                print(addr)
            is_packed = True

        print(is_packed)
