import json

if __name__ == "__main__":
    with open("output.log", 'r') as file:
        is_packed = False
        #text = file.read().split("\n")[-2]
        #memory_write_list = json.loads(text[text.find("0m ")+3:])
        memory_write_list = json.loads(file.read())
        if len(memory_write_list) > 0:
            # Check if consecutive
            count = 0
            for elem in memory_write_list:
                addr = int(elem) % 0x1000  # Modulo x86 length of instructions
                print(f"{elem} | {addr}")
            is_packed = True
        print(is_packed)
