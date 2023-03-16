import json
import pefile

if __name__ == "__main__":
    """with open("output.log", 'r') as file:
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
        print(is_packed)"""
    #pe = pefile.PE("docker/dev/test.exe")
    input = b'\xfd\xff\xe9\xe3`\xfe\xff\x90\x90\x90\x90\x90\xb8>\x11\x00\x00\xba\x00\x03\xfe\x7f\xff\x12\xc2\x0c\x00\x90\x90\x90\x90\x90j\x0ch\xc8k\x94u\xe8\xacX\xfe\xff\x83e\xe4\x00\x8bM\x08\xe8\x90Y\xfe\xff\x85\xc0t7\x83e\xfc\x00'
    print(input[::-1].hex())
