from scipy.stats import entropy
import os
import pefile


class EntropyAnalysis:
    def __init__(self, panda):
        self.panda = panda
        self.headers = {}  # {"UPX0": (0x401000, 0x401000), ...}
        self.entropy = {}  # {511312271: {"UPX0": 0.7751087, "TOTAL: 0.7751087}, ...}
        self.higher_section_addr = None
        self.initial_EP = None
        self.initial_EP_section = ['', 0]
        self.unpacked_EP_section = ['', 0]
        self.imports = {}
        self.pe = None

    def init_headers(self, cpu):
        # Flags: IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE
        try:
            self.pe = pefile.PE(f"/payload/{'upx_ADExplorer.exe'}")
            entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            headers = (self.pe.OPTIONAL_HEADER.ImageBase, self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.SizeOfHeaders)
            for section in self.pe.sections:
                start = headers[0] + section.VirtualAddress
                end = start + section.Misc_VirtualSize
                name = section.Name.decode().replace('\x00', '')
                self.headers[name] = (start, end)
                self._compute_entropy(0, name, section.get_data())
                if section.contains_rva(entry_point):
                    self.initial_EP_section[0] = name
                    self.initial_EP = headers[0] + entry_point
            self.pe.parse_data_directories()
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                #print(entry.dll)
                print(entry.dll, entry.struct.FirstThunk + headers[0], entry.__dict__, flush=True)
                for imp in entry.imports:
                    #self.imports[imp.name] = int(imp.address, base=16) + 0x200
                    self.imports[imp.name] = imp.address
                    print("\t", imp.name, imp.address, hex(imp.address), flush=True)
                    #print(hex(imp.address), imp.name, hex(imp.struct_table.Function), imp.__dict__, flush=True)
            """for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal, flush=True)"""
        except ValueError as e:
            print(e, flush=True)

    def read_memory(self, cpu):
        m = {}
        for header_name in self.headers:
            m[header_name] = b""
            mapping = self.headers[header_name]
            mapping_size = mapping[1] - mapping[0]
            size = mapping_size
            while size > 0:
                try:
                    m[header_name] += self.panda.virtual_memory_read(cpu, mapping[0], size)
                    print(f"(READ_PROCESS_MEMORY) Successfully read memory of size {size} (initial mapping size: "
                          f"{mapping_size}) with base addr {hex(mapping[0])} (section name: {header_name})", flush=True)
                    break
                except ValueError:
                    size -= 0x1000
            if header_name == "UPX0" and size == mapping_size and self.unpacked_EP_section[0] == "UPX0":
                if not os.path.isfile("/addon/test.exe"):
                    with open("/addon/test.exe", 'wb') as file:
                        file.write(m["UPX0"])
        for import_name in self.imports:
            if self.imports[import_name] < self.get_higher_section_addr():
                try:
                    a = self.panda.virtual_memory_read(cpu, self.imports[import_name], 4)
                    to_hex = int(a[::-1].hex(), base=16)
                    if to_hex > self.imports[import_name]:
                        self.imports[import_name] = to_hex
                except ValueError:
                    pass
            """else:
                try:
                    a = self.panda.virtual_memory_read(cpu, self.imports[import_name] - 32, 64)
                    print(a, flush=True)
                except ValueError as e:
                    print(e, flush=True)
                    pass"""
        return m

    def analyse_entropy(self, cpu, m):
        whole_m = b""
        for header_name in m:
            memory = m[header_name]
            if memory:
                whole_m += memory
                self._compute_entropy(cpu.rr_guest_instr_count, header_name, memory)
        if whole_m:
            self._compute_entropy(cpu.rr_guest_instr_count, "TOTAL", whole_m)

    def _compute_entropy(self, instr_count, header_name, memory):
        pk = [memory.count(i) for i in range(256)]
        if sum(pk) != 0:
            text_entropy = entropy(pk, base=2)
            instr_count = str(instr_count)
            if instr_count not in self.entropy:
                self.entropy[instr_count] = {}
            self.entropy[instr_count][header_name] = text_entropy

    def get_higher_section_addr(self):
        if self.higher_section_addr is None:
            self.higher_section_addr = 0
            for header_name in self.headers:
                section = self.headers[header_name]
                if int(section[1]) > self.higher_section_addr:
                    self.higher_section_addr = int(section[1])
            return self.higher_section_addr
        else:
            return self.higher_section_addr


def write_debug_file(file_name, process_name, process_output):
    with open(f"/debug/{file_name.split('.exe')[0]}_{process_name}_exec.txt", "w") as file:
        file.write(process_output)


def write_output_file(file_name, is_packed, exec_type, process_output):
    name = file_name.split('.exe')[0]
    folder_path = f"/output/{'packed' if is_packed else 'not-packed'}/{name}"
    if not os.path.isdir(folder_path):
        os.makedirs(folder_path)
    with open(f"{folder_path}/{exec_type}.txt", "w") as file:
        file.write(process_output)
