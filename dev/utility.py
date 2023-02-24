from scipy.stats import entropy
import pefile


class EntropyAnalysis:
    def __init__(self, panda):
        self.panda = panda
        self.headers = {}  # {"UPX0": (0x401000, 0x401000), ...}
        self.entropy = {}  # {511312271: {"UPX0": 0.7751087, "TOTAL: 0.7751087}, ...}
        self.initial_EP = None
        self.initial_EP_section = ['', 0]
        self.unpacked_EP_section = ['', 0]

    def init_headers(self, cpu):
        headers = (0x400000, 0x401000)
        size = headers[1] - headers[0]
        try:
            m = self.panda.virtual_memory_read(cpu, headers[0], size)
            if m:
                pe = pefile.PE(data=m)
                entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                for section in pe.sections:
                    start = headers[0] + section.VirtualAddress
                    end = start + section.Misc_VirtualSize
                    name = section.Name.decode().replace('\x00', '')
                    self.headers[name] = (start, end)
                    if section.contains_rva(entry_point):
                        self.initial_EP_section[0] = name
                        self.initial_EP = 0x400000 + entry_point
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
        return m

    def analyse_entropy(self, cpu, m):
        whole_m = b""
        for header_name in m:
            memory = m[header_name]
            if memory:
                whole_m += memory
                self._compute_entropy(cpu, header_name, memory)
        if whole_m:
            self._compute_entropy(cpu, "TOTAL", whole_m)

    def _compute_entropy(self, cpu, header_name, memory):
        pk = [memory.count(i) for i in range(256)]
        if sum(pk) != 0:
            text_entropy = entropy(pk, base=2)
            instr_count = str(cpu.rr_guest_instr_count)
            if instr_count not in self.entropy:
                self.entropy[instr_count] = {}
            self.entropy[instr_count][header_name] = text_entropy

    def get_higher_section_addr(self):
        higher_addr = 0
        for header_name in self.headers:
            section = self.headers[header_name]
            if section[1] > higher_addr:
                higher_addr = section[1]
        return higher_addr


def write_debug_file(file_name, process_name, process_output):
    with open(f"/debug/{file_name.split('.exe')[0]}_{process_name}_exec.txt", "w") as file:
        file.write(process_output)
