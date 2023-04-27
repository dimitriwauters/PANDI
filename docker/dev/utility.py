from scipy.stats import entropy
import os
import pefile
import pickle
import hashlib
import string

class PEInformations:
    def __init__(self, panda, process_name):
        self.panda = panda
        self.process_name = process_name
        self.headers = {}  # {"UPX0": (0x401000, 0x401000), ...}
        self.headers_perms = {}  # {"UPX0": {"uninitialized_data": True, "execute": False, "read": False, "write": False}}
        self.imports = {}
        self.higher_section_addr = None
        self.initial_EP = None
        self.initial_EP_section = ['', 0]
        self.unpacked_EP_section = ['', 0]
        self.pe = None

    def init_headers(self, callback_entropy, callback_iat):
        # Flags: IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE
        try:
            self.pe = pefile.PE(f"/payload/{self.process_name}")
            entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            headers = (self.pe.OPTIONAL_HEADER.ImageBase, self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.SizeOfHeaders)
            for section in self.pe.sections:
                start = headers[0] + section.VirtualAddress
                end = start + section.Misc_VirtualSize
                try:
                    name = section.Name.decode().replace('\x00', '')
                except UnicodeDecodeError:
                    name = section.Name
                self.headers[name] = (start, end)
                self.headers_perms[name] = {"uninitialized_data": section.IMAGE_SCN_CNT_UNINITIALIZED_DATA,
                                            "execute": section.IMAGE_SCN_MEM_EXECUTE,
                                            "read": section.IMAGE_SCN_MEM_READ,
                                            "write": section.IMAGE_SCN_MEM_WRITE}
                if section.contains_rva(entry_point):
                    self.initial_EP_section[0] = name
                    self.initial_EP = headers[0] + entry_point
                callback_entropy(name, section)
            if self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress != 0:
                self.pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
                if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                        #print(entry.dll)
                        print(entry.dll, entry.struct.FirstThunk + headers[0], entry.__dict__, flush=True)
                        for imp in entry.imports:
                            #self.imports[imp.name] = int(imp.address, base=16) + 0x200
                            if imp.name != None:
                                self.imports[imp.name.decode()] = imp.address
                            print("\t", imp.name, imp.address, hex(imp.address), flush=True)
                            #print(hex(imp.address), imp.name, hex(imp.struct_table.Function), imp.__dict__, flush=True)
                            callback_iat(entry.dll.decode())
                else:  # IAT is stripped
                    pass  # TODO: IMPLEMENT
                """for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal, flush=True)"""
        except ValueError as e:
            print(e)

    def get_section_from_addr(self, addr):
        for section in self.headers.keys():
            if self.headers[section][0] <= addr <= self.headers[section][1]:
                return section
        return None

    def get_import_name_from_addr(self, addr):
        try:
            return list(self.imports.keys())[list(self.imports.values()).index(addr)]
        except ValueError:
            return None

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

    def get_section_initial_perms(self, section):
        if section in self.headers:
            return self.headers_perms[section]
        return None

    def has_sections_perms_changed(self, cpu):
        for section in list(self.headers_perms.keys()):
            boundaries = self.headers[section]
            if not self.headers_perms[section]["write"]:
                try:
                    self.panda.virtual_memory_write(cpu, boundaries[0], b'\x00')
                    return True
                except ValueError:
                    pass
            if not self.headers_perms[section]["read"]:
                try:
                    self.panda.virtual_memory_read(cpu, boundaries[0], 1)
                    return True
                except ValueError:
                    pass
        return False


class EntropyAnalysis:
    def __init__(self, panda, pe_info):
        self.panda = panda
        self.pe_info = pe_info
        self.entropy = {}  # {511312271: {"UPX0": 0.7751087, "TOTAL: 0.7751087}, ...}

    def initial_entropy(self, name, section):
        self._compute_entropy(0, name, section.get_data())

    def read_memory(self, cpu):
        m = {}
        for header_name in self.pe_info.headers:
            m[header_name] = b""
            mapping = self.pe_info.headers[header_name]
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
            if header_name == self.pe_info.unpacked_EP_section[0] and size == mapping_size:
                if not os.path.isfile("/addon/test.exe"):
                    with open("/addon/test.exe", 'wb') as file:
                        file.write(m[header_name])
        for import_name in self.pe_info.imports:
            if self.pe_info.imports[import_name] < self.pe_info.get_higher_section_addr():
                try:
                    a = self.panda.virtual_memory_read(cpu, self.pe_info.imports[import_name], 4)
                    to_hex = int(a[::-1].hex(), base=16)
                    if to_hex > self.pe_info.imports[import_name]:
                        self.pe_info.imports[import_name] = to_hex
                except ValueError:
                    pass
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


class DynamicLoadedDLL:
    def __init__(self, panda, pe_info):
        self.panda = panda
        self.pe_info = pe_info
        self.iat_dll = []
        self.loaded_dll = {"before": [], "after": []}
        self.dynamic_dll_methods = {}

    def initial_iat(self, dll_name):
        dll_name = dll_name.lower()
        if dll_name not in self.iat_dll:
            self.iat_dll.append(dll_name)

    def add_dll(self, dll_name):
        dll_name = dll_name.lower()
        if ".dll" in dll_name:
            sanitized = dll_name.split(".dll")[0] + ".dll"
            position = "before" if self.pe_info.unpacked_EP_section[0] == '' else "after"
            if not sanitized in self.loaded_dll[position] and not sanitized in self.iat_dll:
                self.loaded_dll[position].append(sanitized)

    def add_dll_method(self, name, addr):
        if name is None:
            self.dynamic_dll_methods[''.join(random.choice(string.ascii_lowercase) for i in range(5))] = addr
        elif name not in self.dynamic_dll_methods:
            self.dynamic_dll_methods[name] = addr

    def get_dll_method_name_from_addr(self, addr):
        try:
            return list(self.dynamic_dll_methods.keys())[list(self.dynamic_dll_methods.values()).index(addr)]
        except ValueError:
            return None


class DLLCallAnalysis:
    def __init__(self, panda, pe_info):
        self.panda = panda
        self.pe_info = pe_info
        self.functions = {"iat": {}, "dynamic": {}, "discovered": {}}

    def increase_call_nbr(self, source, name):
        if name not in self.functions[source]:
            self.functions[source][name] = 1
        else:
            self.functions[source][name] += 1

    def add_dll_function(self, source, name, addr):
        if name not in self.functions:
            self.functions[source][name] = addr

    def get_dll_function_name_from_addr(self, addr):
        for source in self.functions.keys():
            try:
                functions = list(self.functions[source].keys())
                index = list(self.functions.values()).index(addr)
                return functions[index]
            except ValueError:
                pass
        return None

    def get_nbr_calls(self, name, source=None):
        if source is None:
            sum = 0
            for s in self.functions.keys():
                if name in self.functions[s]:
                    sum += self.functions[s][name]
            return sum
        else:
            if name in self.functions[source]:
                return self.functions[source][name]
            else:
                return 0

class SearchDLL:
    def __init__(self, panda):
        self._DOS_HEADER_NEXT_PTR = 0x3c
        self._SIZE_OF_FILEHEADER = 0x14
        self.panda = panda
        self.dll = {}
        self.completed_dll = []
        self.resolved_dll_ordinal = {}
        with open('/root/.panda/vm.qcow2', 'rb') as vm_file:
            self.vm_hash = hashlib.sha256(vm_file.read(8192)).hexdigest()

    def search_dlls(self, env, specific_dll=None, specific_function=None):
        found = False
        for mapping in self.panda.get_mappings(env):
            if mapping.file != self.panda.ffi.NULL:
                name = self.panda.ffi.string(mapping.file).decode()
                if ".dll" in name:
                    dll_name = name.split('\\')[-1]
                    if not dll_name in self.resolved_dll_ordinal:
                        self.resolved_dll_ordinal[dll_name] = set()
                    if (specific_dll is None or dll_name == specific_dll) and (dll_name not in self.completed_dll):
                        try:
                            new_exe_addr = int(self.panda.virtual_memory_read(env, mapping.base + self._DOS_HEADER_NEXT_PTR, 4)[::-1].hex(), base=16) + 0x4
                            export_table_offset = int(self.panda.virtual_memory_read(env, mapping.base + new_exe_addr + self._SIZE_OF_FILEHEADER + 0x60, 4)[::-1].hex(), base=16)
                            nbr_exported_fct = int(self.panda.virtual_memory_read(env, mapping.base + export_table_offset + 0x14, 4)[::-1].hex(), base=16)
                            base_addr_exported_fct_name = int(self.panda.virtual_memory_read(env, mapping.base + export_table_offset + 0x20, 4)[::-1].hex(), base=16)
                            for i in range(nbr_exported_fct):
                                if i not in self.resolved_dll_ordinal[dll_name]:
                                    try:
                                        fct_name_addr = int(self.panda.virtual_memory_read(env, mapping.base + base_addr_exported_fct_name + i * 0x4, 4)[::-1].hex(), base=16)
                                        fct_name = self.panda.virtual_memory_read(env, mapping.base + fct_name_addr, 32).split(b'\x00')[0].decode()
                                        self.resolved_dll_ordinal[dll_name].add(i)
                                        if specific_function is None or fct_name == specific_function:
                                            function_rva = int(self.panda.virtual_memory_read(env, mapping.base + export_table_offset + 0x2c + i * 0x4, 4)[::-1].hex(), base=16)
                                            if (mapping.base + function_rva) not in self.dll:
                                                self.dll[mapping.base + function_rva] = f"{fct_name}-{dll_name}"
                                                found = True
                                                print(hex(mapping.base + function_rva), f"{fct_name}-{dll_name}")
                                        if len(self.resolved_dll_ordinal[dll_name]) == nbr_exported_fct:
                                            self.completed_dll.append(dll_name)
                                    except Exception:
                                        pass
                        except ValueError:
                            pass
        return found

    def get_dll_method_name_from_addr(self, addr):
        if addr in self.dll:
            return self.dll[addr]
        else:
            return None

    def save_discovered_dlls(self):
        if not os.path.isdir("/payload/dll"):
            os.makedirs("/payload/dll")
        with open(f"/payload/dll/{self.vm_hash}_discovered_dlls.pickle", 'wb') as file:
            pickle.dump(self.dll, file, protocol=pickle.HIGHEST_PROTOCOL)

    def get_discovered_dlls(self):
        if self.is_savefile_exist():
            with open(f"/payload/dll/{self.vm_hash}_discovered_dlls.pickle", 'rb') as file:
                self.dll = pickle.load(file)

    def is_savefile_exist(self):
        return os.path.isfile(f"/payload/dll/{self.vm_hash}_discovered_dlls.pickle")


def write_debug_file(file_name, process_name, process_output):
    with open(f"/debug/{file_name.split('.exe')[0]}_{process_name}_exec.txt", "w") as file:
        file.write(process_output)


def write_output_file(file_name, is_packed, type_of_analysis, debug_name, process_output):
    name = file_name.split('.exe')[0]
    folder_path = f"/output/{'packed' if is_packed else 'not-packed'}/{name}/{type_of_analysis}"
    if not os.path.isdir(folder_path):
        os.makedirs(folder_path)
    with open(f"{folder_path}/{debug_name}.pickle", "wb") as file:
        pickle.dump(process_output, file, protocol=pickle.HIGHEST_PROTOCOL)

def read_output_file(file_name, is_packed, type_of_analysis, debug_name):
    result = {}
    name = file_name.split('.exe')[0]
    folder_path = f"/output/{'packed' if is_packed else 'not-packed'}/{name}/{type_of_analysis}"
    if os.path.isdir(folder_path):
        try:
            with open(f"{folder_path}/{debug_name}.pickle", "rb") as file:
                result = pickle.load(file)
        except FileNotFoundError:
            pass
    return result
