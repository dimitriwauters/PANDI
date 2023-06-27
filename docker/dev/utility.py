from scipy.stats import entropy
import os
import pefile
import random
import pickle
import hashlib
import string
import re


class PEInformations:
    def __init__(self, panda, debugging_activated, process_path, process_name):
        self.panda = panda
        self.debugging_activated = debugging_activated
        self.process_path = process_path
        self.process_name = process_name
        self.image_base = 0x0
        self.optional_header_size = 0x0
        self.headers = {}  # {"UPX0": (0x401000, 0x401000), ...}
        self.headers_perms = {"OPTIONAL_HEADER": {"uninitialized_data": False, "execute": False, "read": True, "write": False}}
        self.imports = {}
        self.higher_section_addr = None
        self.initial_EP = None
        self.initial_EP_section = ['', 0]
        self.unpacked_EP_section = ['', 0]
        self.pe = None

    def init_headers(self, sample_base, callback_entropy, callback_iat):
        # Flags: IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE
        try:
            self.pe = pefile.PE(f"{self.process_path}/{self.process_name}")
            self.image_base = sample_base
            self.optional_header_size = self.pe.OPTIONAL_HEADER.SectionAlignment
            entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            headers = (self.image_base, self.image_base + self.pe.OPTIONAL_HEADER.SizeOfHeaders)
            sections_data = b''
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
                callback_entropy(name, section.get_data())
                sections_data += section.get_data()
            callback_entropy("TOTAL", sections_data)
            if self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress != 0:
                self.pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
                if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                        if self.debugging_activated:
                            print(entry.dll, entry.struct.FirstThunk + headers[0], entry.__dict__, flush=True)
                        for imp in entry.imports:
                            if imp.name is not None:
                                self.imports[imp.name.decode()] = imp.address
                            if self.debugging_activated:
                                print("\t", imp.name, imp.address, hex(imp.address), flush=True)
                            callback_iat(entry.dll.decode())
                else:  # IAT is stripped
                    pass  # TODO: IMPLEMENT
                """for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal, flush=True)"""
        except ValueError as e:
            print(e)

    def update_imports_addr(self, cpu):
        for import_name in self.imports:
            if self.imports[import_name] < self.get_higher_section_addr():
                try:
                    a = self.panda.virtual_memory_read(cpu, self.imports[import_name], 4)
                    to_hex = int(a[::-1].hex(), base=16)
                    if to_hex > self.imports[import_name]:
                        if self.debugging_activated:
                            print(f"(IAT_IMPORT) CHANGED IMPORT {import_name}: {hex(self.imports[import_name])} -> {hex(to_hex)}")
                        self.imports[import_name] = to_hex
                except ValueError:
                    pass

    def get_section_from_addr(self, addr):
        if self.image_base <= addr <= self.image_base + self.optional_header_size:
            return "OPTIONAL_HEADER"
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
        if self.higher_section_addr is None or self.higher_section_addr == 0:
            self.higher_section_addr = 0
            for header_name in self.headers.keys():
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

    def initial_entropy(self, section_name, section_data):
        self._compute_entropy(0, section_name, section_data)

    def read_memory(self, cpu):
        m = {}
        modified = False
        for header_name in self.pe_info.headers:
            m[header_name] = b""
            mapping = self.pe_info.headers[header_name]
            mapping_size = mapping[1] - mapping[0]
            size = mapping_size
            while size > 0:
                try:
                    m[header_name] += self.panda.virtual_memory_read(cpu, mapping[0], size)
                    modified = True
                    if self.pe_info.debugging_activated:
                        print(f"(READ_PROCESS_MEMORY) Successfully read memory of size {size} (initial mapping size: {mapping_size}) with base addr {hex(mapping[0])} (section name: {header_name})", flush=True)
                    break
                except ValueError:
                    size -= 0x1000
        return m, modified

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
        self.iat_modified = []

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

    def iat_address_modified(self, iat_name, dynamic_name):
        self.iat_modified.append((iat_name, dynamic_name))


class DLLCallAnalysis:
    def __init__(self):
        self.functions_generic = {"iat": {}, "dynamic": {}, "discovered": {}}
        self.functions_malicious = {"iat": {}, "dynamic": {}, "discovered": {}}
        self.__MALICIOUS_FUNCTIONS = ["getprocaddress", "loadlibrary", "exitprocess", "getmodulehandle", "virtualalloc",
                                     "virtualfree", "getmodulefilename", "createfile", "regqueryvalueex", "messagebox",
                                     "getcommandline", "virtualprotect", "getstartupinfo", "getstdhandle", "regopenkeyex"]

    def __get_list_for_function(self, name):
        if self.is_function_malicious(name):
            return self.functions_malicious
        else:
            return self.functions_generic

    def is_function_malicious(self, name):
        return name.lower() in self.__MALICIOUS_FUNCTIONS

    def increase_call_nbr(self, source, name):
        list_to_use = self.__get_list_for_function(name)
        if name not in list_to_use[source]:
            list_to_use[source][name] = 1
        else:
            list_to_use[source][name] += 1

    def get_nbr_calls(self, name, source=None):
        list_to_use = self.__get_list_for_function(name)
        if source is None:
            sum = 0
            for s in list_to_use.keys():
                if name in list_to_use[s]:
                    sum += list_to_use[s][name]
            return sum
        else:
            if name in list_to_use[source]:
                return list_to_use[source][name]
            else:
                return 0

    def get_malicious_functions(self):
        return self.functions_malicious

    def get_generic_functions(self):
        return self.functions_generic

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
        self.external_dll = [name for root, dirs, files in os.walk("/dll/additional-dll") for name in files if name.lower().endswith(".dll")]

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
            pickle.dump({"discovered_dll": self.dll, "external_dll": self.external_dll}, file, protocol=pickle.HIGHEST_PROTOCOL)

    def get_discovered_dlls(self):
        if self.is_savefile_exist():
            with open(f"/payload/dll/{self.vm_hash}_discovered_dlls.pickle", 'rb') as file:
                data = pickle.load(file)
                self.dll = data["discovered_dll"]
                self.external_dll = data["external_dll"]

    def is_savefile_exist(self):
        if os.path.isfile(f"/payload/dll/{self.vm_hash}_discovered_dlls.pickle"):
            with open(f"/payload/dll/{self.vm_hash}_discovered_dlls.pickle", 'rb') as file:
                data = pickle.load(file)
                return len(list(set(self.external_dll) - set(data["external_dll"]))) == 0
        return False


def write_debug_file(file_name, process_name, process_output):
    name = re.split('\.exe', file_name, flags=re.IGNORECASE)[0]
    with open(f"/debug/{name}_{process_name}_exec.txt", "w") as file:
        file.write(process_output)


def write_output_file(file_name, type_of_analysis, debug_name, process_output):
    name = re.split('\.exe', file_name, flags=re.IGNORECASE)[0]
    folder_path = f"/output/{name}/{type_of_analysis}"
    if not os.path.isdir(folder_path):
        os.makedirs(folder_path)
    with open(f"{folder_path}/{debug_name}.pickle", "wb") as file:
        pickle.dump(process_output, file, protocol=pickle.HIGHEST_PROTOCOL)


def read_output_file(file_name, type_of_analysis, debug_name):
    result = {}
    name = re.split('\.exe', file_name, flags=re.IGNORECASE)[0]
    folder_path = f"/output/{name}/{type_of_analysis}"
    if os.path.isdir(folder_path):
        try:
            with open(f"{folder_path}/{debug_name}.pickle", "rb") as file:
                result = pickle.load(file)
        except FileNotFoundError:
            pass
    return result


class SectionPermissionCheck:
    class VirtualMemoryCheck:
        def __init__(self):
            self.__waiting = {"baseaddress": None, "permissions": None, "section": None}
            self.translation = {"PAGE_EXECUTE": {"execute": True, "read": False, "write": False},
                                "PAGE_EXECUTE_READ": {"execute": True, "read": True, "write": False},
                                "PAGE_EXECUTE_READWRITE": {"execute": True, "read": True, "write": True},
                                "PAGE_EXECUTE_WRITECOPY": {"execute": True, "read": False, "write": True},
                                "PAGE_NOACCESS": {"execute": False, "read": False, "write": False},
                                "PAGE_READONLY": {"execute": False, "read": True, "write": False},
                                "PAGE_READWRITE": {"execute": False, "read": True, "write": True},
                                "PAGE_WRITECOPY": {"execute": False, "read": False, "write": True},
                                "PAGE_TARGETS_INVALID or PAGE_TARGETS_NO_UPDATE": None}

        def add_baseaddress(self, addr):
            self.__waiting["baseaddress"] = addr

        def add_permissions(self, perms):
            self.__waiting["permissions"] = self.translation[perms]

        def add_section(self, section_name):
            self.__waiting["section"] = section_name

        def get_section(self):
            return self.__waiting["section"]

        def get_infos(self):
            data = self.__waiting
            self.__waiting = {"baseaddress": None, "permissions": None, "section": None}
            return data

    def __init__(self, initial_perms):
        self.permissions_modifications = {"initial": initial_perms}
        self.__last_modification = "initial"
        self.__virtual_memory_check = self.VirtualMemoryCheck()

    def add_baseaddress(self, addr):
        self.__virtual_memory_check.add_baseaddress(addr)

    def add_section(self, section_name):
        self.__virtual_memory_check.add_section(section_name)

    def add_permissions(self, perms):
        self.__virtual_memory_check.add_permissions(perms)

    def get_infos(self):
        return self.__virtual_memory_check.get_infos()

    def add_section_permission(self, time, section_name, access, perm):
        if not time in self.permissions_modifications:
            self.permissions_modifications[time] = {}
        if not section_name in self.permissions_modifications[time]:
            self.permissions_modifications[time][section_name] = {}
        self.permissions_modifications[time] = self.permissions_modifications[self.__last_modification]
        self.permissions_modifications[time][section_name][access] = perm
        self.__last_modification = time

    def get_last_section_permission(self, section_name):
        return self.permissions_modifications[self.__last_modification][section_name]
