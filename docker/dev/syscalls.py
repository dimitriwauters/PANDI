class SysCallsInterpreter:
    def __init__(self, panda):
        self.panda = panda


    def read_syscall(self, env, function_name, parameter_name, addr):
        result = "Unknown"
        try:
            result = getattr(self, f"_{function_name}_{parameter_name}")(env, addr)
        except AttributeError:
            try:
                result = getattr(self, f"_{parameter_name}")(env, addr)
            except AttributeError:
                pass
        finally:
            return result

    def _ObjectAttributes(self, env, addr):
        obj = self.read_ObjectAttributes(env, addr)
        return self.read_PUNICODE_STRING(env, obj["name_addr"])

    def read_ObjectAttributes(self, env, addr):
        """length = int(self.panda.virtual_memory_read(env, addr, 4)[::-1].hex(), base=16)
        max_length = int(self.panda.virtual_memory_read(env, addr + 4, 4)[::-1].hex(), base=16)
        if max_length >= length:
            if max_length == 0:
                return "NULL"
            str_addr = int(self.panda.virtual_memory_read(env, addr + 8, 4)[::-1].hex(), base=16)
            str_content = self.panda.virtual_memory_read(env, str_addr, length * 2)
            print(str_content)
            str_valid = str_content.decode("utf-8", "ignore").replace('\x00', '').lower().split(".dll")[0]
            return str_valid
        else:
            return "Error"""""

        object_length = self.panda.ffi.cast("unsigned int", int(self.panda.virtual_memory_read(env, addr, 4)[::-1].hex(), base=16))
        if object_length == 0:
            return "NULL"
        handle_addr = int(self.panda.virtual_memory_read(env, addr + 4, 4)[::-1].hex(), base=16)
        if handle_addr > 0xFFFF:
            print(self.panda.virtual_memory_read(env, handle_addr, 64))
        name_addr = int(self.panda.virtual_memory_read(env, addr + 8, 4)[::-1].hex(), base=16)
        attributes = self.panda.ffi.cast("unsigned int", int(self.panda.virtual_memory_read(env, addr + 16, 4)[::-1].hex(), base=16))
        return {"object_length": object_length, "handle_addr": handle_addr, "name_addr": name_addr, "attributes": attributes}

    def read_PUNICODE_STRING(self, env, addr):
        length = int(self.panda.virtual_memory_read(env, addr, 2)[::-1].hex(), base=16)
        max_length = int(self.panda.virtual_memory_read(env, addr + 2, 2)[::-1].hex(), base=16)
        if max_length >= length:
            if max_length == 0:
                return "NULL"
            str_addr = int(self.panda.virtual_memory_read(env, addr + 4, 4)[::-1].hex(), base=16)
            str_content = self.panda.virtual_memory_read(env, str_addr, max_length * 2)
            str_valid = str_content.decode("utf-8", "ignore").replace('\x00', '').lower()
            return str_valid
        else:
            return "Error"

    def _NtOpenSection_DesiredAccess(self, env, addr):
        """
            #define SECTION_QUERY                0x0001
            #define SECTION_MAP_WRITE            0x0002
            #define SECTION_MAP_READ             0x0004
            #define SECTION_MAP_EXECUTE          0x0008
        """
        return "Unknown"