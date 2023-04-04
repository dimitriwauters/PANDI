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

    def _DesiredAccess(self, env, addr):
        data = bin(addr)[2:]
        data = ''.join(['0' for i in range(32 - len(data))]) + str(data)
        return data

    def _ValueName(self, env, addr):
        return self.read_PUNICODE_STRING(env, addr)

    def _Protect(self, env, value):
        values = {0x10: "PAGE_EXECUTE", 0x20: "PAGE_EXECUTE_READ", 0x40: "PAGE_EXECUTE_READWRITE", 0x80: "PAGE_EXECUTE_WRITECOPY",
                  0x1: "PAGE_NOACCESS", 0x2: "PAGE_READONLY", 0x4: "PAGE_READWRITE", 0x8: "PAGE_WRITECOPY",
                  0x40000000: "PAGE_TARGETS_INVALID or PAGE_TARGETS_NO_UPDATE"}
        return values[value]

    def _NewProtectWin32(self, env, value):
        return self._Protect(env, value)

    def _Win32Protect(self, env, value):
        return self._Protect(env, value)

    def _SectionPageProtection(self, env, value):
        return self._Protect(env, value)

    def read_ObjectAttributes(self, env, addr):
        object_length = self.panda.ffi.cast("unsigned int", int(self.panda.virtual_memory_read(env, addr, 4)[::-1].hex(), base=16))
        if object_length == 0:
            return "NULL"
        handle_addr = int(self.panda.virtual_memory_read(env, addr + 4, 4)[::-1].hex(), base=16)
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
            str_content = self.panda.virtual_memory_read(env, str_addr, max_length)
            str_valid = str_content.decode("utf-8", "ignore").replace('\x00', '').lower()
            return str_valid
        else:
            return "Error"

    # ==================================================================================================================

    def read_usercall(self, env, function_name):
        result = "Unknown"
        try:
            result = getattr(self, f"_{function_name}")(env)
        except AttributeError:
            pass
        finally:
            return result

    def _GetProcAddress(self, env):
        """
        FARPROC GetProcAddress(
          [in] HMODULE hModule,
          [in] LPCSTR  lpProcName
        );
        """
        hModule_addr = self.panda.arch.get_arg(env, 0, convention='cdecl')
        lpProcName_addr = self.panda.arch.get_arg(env, 1, convention='cdecl')
        lpProcName_val = "Unknown"
        try:
            lpProcName_raw = self.panda.virtual_memory_read(env, lpProcName_addr, 32)
            lpProcName_val = lpProcName_raw[:lpProcName_raw.find(b'\x00')].decode()
        except ValueError:
            pass
        return {"name": lpProcName_val, "addr": self.panda.arch.get_retval(env)}

    def _LoadLibraryA(self, env):
        """
        HMODULE LoadLibraryA(
          [in] LPCSTR lpLibFileName
        );
        """
        lpLibFileName_addr = self.panda.arch.get_arg(env, 0, convention='cdecl')
        lpLibFileName_val = "Unknown"
        try:
            lpLibFileName_raw = self.panda.virtual_memory_read(env, lpLibFileName_addr, 32)
            lpLibFileName_val = lpLibFileName_raw[:lpLibFileName_raw.find(b'\x00')].decode()
        except ValueError:
            pass
        return {"name": lpLibFileName_val, "addr": self.panda.arch.get_retval(env)}

    def _LoadLibraryW(self, env):
        return self._LoadLibraryA(env)
