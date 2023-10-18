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

    def _NewAccessProtection(self, env, value):
        return self._Protect(env, value)

    def _BaseAddress(self, env, addr):
        return int(self.panda.virtual_memory_read(env, addr, 4)[::-1].hex(), base=16)

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
        result = None
        function_name = function_name.split("-")[0]
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
        lpProcName_addr = self.panda.arch.get_arg(env, 1, convention='cdecl')
        lpProcName_val = "Unknown"
        try:
            if lpProcName_addr >> 16 == 0:
                lpProcName_val = "Ordinal_"+str(lpProcName_addr)
            else:
                lpProcName_raw = self.panda.virtual_memory_read(env, lpProcName_addr, 32)
                lpProcName_val = lpProcName_raw[:lpProcName_raw.find(b'\x00')].decode()
        except ValueError:
            pass
        func_addr = self.panda.arch.get_retval(env, convention="syscall")
        ret_addr = self.panda.arch.get_return_address(env)
        return {"name": lpProcName_val, "addr": func_addr,"ret": ret_addr}

    def _LoadLibraryA(self, env):
        """
        HMODULE LoadLibraryA(
          [in] LPCSTR lpLibFileName
        );
        """
        lpLibFileName_addr = self.panda.arch.get_arg(env, 0, convention='cdecl')
        lpLibFileName_val = "Unknown"
        try:
            lpLibFileName_raw = self.panda.virtual_memory_read(env, lpLibFileName_addr, 100)
            lpLibFileName_val = lpLibFileName_raw[:lpLibFileName_raw.find(b'\x00')].decode()
        except ValueError as e:
            print(e)
        ret_addr = self.panda.arch.get_return_address(env)
        return {"name": lpLibFileName_val,"ret": ret_addr}

    def _LoadLibraryW(self, env):
        lpLibFileName_addr = self.panda.arch.get_arg(env, 0, convention='cdecl')
        lpLibFileName_val = "Unknown"
        try:
            lpLibFileName_raw = self.panda.virtual_memory_read(env, lpLibFileName_addr, 100)
            lpLibFileName_val = lpLibFileName_raw[:lpLibFileName_raw.find(b'\x00\x00\x00')+1].decode('utf-16')
        except ValueError as e:
            print(e)
            pass
        ret_addr = self.panda.arch.get_return_address(env)
        return {"name": lpLibFileName_val,"ret": ret_addr}
        
    def _GetModuleHandleA(self, env):
        """
        HMODULE GetModuleHandleA(
          [in, optional] LPCSTR lpModuleName
        );
        """
        lpModuleName_addr = self.panda.arch.get_arg(env, 0, convention='cdecl')
        if lpModuleName_addr == 0x0:
            return {"name": "","ret": 0x0}
        lpModuleName_val = "Unknown"
        try:
            lpModuleName_raw = self.panda.virtual_memory_read(env, lpModuleName_addr, 100)
            lpModuleName_val = lpModuleName_raw[:lpModuleName_raw.find(b'\x00')].decode()
        except ValueError as e:
            print(e)
        ret_addr = self.panda.arch.get_return_address(env)
        return {"name": lpModuleName_val,"ret": ret_addr}

    def _GetModuleHandleW(self, env):
        lpModuleName_addr = self.panda.arch.get_arg(env, 0, convention='cdecl')
        if lpModuleName_addr == 0x0:
            return {"name": "","ret": 0x0}
        lpModuleName_val = "Unknown"
        try:
            lpModuleName_raw = self.panda.virtual_memory_read(env, lpModuleName_addr, 100)
            lpModuleName_val = lpModuleName_raw[:lpModuleName_raw.find(b'\x00\x00\x00')+1].decode('utf-16')
        except ValueError as e:
            print(e)
        ret_addr = self.panda.arch.get_return_address(env)
        return {"name": lpModuleName_val,"ret": ret_addr}

    def _LdrGetProcedureAddress(self, env):
        # hModule_addr = self.panda.arch.get_arg(env, 0, convention='cdecl')
        FunctionName_addr = self.panda.arch.get_arg(env, 1, convention='cdecl')
        # Oridinal_addr = self.panda.arch.get_arg(env, 2, convention='cdecl')
        FunctionName_val = "Unknown"
        try:
            FunctionName_raw = self.panda.virtual_memory_read(env, FunctionName_addr, 32)
            FunctionName_val = FunctionName_raw[:FunctionName_raw.find(b'\x00')].decode()
        except ValueError:
            pass
        return {"name": FunctionName_val, "addr": self.panda.arch.get_retval(env, convention="syscall")}
        
