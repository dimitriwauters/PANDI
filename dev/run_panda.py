import string
import time
import sys
from multiprocessing import Queue
from pandare import Panda, panda_expect

malware_sample = ""
malware_pid = 0
memory_write_list = {}
memory_write_exe_list = []
#panda = Panda(qcow='/root/.panda/win7.qcow2', arch="x86_64", mem="1048576k", os_version="windows-32-7sp1", extra_args="-show-cursor -vnc 0.0.0.0:0,to=99,id=default -device VGA,vgamem_mb=16")
panda = Panda(qcow='/root/.panda/win7_3.qcow2', mem="3G", os_version="windows-32-7sp1", extra_args="-show-cursor -vnc 0.0.0.0:0,to=99,id=default -loadvm 1")
#panda = Panda(qcow='/root/.panda/win7_3.qcow2', mem="3G", os_version="windows-32-7sp1", extra_args="-nographic -loadvm 1")


def send_command(p, cmd):
    keymap = {
        '-': 'minus',
        '=': 'equal',
        '[': 'bracket_left',
        ']': 'bracket_right',
        ';': 'semicolon',
        '\'': 'apostrophe',
        '\\': 'backslash',
        ',': 'comma',
        '.': 'dot',
        '/': 'slash',
        '*': 'asterisk',
        ' ': 'spc',
        '_': 'shift-minus',
        '+': 'shift-equal',
        '{': 'shift-bracket_left',
        '}': 'shift-bracket_right',
        ':': 'shift-semicolon',
        '"': 'shift-apostrophe',
        '|': 'shift-backslash',
        '<': 'shift-comma',
        '>': 'shift-dot',
        '?': 'shift-slash',
        '\n': 'ret',
    }

    for key in cmd:
        if key in string.ascii_uppercase:
            os_key = 'shift-' + key.lower()
        else:
            os_key = keymap.get(key, key)
        p.run_monitor_cmd("sendkey {}".format(os_key))
        time.sleep(.25)
    p.run_monitor_cmd("sendkey ret")


#@panda.cb_virt_mem_after_write(procname="sample.exe")
@panda.cb_virt_mem_after_write(enabled=False)
def virt_mem_after_write(env, pc, addr, size, buf):
    """global malware_pid
    global memory_write_list
    global memory_write_exe_list
    if malware_pid == 0:
        for pid, name_dict in panda.get_processes_dict(env).items():
            if name_dict["name"] == "sample.exe":
                malware_pid = pid
    else:
        if panda.get_id(env) == malware_pid:
            print(panda.get_process_name(env), pc, addr, size, buf)
            if addr not in memory_write_list.keys():
                memory_write_list[addr] = []
            else:
                for elem_pc in memory_write_list[addr]:
                    memory_write_exe_list.append([elem_pc, addr])
                memory_write_list[addr] = []
            # TODO: Add splitting if more than one byte
            memory_write_list[addr].append(pc)"""

    #pid = panda.get_id(env)

    global memory_write_list
    global memory_write_exe_list
    current = panda.get_process_name(env)
    if "sample" in current or "cmd" in current:
        if addr not in memory_write_list.keys():
            memory_write_list[addr] = []
        else:
            for elem_pc in memory_write_list[addr]:
                memory_write_exe_list.append([elem_pc, addr])
            memory_write_list[addr] = []
        # TODO: Add splitting if more than one byte
        memory_write_list[addr].append(pc)

    """print(env, pc, addr, size, buf)
    memory_write_list.append([pc, addr, size])"""


@panda.queue_blocking
def run_cmd():
    #panda.load_plugin("osi")
    #panda.load_plugin("osi_test")
    #panda.load_plugin("wintrospection")

    """panda.load_plugin("osi")
    panda.load_plugin("osi_test")
    panda.load_plugin("wintrospection")"""
    #panda.enable_memcb()

    print(panda.run_monitor_cmd("change ide1-cd0 /payload.iso"))
    #print(panda.run_monitor_cmd("change ide1-cd0 /root/.panda/payload.iso"))
    time.sleep(3)
    panda.run_monitor_cmd("sendkey esc")
    send_command(panda, "copy D:\\" + malware_sample + " C:\\Users\\IEUser\\Desktop\\sample.exe")
    send_command(panda, "start /w /D \"C:\\Users\\IEUser\\Desktop\" sample.exe")
    #panda.run_monitor_cmd('begin_record /addon/test')
    panda.enable_memcb()
    panda.enable_callback("virt_mem_after_write")
    time.sleep(600)
    #panda.run_monitor_cmd('end_record')
    panda.end_analysis()


def runpd(q, malware):
    global malware_sample
    malware_sample = malware
    try:
        panda.run()
        print(memory_write_exe_list)
        return memory_write_exe_list
        q.put(memory_write_exe_list)
    except panda_expect.TimeoutExpired:
        print("ERROR")
        return None
        q.put(None)


if __name__ == "__main__":
    #runpd(Queue(), "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
    if len(sys.argv) > 1:
        print(runpd(None, sys.argv[1]))
    else:
        #runpd(None, "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
        runpd(None, "KeePass.exe")


