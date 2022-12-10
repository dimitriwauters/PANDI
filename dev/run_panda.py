import string
import time
import sys
from pandare import Panda, panda_expect

malware_sample = ""
malware_pid = []
memory_write_list = {}
memory_write_exe_list = []
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


@panda.cb_virt_mem_after_write(enabled=False)
def virt_mem_after_write(env, pc, addr, size, buf):
    global malware_pid
    global memory_write_list
    global memory_write_exe_list
    if len(malware_pid) == 0:
        for pid, infos in panda.get_processes_dict(env).items():
            if infos["name"] == "cmd.exe" and pid not in malware_pid:
                malware_pid.append(pid)
    else:
        for pid, infos in panda.get_processes_dict(env).items():
            if infos["parent_pid"] in malware_pid and pid not in malware_pid:
                malware_pid.append(pid)

    pid = panda.plugins['osi'].get_current_process(env).pid
    if pid in malware_pid:
        #print(panda.virtual_memory_read(env, pc, 8))
        for _ in range(size):
            if addr not in memory_write_list.keys():
                memory_write_list[addr] = []
            else:
                for elem_pc in memory_write_list[addr]:
                    memory_write_exe_list.append([elem_pc, addr])
                memory_write_list[addr] = []
            memory_write_list[addr].append(pc)


@panda.queue_blocking
def run_cmd():
    #print(panda.run_monitor_cmd("change ide1-cd0 /payload.iso"))
    print(panda.run_monitor_cmd("change ide1-cd0 /root/.panda/payload.iso"))  # /!\ Do not use with main.py
    time.sleep(3)
    panda.run_monitor_cmd("sendkey esc")
    send_command(panda, "copy D:\\" + malware_sample + " C:\\Users\\IEUser\\Desktop\\sample.exe")
    send_command(panda, "start /w /D \"C:\\Users\\IEUser\\Desktop\" sample.exe")
    #panda.run_monitor_cmd('begin_record /addon/test')
    panda.enable_memcb()
    panda.enable_callback("virt_mem_after_write")
    time.sleep(600)  # TODO: Wait for end of process or timeout (40 min)
    #panda.run_monitor_cmd('end_record')
    panda.end_analysis()


def runpd(malware):
    global malware_sample
    malware_sample = malware
    try:
        panda.run()
        return memory_write_exe_list
    except panda_expect.TimeoutExpired:
        return "ERROR"


if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(runpd(sys.argv[1]))


