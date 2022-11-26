import string
import time
from pandare import Panda
panda = Panda(qcow='/root/.panda/vm2.qcow2', arch="x86_64", mem="1G", os="windows-64-10")

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
        time.sleep(.5)
    p.run_monitor_cmd("sendkey ret")


@panda.cb_virt_mem_after_write
def virt_mem_after_write(env, pc, addr, size, buf):
    pc = panda.current_pc(cpustate)
    print("About to run the block at 0x{:x}".format(pc))
    print(size)


@panda.queue_blocking
def run_cmd():
    #print(panda.revert_sync("prompt2"))
    #panda.copy_to_guest("payload")
    panda.load_plugin("osi")
    panda.load_plugin("osi-test")
    panda.load_plugin("wintrospection")
    panda.enable_memcb()
    panda.run_monitor_cmd("loadvm prompt2")
    panda.run_monitor_cmd("change ide1-cd0 payload.iso")
    time.sleep(3)
    panda.run_monitor_cmd("sendkey esc")
    send_command(panda, "copy D:\\main.exe C:\\Users\\Malware\\Desktop\\main.exe")
    time.sleep(5)
    #panda.run_monitor_cmd('begin_record /addon/test')
    send_command(panda, "start C:\\Users\\Malware\\Desktop\\main.exe")
    time.sleep(10)
    #panda.run_monitor_cmd('end_record')
    panda.end_analysis()


# Start the guest
panda.run()
#run_cmd()
#panda.run_replay("/addon/test")
print("FINISHED")
