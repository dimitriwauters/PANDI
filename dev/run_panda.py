import string
import time
import sys

from pandare import Panda, panda_expect

malware_sample = ""
panda = Panda(qcow='/root/.panda/vm.qcow2', mem="3G", os_version="windows-32-7sp0", extra_args="-show-cursor -vnc 0.0.0.0:0,to=99,id=default -loadvm 1")


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

@panda.queue_blocking
def run_cmd():
    panda.run_monitor_cmd("change ide1-cd0 /payload.iso")
    time.sleep(3)
    panda.run_monitor_cmd("sendkey esc")
    send_command(panda, "copy D:\\" + malware_sample + " C:\\Users\\IEUser\\Desktop\\sample.exe")
    send_command(panda, "start /w /D \"C:\\Users\\IEUser\\Desktop\" sample.exe")
    panda.disable_tb_chaining()
    panda.run_monitor_cmd('begin_record /replay/sample')
    time.sleep(60)  # 600 - TODO: Need to find way of detecting end of process or timeout (40 min)
    panda.run_monitor_cmd('end_record')
    time.sleep(5)
    panda.end_analysis()


def runpd(malware):
    global malware_sample
    malware_sample = malware
    panda.run()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        runpd(sys.argv[1])


