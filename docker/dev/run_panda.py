import string
import time
import sys
import random

from pandare import Panda, panda_expect

malware_sample = ""
panda = Panda(qcow='/root/.panda/vm.qcow2', mem="3G", os_version="windows-32-7sp0", extra_args="-show-cursor -vnc 0.0.0.0:0,to=99,id=default -net nic -net user,restrict=on -loadvm 1")


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
        '&': 'shift-7',
        '^': 'shift-6',
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
    time.sleep(1)
    send_command(panda, "xcopy D:\\additional-dll C:\\Users\\IEUser\\Desktop")
    send_command(panda, "copy D:\\" + malware_sample + " C:\\Users\\IEUser\\Desktop\\sample.exe")
    send_command(panda, "start /w /D \"C:\\Users\\IEUser\\Desktop\" sample.exe")
    #send_command(panda, "start /w /D \"C:\\Users\\IEUser\\Desktop\" sample.exe & shutdown /s /t 0 /f")
    panda.disable_tb_chaining()
    panda.run_monitor_cmd('begin_record /replay/sample')

    # TODO: Use mouse movements to prevent SplashScreen blocking (ex: Demo version of Themida) ?
    """panda.run_monitor_cmd('mouse_move 100 -100')
    for i in range(60):
        panda.run_monitor_cmd(f'mouse_move {random.randint(-10, 10)} {random.randint(-10, 10)}')
        if i % 2 == 0:
            panda.run_monitor_cmd('mouse_button 1')
            time.sleep(.075)
            panda.run_monitor_cmd('mouse_button 0')
        time.sleep(1)"""
    time.sleep(60)  # 600 - TODO: Need to find way of detecting end of process or timeout (40 min)

    #time.sleep(1800)  # 1800 seconds = 30 minutes
    panda.run_monitor_cmd('end_record')
    time.sleep(5)
    panda.run_monitor_cmd('screendump /replay/sample_screen')
    time.sleep(1)
    panda.end_analysis()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        malware_sample = sys.argv[1]
        panda.run()
        time.sleep(2)


