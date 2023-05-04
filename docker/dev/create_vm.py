from pandare import Panda, panda_expect
import time
import subprocess

panda = Panda(qcow='/root/.panda/vm.qcow2', mem="3G", os_version="windows-32-7sp0", extra_args="-show-cursor -vnc 0.0.0.0:0,to=99,id=default -net nic -net user,restrict=on")

@panda.queue_blocking
def run_cmd():
    panda.run_monitor_cmd("change ide1-cd0 /payload.iso")
    finished = input('\nType "finished" when you have open the prompt ...\nOr "shutdown" to shutdown without saving (in case if needed to restart for example)\n')
    if finished == "finished":
        panda.run_monitor_cmd("savevm 1")
    else:
        print("Can be restarted !")
    time.sleep(1)
    panda.end_analysis()


if __name__ == "__main__":
    subprocess.run(["genisoimage", "-max-iso9660-filenames", "-RJ", "-o", "/payload.iso", "/root/new-vm"])
    time.sleep(5)
    panda.run()
    time.sleep(2)