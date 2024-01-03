import time
import sys
import hashlib

from pandare import Panda, panda_expect

malware_sample = ""
panda = Panda(generic='i386', extra_args="-vnc 0.0.0.0:0,to=99,id=default")


@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")
    panda.copy_to_guest(copy_directory="/payload")
    print(panda.run_serial_cmd(f'cd payload && chmod 777 {malware_sample}'))
    panda.type_serial_cmd(f"./{malware_sample}")
    panda.run_monitor_cmd(f"begin_record /replay/{hashlib.sha256(malware_sample.encode()).hexdigest()}")
    result = panda.finish_serial_cmd()
    panda.run_monitor_cmd("end_record")
    print(result)
    time.sleep(1)
    panda.end_analysis()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        malware_sample = sys.argv[1]
        if len(sys.argv) > 2:
            wait_duration = sys.argv[2]
        panda.run()
        time.sleep(2)


