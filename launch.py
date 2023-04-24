import subprocess
import requests
import signal
import os
import sys
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("--build", action='store_true', help="rebuild panda image", default=False)
parser.add_argument("--silent", action='store_true', help="only print the result in JSON format", default=False)

parser.add_argument("--debug", action='store_true', help="activate verbose mode", default=False)
parser.add_argument("--executable", type=str, help="force the selection of one software", default=None)

parser.add_argument("--force_complete_replay", action='store_true', help="read the replay until the end", default=False)
parser.add_argument("--max_memory_write_exe_list_length", type=int, help="maximum length of the returned list before exiting", default=1000)
parser.add_argument("--entropy_granularity", type=int, help="number of basic blocks between samples. Lower numbers result in higher run times", default=1000)
parser.add_argument("--max_entropy_list_length", type=int, help="maximum length of entropy list before exiting", default=0)

parser.add_argument("--dll_discover_granularity", type=int, help="maximum length of the returned list before exiting", default=1000)
parser.add_argument("--max_dll_discover_fail", type=int, help="maximum length of the returned list before exiting", default=10000)
parser.add_argument("--force_dll_rediscover", action='store_true', help="read the replay until the end", default=False)

parser.add_argument("--memcheck", action='store_true', help="activate memory write and executed detection", default=False)
parser.add_argument("--entropy", action='store_true', help="activate entropy analysis", default=False)
parser.add_argument("--dll", action='store_true', help="activate syscalls analysis", default=False)
parser.add_argument("--dll_discover", action='store_true', help="activate dll discovering system", default=False)
parser.add_argument("--sections_perms", action='store_true', help="activate sections permission analysis", default=False)
args = parser.parse_args()


def create_dirs(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    if not os.path.isfile("docker/.panda/vm.qcow2"):
        print("Missing VM, trying to download...")
        r = requests.get("https://uclouvain-my.sharepoint.com/:u:/g/personal/d_wauters_uclouvain_be/EZXz0Kf1U_VEhQSddwlPOI4B_oKqEwY-HmxC5Nv6Wd4WSA?e=09Zg7E&download=1")
        with open("docker/.panda/vm.qcow2", 'wb') as file:
            file.write(r.content)
    if args.build:
        subprocess.run(["docker", "build", "-t", "panda_pandare:latest", "./docker"])

    if not args.entropy and not args.memcheck and not args.dll:
        print("You have to choose at least one type of analysis !\n--entropy\n--memcheck\n--dll")
        sys.exit(1)

    env_args = []
    working_dir = os.getcwd()
    for arg_name in args.__dict__:
        arg_val = args.__dict__[arg_name]
        env_args.append("-e")
        env_args.append(f"panda_{arg_name}={arg_val}")
    if not args.debug:
        subprocess.run(["docker", "run", "--rm", "-v", f"{working_dir}/payload:/payload", "-v", f"{working_dir}/output:/output"] + env_args + ["panda_pandare"])
    else:
        create_dirs("./.debug")
        create_dirs("./replay")
        subprocess.run(["docker", "run", "--rm", "-v", f"{working_dir}/payload:/payload", "-v", f"{working_dir}/output:/output",
                        "-v", f"{working_dir}/dev:/addon", "-v", f"{working_dir}/.debug:/debug", "-v", f"{working_dir}/replay:/replay",
                        "-p", "4443:5900"] + env_args + ["panda_pandare"])

