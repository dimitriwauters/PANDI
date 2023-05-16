import docker
import requests
import signal
import os
import sys
from argparse import ArgumentParser

working_dir = os.getcwd()
DOCKER_VOLUMES_ARG = {f"{working_dir}/payload": {'bind': '/payload', 'mode': 'rw'},
                      f"{working_dir}/output": {'bind': '/output', 'mode': 'rw'},
                      f"{working_dir}/additional-dll": {'bind': '/dll/additional-dll', 'mode': 'ro'}}
DOCKER_VOLUMES_ARG_DEBUG = DOCKER_VOLUMES_ARG | {f"{working_dir}/docker/dev": {'bind': '/addon', 'mode': 'ro'},
                                                 f"{working_dir}/docker/.panda": {'bind': '/root/.panda', 'mode': 'ro'},
                                                 f"{working_dir}/.debug": {'bind': '/debug', 'mode': 'rw'},
                                                 f"{working_dir}/replay": {'bind': '/replay', 'mode': 'rw'}}

docker_client = docker.from_env()
parser = ArgumentParser()
parser.add_argument("--build", action='store_true', help="rebuild panda image", default=False)
parser.add_argument("--silent", action='store_true', help="don't print anything, just create output files", default=False)
parser.add_argument("--max_parallel_execution", type=int, help="maximum number of simultaneous sample analysis. Depends on the number of available core and memory", default=4)

parser.add_argument("--debug", action='store_true', help="activate verbose mode in debug folder", default=False)
parser.add_argument("--executable", type=str, help="force the selection of only one sample to analyse", default=None)

parser.add_argument("--force_complete_replay", action='store_true', help="force to read the replay until the end", default=False)
parser.add_argument("--max_memory_write_exe_list_length", type=int, help="maximum length of the memory write&executed list before stopping", default=1000)
parser.add_argument("--entropy_granularity", type=int, help="number of basic blocks between computation of entropy. Lower numbers result in higher run times", default=1000)
parser.add_argument("--max_entropy_list_length", type=int, help="maximum length of entropy list before stopping", default=0)

parser.add_argument("--dll_discover_granularity", type=int, help="number of basic blocks between tries to read DLL functions. Lower numbers result in higher run times", default=1000)
parser.add_argument("--max_dll_discover_fail", type=int, help="maximum number of reading fail before stopping discovering process", default=10000)
parser.add_argument("--force_dll_rediscover", action='store_true', help="force to re-do the DLL discovering process and overite the existing save", default=False)

parser.add_argument("--memcheck", action='store_true', help="activate memory write and executed detection", default=False)
parser.add_argument("--entropy", action='store_true', help="activate entropy analysis", default=False)
parser.add_argument("--dll", action='store_true', help="activate syscalls analysis", default=False)
parser.add_argument("--dll_discover", action='store_true', help="activate dll discovering system", default=False)
parser.add_argument("--sections_perms", action='store_true', help="activate sections permission analysis", default=False)
parser.add_argument("--first_bytes", action='store_true', help="activate first bytes analysis", default=False)
args = parser.parse_args()


def create_dirs(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def signal_handler(sig, frame):
    print("\nCTRL-C has been pressed, trying to gracefully shutdown the analysis ...")
    docker_client.containers.get("pandi").stop()
    sys.exit(0)

def check_vm():
    if not os.path.isfile("docker/.panda/vm.qcow2"):
        print("Missing VM, trying to download...")
        r = requests.get("https://uclouvain-my.sharepoint.com/:u:/g/personal/d_wauters_uclouvain_be/EZXz0Kf1U_VEhQSddwlPOI4B_oKqEwY-HmxC5Nv6Wd4WSA?e=09Zg7E&download=1")
        with open("docker/.panda/vm.qcow2", 'wb') as file:
            file.write(r.content)

def does_image_exist():
    try:
        image = docker_client.images.get("panda_pandare")
        return True
    except docker.errors.ImageNotFound:
        return False

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    check_vm()
    if args.build or not does_image_exist():
        docker_client.images.build(path="./docker", tag="panda_pandare:latest")

    if not args.entropy and not args.memcheck and not args.dll and not args.section_perms and not args.first_bytes:
        print("You have to choose at least one type of analysis !\n--entropy\n--memcheck\n--dll\n--section_perms\n--first_bytes")
        sys.exit(1)

    env_args = []
    for arg_name in args.__dict__:
        arg_val = args.__dict__[arg_name]
        env_args.append(f"panda_{arg_name}={arg_val}")
    if not args.debug:
        docker_client.containers.run(image="panda_pandare", volumes=DOCKER_VOLUMES_ARG, environment=env_args, auto_remove=True, name="pandi")
    else:
        create_dirs("./.debug")
        create_dirs("./replay")
        docker_client.containers.run(image="panda_pandare", volumes=DOCKER_VOLUMES_ARG_DEBUG, ports={'5900/udp': 4443}, environment=env_args, auto_remove=True, name="pandi")

