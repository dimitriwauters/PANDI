# PANDI

PANDI is a ***dynamic packing detection*** solution built on top of PANDA (https://github.com/panda-re/panda), a platform for Architecture-Neutral Dynamic Analysis.
TODO   
PANDI is currently developed at UCLouvain (Belgium) and is available under [TODO] license.

## How to use
***First, put the malware(s) that need to be analysed under the folder "payload".***  
Then, there is two main ways of running this program:
- Use launch.py
- Use the docker-compose provided

### Launching the packing detector
#### Launch.py
This script is an interface between the Docker implementation of PANDA and the host machine.  
It allows the user to easily modify the parameters of the software, as shown below.  
It will also download automatically the Windows VM needed to run PANDA and build the Docker image.
```
usage: launch.py [-h] [--build] [--silent] [--debug] [--executable EXECUTABLE] [--force_complete_replay] [--max_memory_write_exe_list_length MAX_MEMORY_WRITE_EXE_LIST_LENGTH] [--entropy_granularity ENTROPY_GRANULARITY]
                 [--max_entropy_list_length MAX_ENTROPY_LIST_LENGTH] [--dll_discover_granularity DLL_DISCOVER_GRANULARITY] [--max_dll_discover_fail MAX_DLL_DISCOVER_FAIL] [--force_dll_rediscover] [--memcheck] [--entropy] [--dll]
                 [--dll_discover] [--sections_perms] [--first_bytes]

options:
  -h, --help            show this help message and exit
  --build               rebuild panda image
  --silent              only print the result in JSON format
  --debug               activate verbose mode
  --executable EXECUTABLE
                        force the selection of one software
  --force_complete_replay
                        read the replay until the end
  --max_memory_write_exe_list_length MAX_MEMORY_WRITE_EXE_LIST_LENGTH
                        maximum length of the returned list before exiting
  --entropy_granularity ENTROPY_GRANULARITY
                        number of basic blocks between samples. Lower numbers result in higher run times
  --max_entropy_list_length MAX_ENTROPY_LIST_LENGTH
                        maximum length of entropy list before exiting
  --dll_discover_granularity DLL_DISCOVER_GRANULARITY
                        maximum length of the returned list before exiting
  --max_dll_discover_fail MAX_DLL_DISCOVER_FAIL
                        maximum length of the returned list before exiting
  --force_dll_rediscover
                        read the replay until the end
  --memcheck            activate memory write and executed detection
  --entropy             activate entropy analysis
  --dll                 activate syscalls analysis
  --dll_discover        activate dll discovering system
  --sections_perms      activate sections permission analysis
  --first_bytes         activate first bytes analysis
```

#### docker-compose
Before using the provided docker-compose, the virtual machine that will be used to perform the analysis need to be downloaded.   
You can find it by following this link: https://uclouvain-my.sharepoint.com/:u:/g/personal/d_wauters_uclouvain_be/EZXz0Kf1U_VEhQSddwlPOI4B_oKqEwY-HmxC5Nv6Wd4WSA?e=09Zg7E   
(or by performing the procedure of creating a new virtual machine)

Once the virtual machine is downloaded, the process can be launched as any docker-compose project.

### Importing additional DLLs
There is the possibility to add new DLL that are not present in the virtual machine.
This might be interesting in the case of a sample that need a specific DLL that is not standard.   
To add these DLLs to the virtual machine, you can simply put them in the `additional-dll` folder and they will be loaded
in parallel to the sample.

## Usage
The five possible options of this software can be combined but at least one must be enabled.  
Some parameters can be tweaked to modify the behavior of the whole software. These parameters are:
- `--build`
- `--silent` (or `panda_silent=False`)
- `--debug` (or `panda_debug=False`)
- `--executable` (or `panda_executable=None`)

### Memory Write&Execution Detection
>This option must be activated with the `--memcheck` parameter on `launch.py` or by modifying the `docker-compose.yml` file by adding `panda_memcheck=True` in the environment variables.

This memory check process will be responsible to analyse the memory of a given software by detecting each time it tries
to execute a piece of memory that it has previously written to. If this list of written-then-executed memory portion is
not empty and contains some consecutive addresses, we can consider that the analysed software is in fact packed.

This analysis works by using the `@panda.cb_virt_mem_after_write` callback from PANDA to register each memory address
written. Then a second callback `@panda.cb_before_block_exec` will be responsible to detect
when a previously written address (known by the first syscall) is currently executed.

Some parameters can be tweaked to modify the behavior of this option. These parameters are:
- `--max_memory_write_exe_list_length=1000` (or `panda_max_memory_write_exe_list_length=1000`) define the maximum length
of the writen-then-executed list before cutting the analysis. This allows to reduce the execution time when there is enough
data. The default value of this parameter is a length of 1000.

### Entropy Analysis
>This option must be activated with the `--entropy` parameter on `launch.py` or by modifying the `docker-compose.yml` file by adding `panda_entropy=True` in the environment variables.   
> This option will need the help of machine learning to give the result.

The entropy analysis will gather the entropy of each of the program section at every execution of a basic block
(with a defined granularity). These entropy points will then be used to construct some statistics to determine, with the
help of some machine learning, if the analysed software is packed or not.   
The entry point of the software and the entry point of the unpacked software (if any) will be also used to extract statistics.

Some parameters can be tweaked to modify the behavior of this option. These parameters are:
- `--entropy_granularity=1000` (or `panda_entropy_granularity=1000`) define the granularity to adopt between two analysis
of the entropy. We use the basic blocks of PANDA as our metric and analysis only a portion of them to minimize the time
needed to finish the whole analysis. Here we defined that the entropy is computed every 1000 basic block.
- `--max_entropy_list_length=0` (or `panda_max_entropy_list_length=0`) define the maximum length of the list containing
the computed entropy of the sections. If the length of this list reach the limit, the entropy analysis is stopped. The
default value for this parameter is 0, meaning that the list can be any size.

A file is generated with the result of the entropy analysis under the `./output` directory. It is also possible to 
see a visual representation of the entropy points can also be obtained by running the python script 
`entropy_graph.py [SOFTWARE_NAME] [SECTION_TO_SHOW] [IS_DETECTED_AS_PACKED]`.

### Syscalls Analysis
>This option must be activated with the `--dll` parameter on `launch.py` or by modifying the `docker-compose.yml` file by adding `panda_dll=True` in the environment variables.   
> This option will need the help of machine learning to give the result.

This analysis will recover the initially imported function by recovering the IAT (Import Address Table) of the software
and raising an event when the address currently executed correspond to an imported function. It also detects (thanks to
the `syscalls2` PANDA plugin) when a DLL is used and produce a list of used DLL before and after the detected entry point
of the unpacked part of the software (if any).

If the initial IAT contains `GetProcAddress` or `LoadLibrary`, this module is able to count the number of times these
functions are called and also recover the imported function or DLL to later detect their usage.   
The data collected on these syscalls will be used, in a machine learning algorithm, to determine if the analysed software
is packed or not.

### Automatic DLL Discovery
>This option must be activated with the `--dll_discovery` parameter on `launch.py` or by modifying the `docker-compose.yml` file by adding `panda_dll_discovery=True` in the environment variables.

This option is usefull in the cas of a corrupted/missing/stripped IAT (Import Address Table).
It will parse the DLLs loaded in memory by the sample to analyse and parse it to discover the exported function of these loaded DLL.
Meaning that we will not need anymore to parse the IAT to recover the addresses of each function that will be called by the sample,
we will know them before the execution of the sample.

To limit the overhead of this option, the result is saved into a file available at `/payload/dll` and will be used
for the next analysis. If you don't want to reuse the previously computed result, you can delete the file or add the
`--force_dll_rediscover` on `launch.py` or add `panda_force_dll_rediscover=True` in the environment parameters of the `docker-compose.yml`.

This option must be used in parallel to the [Syscalls Analysis](#syscalls-analysis) section. It will benefit from the discovered
DLLs to perform its analysis. This option will not work alone.

Some parameters can be tweaked to modify the behavior of this option. These parameters are:
- `--dll_discover_granularity=1000` (or `panda_dll_discover_granularity=1000`) define the granularity to adopt between 
two analysis of the loaded DLL in-memory. This parameter is exactly like the one for the entropy. The default value is 
an analysis every 1000 basic block.
- `--max_dll_discover_fail=10000` (or `panda_max_dll_discover_fail=10000`) define the maximum number of failure authorized 
before shutting down the discovery of DLL functions. Not every function of the DLL are mapped in-memory when loading the DLL
meaning that some will throw an error when trying to get information about them, this is the type of failure we see here.
The default value is fixed at 10 000 errors.
- `--force_dll_rediscover=False` (or `panda_force_dll_rediscover=False`) force the re-discovery of DLL functions even if
it was already done in the past, like explained above.

### Section Permissions Modification Detection
>This option must be activated with the `--section_perms` parameter on `launch.py` or by modifying the `docker-compose.yml` file by adding `panda_section_perms=True` in the environment variables.   
> This option will need the help of machine learning to give the result.

This analysis make an additional verification regarding the headers of the executable. It recovers the initial permissions
of the different sections at the beginning of the execution and tries at multiple times during the execution of the sample
to write in the section if it was previously announced at read-only.

It allows to know if the section permissions have been changed during the execution of the program, giving an indication
that the sample may perform an unpacking procedure.

### First Bytes Extraction
>This option must be activated with the `--first_bytes` parameter on `launch.py` or by modifying the `docker-compose.yml` file by adding `panda_first_bytes=True` in the environment variables.   
> This option will need the help of machine learning to output the result.

TODO

## Output (results)
TODO

## Evaluation - Examples
TODO

## Improvements
TODO

### Exact Unpacked Entry-Point Detection
Currently, the entry-point of the unpacked program is detected but this detection is not precise.
As not every instruction is observed to reduce the process time, the exact entry-point can happen between two lookups.
This means that the analysis will detect an approximation of the entry-point (for example 1000 instructions later) but not the exact one.

To scope with that, we can think of two approaches:
- The first one will be simple to set the granularity to zero with the variable `panda_entropy_granularity` but this will
significantly increase the time needed to finish the analysis as every instruction will be analysed.
- The second needs a little more work. It can be done by setting temporarily the variable `panda_entropy_granularity`
to 0 when we see that the entry-point of the unpacked code is close. For example when a dynamically imported function is 
called (DYNAMIC_DLL).

This functionality as not been implemented as the purpose of this software is not to exact the unpacked data but only
to define if the provided sample is packed or not.

## Build VM from scratch
In case if you want to build your own VM or the given link is broken, this section will present how to rebuild the VM for PANDA.

* Download a Windows 7 x86 virtual machine from a known source   
For example: https://az792536.vo.msecnd.net/vms/VMBuild_20150916/VirtualBox/IE8/IE8.Win7.VirtualBox.zip
* Transform the virtual machine into a QEMU compatible one (if not already)   
For example with `qemu-utils` on Linux
* Launch the virtual machine, open a prompt and make a snapshot of the machine (on the slot 1)
  * To perform that, a script has been made. It can be launched with `docker-compose -f docker-compose.newvm.yml run pandare`
  * You can add, prior launching the script, some file you will want to launch on the VM. Those files can be put a folder called `new-vm`
  * Now connect to the VM with a VNC viewer (like Remmina) trough the IP of the docker container
  * Install the program you want and finish by opening a prompt
  * Once its done, type `finished` in the console (where you typed `docker-compose -f docker-compose.newvm.yml run pandare`)
  * The VM is now ready to be used !
  * (If you don't want to save the modification you have done, you can type anything in the console and the snapshot will not be saved)
* Name the virtual machine as `vm.qcow2` and place the file under the folder `./docker/.panda`
* ENJOY