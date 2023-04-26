# ABCD

ABCD is a ***packing detection*** solution built on top of PANDA (https://github.com/panda-re/panda), a platform for Architecture-Neutral Dynamic Analysis.
TODO   
ABCD is currently developed at UCLouvain (Belgium) and is available under [TODO] license.

## How to use
***First, put the malware(s) that need to be analysed under the folder "payload".***  
Then, there is two main ways of running this program:
- Use launch.py
- Use the docker-compose provided

### Launch.py
This script is an interface between the Docker implementation of PANDA and the host machine.  
It allows the user to easily modify the parameters of the software, as shown below.  
It will also download automatically the Windows VM needed to run PANDA and build the Docker image.
```
usage: launch.py [-h] [--build] [--silent] [--debug] [--executable EXECUTABLE] [--force_complete_replay] [--max_memory_write_exe_list_length MAX_MEMORY_WRITE_EXE_LIST_LENGTH] [--entropy_granularity ENTROPY_GRANULARITY]
                 [--max_entropy_list_length MAX_ENTROPY_LIST_LENGTH] [--memcheck] [--entropy]

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
  --memcheck            activate memory write and executed detection
  --entropy             activate entropy analysis
```

### docker-compose
Before using the provided docker-compose, the virtual machine that will be used to perform the analysis need to be downloaded.   
You can find it by following this link: https://uclouvain-my.sharepoint.com/:u:/g/personal/d_wauters_uclouvain_be/EZXz0Kf1U_VEhQSddwlPOI4B_oKqEwY-HmxC5Nv6Wd4WSA?e=09Zg7E   
(or by performing the procedure of creating a new virtual machine)

Once the virtual machine is downloaded, the process can be launched as any docker-compose project.

## Usage
The five possible options of this software can be combined but at least one must be enabled.

### Memory Write&Execution Detection
>This option must be activated with the `--memcheck` parameter on `launch.py` or by modifying the `docker-compose.yml` file by adding `panda_memcheck=True` in the environment variables.

This memory check process will be responsible to analyse the memory of a given software by detecting each time it tries
to execute a piece of memory that it has previously written to. If this list of written-then-executed memory portion is
not empty and contains some consecutive addresses, we can consider that the analysed software is in fact packed.

This analysis works by using the `@panda.cb_virt_mem_after_write` callback from PANDA to register each memory address
written. Then a second callback `@panda.cb_before_block_exec` will be responsible to detect
when a previously written address (known by the first syscall) is currently executed.

### Entropy Analysis
>This option must be activated with the `--entropy` parameter on `launch.py` or by modifying the `docker-compose.yml` file by adding `panda_entropy=True` in the environment variables.

The entropy analysis will gather the entropy of each of the program section at every execution of a basic block
(with a defined granularity). These entropy points will then be used to construct some statistics to determine, with the
help of some machine learning, if the analysed software is packed or not.   
The entry point of the software and the entry point of the unpacked software (if any) will be also used to extract statistics.

A file is generated with the result of the entropy analysis under the `./output` directory. It is also possible to 
see a visual representation of the entropy points can also be obtained by running the python script 
`entropy_graph.py [SOFTWARE_NAME] [SECTION_TO_SHOW] [IS_DETECTED_AS_PACKED]`.

### Syscalls Analysis
>This option must be activated with the `--dll` parameter on `launch.py` or by modifying the `docker-compose.yml` file by adding `panda_dll=True` in the environment variables.

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

### Section Permissions Modification Detection
>This option must be activated with the `--section_perms` parameter on `launch.py` or by modifying the `docker-compose.yml` file by adding `panda_section_perms=True` in the environment variables.

This analysis make an additional verification regarding the headers of the executable. It recovers the initial permissions
of the different sections at the beginning of the execution and tries at multiple times during the execution of the sample
to write in the section if it was previously announced at read-only.

It allows to know if the section permissions have been changed during the execution of the program, giving an indication
that the sample may perform an unpacking procedure.

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
* Name the virtual machine as `vm.qcow2` and place the file under the folder `./docker/.panda`
* ENJOY