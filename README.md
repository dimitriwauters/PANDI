# PANDA

## How to use
First, put the malware(s) that need to be analysed under the folder "payload".  
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
TODO

## Usage
The two possible usages of this software can be combined but at least one must be enabled.
### Memory Write&Execution Detection
This option must be activated with the ```--memcheck``` parameter on ```launch.py``` or by modifying the ```docker-compose.yml``` file by adding ```panda_memcheck=True``` in the environment variables.

### Entropy Analysis
This option must be activated with the ```--entropy``` parameter on ```launch.py``` or by modifying the ```docker-compose.yml``` file by adding ```panda_entropy=True``` in the environment variables.