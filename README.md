# PANDA

## How to use
### Download the virtual machine
- Download the vm.qcow2 file from:

https://uclouvain-my.sharepoint.com/:u:/g/personal/d_wauters_uclouvain_be/EZXz0Kf1U_VEhQSddwlPOI4B_oKqEwY-HmxC5Nv6Wd4WSA?e=09Zg7E

- Put the VM (vm.qcow2) in the folder ".panda"

### Execute the software
First, put the malware(s) that need to be analysed under the folder "payload".

Then, there is two main ways of running this program:
- Use the docker-compose provided and launch it with "docker-compose up"
- Use docker directly but don't forget to mount the "payload" volume !

Then content of the "payload" folder will be analysed by PANDA and the result will be shown in the terminal.  
(If you used "docker-compose up -d", the logs are accessible with "docker-compose logs")