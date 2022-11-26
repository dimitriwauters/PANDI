#wget https://az792536.vo.msecnd.net/vms/VMBuild_20190311/VirtualBox/MSEdge/MSEdge.Win10.VirtualBox.zip
wget https://aka.ms/windev_VM_virtualbox
unzip windev_VM_virtualbox
rm windev_VM_virtualbox
tar -xvf WinDev2210Eval.ova WinDev2210Eval-disk001.vmdk
#sudo apt install qemu-utils
rm WinDev2210Eval.ova
qemu-img convert -O qcow2 WinDev2210Eval-disk001.vmdk win10.qcow2
chmod +x ./win10.qcow2
rm WinDev2210Eval-disk001.vmdk
