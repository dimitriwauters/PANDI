wget https://az792536.vo.msecnd.net/vms/VMBuild_20150916/VirtualBox/IE8/IE8.Win7.VirtualBox.zip
unzip IE8.Win7.VirtualBox.zip
rm IE8.Win7.VirtualBox.zip
tar -xvf "IE8 - Win7.ova" "IE8 - Win7-disk1.vmdk"
#sudo apt install qemu-utils
rm "IE8 - Win7.ova"
qemu-img convert -O qcow2 "IE8 - Win7-disk1.vmdk" win7.qcow2
chmod +x ./win7.qcow2
rm "IE8 - Win7-disk1.vmdk"
