# Crowd_Detection_STToolkit

1. The wlan1 interface has to be put in "unmanaged" mode so that the Network Manager doesn't interfere with sensor <br>
(https://support.qacafe.com/cdrouter/knowledge-base/prevent-network-manager-from-controlling-an-interface/) <br>
Create a file in **/etc/NetworkManager/conf.d/** named **unmanage.conf** and add the following text:
```
[main]
plugins=ifcfg-rh,keyfile

[keyfile]
unmanaged-devices=interface-name:wlan1
```
2. The following line has to be added to the **/etc/fstab** file for the "RAM disk" to be created on startup: <br>
`tmpfs    /home/kali/Desktop/MemoryDB tmpfs   rw,nodev,nosuid,size=500M 0 0` <br>
(https://ryan.himmelwright.net/post/tmpfs-mount-ramdisk/) <br>
A directory named "MemoryDB" has to be created on /Desktop
3. It may be necessary to run **build_t1ha0_module.py** located in /home/kali/Desktop/t1ha0