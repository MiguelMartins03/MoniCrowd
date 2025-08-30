# Crowd_Detection_STToolkit

1. A wlan1 tem que ser colocada em modo "unmanaged" para não interferir com o normal funcionamento do sensor (https://support.qacafe.com/cdrouter/knowledge-base/prevent-network-manager-from-controlling-an-interface/)
2. Tem que ser adicionada a linha "tmpfs    /home/kali/Desktop/MemoryDB tmpfs   rw,nodev,nosuid,size=500M 0 0" ao ficheiro /etc/fstab para criar um "RAM disk" (https://ryan.himmelwright.net/post/tmpfs-mount-ramdisk/). O diretório "MemoryDB" também tem que ser criado no /Desktop