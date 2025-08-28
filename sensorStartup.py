import subprocess
import os

PID_FILE = "/home/kali/Desktop/sniffer.pid"

os.system("sudo iwconfig wlan1 channel 1")

snifferProcess = subprocess.Popen(
    ["sudo", "/usr/bin/python3", "/home/kali/Desktop/crowdingSniffer.py"]#,
    #stdout=subprocess.PIPE,
    #stderr=subprocess.PIPE,
    #text=True
)

with open(PID_FILE, "w") as f:
    f.write(str(snifferProcess.pid))

hopperProcess = subprocess.Popen(
    ["sudo", "/usr/bin/python3", "/home/kali/Desktop/channelHopper.py"]
)