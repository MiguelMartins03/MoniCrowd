#!/bin/bash

LOGFILE="/home/kali/Desktop/wifi_check.log"
NICKNAME_EXPECTED='<WIFI@REALTEK>'

# Capture iwconfig output (again)
iwout=$(iwconfig wlan1 2>/dev/null)

# Extract the nickname safely using awk
nickname=$(echo "$iwout" | grep -o 'Nickname:".*"' | cut -d: -f2 | tr -d '"')

# Compare with expected
if [ "$nickname" = "$NICKNAME_EXPECTED" ]; then
    echo "$(date) - Nickname is correct. No reboot needed." >> "$LOGFILE"
else
    echo "$(date) - Nickname is incorrect or missing. Rebooting..." >> "$LOGFILE"
    sleep 15 && sudo reboot
fi
