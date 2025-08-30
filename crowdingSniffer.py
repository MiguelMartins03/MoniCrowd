from _t1ha0_module import ffi, lib
from scapy.all import *
import sqlite3
import signal
import sys

PID_FILE = "/home/kali/Desktop/sniffer.pid"

dr_con = sqlite3.connect('/home/kali/Desktop/MemoryDB/DeviceRecords.db', timeout=30)
dr_cur = dr_con.cursor()

dr_con.execute("PRAGMA journal_mode = WAL")
dr_con.execute("PRAGMA cache_size = -64000")  # 64MB cache

sc_con = sqlite3.connect('/home/kali/Desktop/DB/SensorConfiguration.db', timeout=30)
sc_cur = sc_con.cursor()

PACKET_POWER_FILTRATION = sc_cur.execute("Select Power_Filtration from SensorConfiguration;").fetchone()[0]
sc_con.close()

OUI_DICT = {}
with open("/home/kali/Desktop/wireshark-oui-list.txt", 'r') as file:
    for line in file:
        OUI_DICT[line[:8].strip()] = line[34:].strip()

MOBILE_MANUFACTURERS = set()
with open("/home/kali/Desktop/Mobile_device_manufacturers.txt") as file:
    MOBILE_MANUFACTURERS.update(line.strip().upper() for line in file)

def frame_processing(frame):

    manuf = "Unknown"
    oui = frame[Dot11].addr2[:8].upper().replace(":","-")

    result = OUI_DICT.get(oui)

    if result:
        manuf = result

    if(isMobileManufacturer(manuf)):

        if(frame[Dot11].type == 0):                                                                                 # MANAGEMENT FRAMES

            if(bin(int(frame[Dot11].addr2[1],16))[-2] == '0'):                                                      # Check if 3rd bit from 2nd byte is '1' to verify if MAC is randomized (frame[Dot11].addr2" -> Transmitter/Source Address)
                
                footprint_mac = hex(lib.t1ha0(frame[Dot11].addr2.encode('ASCII'), len(frame[Dot11].addr2), 11))[2:].upper().zfill(16)
                putInToProbeRequestsDB(footprint_mac, manuf)
                #print("Probe Request | Source: " + frame[Dot11].addr2.upper() + " | Footprint: " + footprint_mac + " | SEQ: " + str(int(bin(frame[Dot11].SC)[-12:].lstrip('b'),2)) + " | Power: " + str(frame[RadioTap].dBm_AntSignal) + " dBm | Manuf: " + manuf )
                return

            else:

                ie = frame.getlayer(Dot11Elt)
                array_v = []
                
                while ie:
                    if(ie.ID == 1):                            # Supported Rates
                        array_v.append(ie.ID)
                        array_v.append(ie.len)
                        for c in ie.info:
                            array_v.append(c)
                    
                    elif(ie.ID == 50):                         # Extended Supported Rates
                        array_v.append(ie.ID)
                        array_v.append(ie.len)
                        for c in ie.info:
                            array_v.append(c)
                    
                    elif(ie.ID == 3):                          # DS Parameter Set
                        array_v.append(ie.ID)
                        #array_v.append(ie.len)
                    
                    elif(ie.ID == 45):                         # HT Capabilities
                        array_v.append(ie.ID)
                        array_v.append(ie.len)
                        for i, c in enumerate(ie.info):
                            if(i != 4):
                                array_v.append(c)
                            else:
                                array_v.append(0)
                    
                    elif(ie.ID == 191):                        # VHT Capabilities
                        array_v.append(ie.ID)
                        array_v.append(ie.len)
                        for c in ie.info:
                            array_v.append(c)
                    
                    elif(ie.ID == 127):                        # Extended Capabilities
                        array_v.append(ie.ID)
                        #array_v.append(ie.len)
                        for c in ie.info:
                            array_v.append(c)
                    
                    elif(ie.ID == 70):                         # RM Enabled Capabilities 
                        array_v.append(ie.ID)
                        array_v.append(ie.len)
                        for c in ie.info:
                            array_v.append(c)
                    
                    elif(ie.ID == 107):                        # Interworking
                        array_v.append(ie.ID)
                        array_v.append(ie.len)
                        for c in ie.info:
                            array_v.append(c)
                    
                    elif(ie.ID == 221):                        # Vendor Specific
                        array_v.append(ie.ID)
                        array_v.append(ie.len)
                        for i, c in enumerate(ie.info):
                            if(i != 5 and i != 7):
                                array_v.append(c)
                            else:
                                array_v.append(0)
                    
                    ie = ie.payload
                
                footprint_mac = hex(lib.t1ha0(bytes(array_v), len(array_v), 3))[2:].upper().zfill(16)
                putInToProbeRequestsDB(footprint_mac, manuf)
                #print("Probe Request | Source: " + frame[Dot11].addr2.upper() + " | Footprint: " + footprint_mac + " | SEQ: " + str(int(bin(frame[Dot11].SC)[-12:].lstrip('b'),2)) + " | Power: " + str(frame[RadioTap].dBm_AntSignal) + " dBm | Manuf: " + manuf )
                return
        else:                                                                                                       # DATA FRAMES
            
            if("to-DS" in str(frame[Dot11].FCfield)):

                footprint_mac = hex(lib.t1ha0(frame[Dot11].addr2.encode('ASCII'), len(frame[Dot11].addr2), 11))[2:].upper().zfill(16)
                putInToDataPacketsDB(footprint_mac, manuf)
                #print("Data Packet   | Source: " + frame[Dot11].addr2.upper() + " | Footprint: " + footprint_mac + " | SEQ: " + str(int(bin(frame[Dot11].SC)[-12:].lstrip('b'),2)) + " | Power: " + str(frame[RadioTap].dBm_AntSignal) + " dBm | Manuf: " + manuf )
                return

def putInToProbeRequestsDB(id, manuf):
    res = dr_cur.execute("SELECT * FROM Probe_Requests WHERE ID='" + id + "';")
    if res.fetchone():
        dr_cur.execute("UPDATE Probe_Requests SET Last_Time_Found=current_timestamp WHERE ID='" + id + "';")
    else:
        dr_cur.execute("INSERT INTO Probe_Requests VALUES( 'Probe Request' , '" + id + "' , current_timestamp , current_timestamp , '" + manuf + "');")
    dr_con.commit()

def putInToDataPacketsDB(id, manuf):
    res = dr_cur.execute("SELECT * FROM Data_Packets WHERE ID='" + id + "';")
    if res.fetchone():
        dr_cur.execute("UPDATE Data_Packets SET Last_Time_Found=current_timestamp WHERE ID='" + id + "';")
    else:
        dr_cur.execute("INSERT INTO Data_Packets VALUES( 'Data Packet' , '" + id + "' , current_timestamp , current_timestamp , '" + manuf + "');")
    dr_con.commit()

def isMobileManufacturer(manuf):
    if manuf == "Unknown":
        return True
    return any(mobile_manuf in manuf.upper() for mobile_manuf in MOBILE_MANUFACTURERS)

def signal_term_handler(signal, frame):
    open(PID_FILE, "w").close()
    dr_con.close()
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_term_handler)

conf.layers.filter([RadioTap, Dot11])           # Enable filtering: only RadioTap and Dot11 will be dissected

filter_str = "(wlan type data) || (wlan type mgt subtype probe-req)"

if PACKET_POWER_FILTRATION != 0:
    filter_str += f" && radio [22] > {256 + PACKET_POWER_FILTRATION}"

sniff(
    count=0,
    filter=filter_str,
    prn=frame_processing,
    iface="wlan1",
    store=0,
    monitor=True)