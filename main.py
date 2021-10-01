from scapy.all import scapy
from scapy.all import ICMP
from scapy.all import  ls, IP 
from scapy.all import  sr1
from scapy.all import  sr
# import logging
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

if __name__ == "__main__":
    src_ip = "192.168.0.1/24"   
    dest_ip = "www.google.com"

    ip_layer = IP(src = src_ip, dst = dest_ip)
    # print(ip_layer.show())
    # print("Destination = ", ip_layer.dst)
    print("HERE", ls(ip_layer))

    icmp_req = ICMP(id=100)
    # print(icmp_req.show())

    packet = ip_layer / icmp_req
    print("combined layers into sigle packet:", packet.show())

    response = sr1(IP(dst= dest_ip)/icmp_req)

    response = sr1(packet, iface="eth0")
    if response:
        print("response: " , response.show())

    print("Summary :", ip_layer.summary())