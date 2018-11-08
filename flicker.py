#!/usr/bin/python3
from scapy.all import *

payload = b"\xcc\x85\x5b\x51\x08\x03\x55\x0f\x6f\x79\x0d\x53\x47\x55\xc6\x14\x04\x6d\x9e\x33\x6a\x75\x76\x6c\xb9\xc2\x58\x40\x80\x72\x6e\x66\xf6\x73\x2a\xdc\x62\x47\x58\x55\x5a\x47\x59\x6c\x38"

crafted = Ether(src="00:0c:29:3d:27:d1", dst="ff:ff:ff:ff:ff:ff") /\
    IP(version=4, ihl=5, id=0, tos=0, src="172.20.3.45", dst="255.255.255.255", ttl=128, options=[]) /\
    UDP(sport=61994, dport=27127) /\
    Raw(load=payload)

sendp(crafted, iface='enp0s31f6')
