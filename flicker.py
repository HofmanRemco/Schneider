#!/usr/bin/python3
from scapy.all import *

payload = bytearray([
    0xcc, 0x85, 0x5b, 0x51, 0x08, 0x03, 0x55, 0x0f,
    0x6f, 0x79, 0x0d, 0x53, 0x47, 0x55, 0xc6, 0x14,
    0x04, 0x6d, 0x9e, 0x33, 0x6a, 0x75, 0x76, 0x6c,
    0xb9, 0xc2, 0x58, 0x40, 0x80, 0x72, 0x6e, 0x66,
    0xf6, 0x73, 0x2a, 0xdc, 0x62, 0x47, 0x58, 0x55,
    0x5a, 0x47, 0x59, 0x6c, 0x38
])

crafted = Ether(dst="ff:ff:ff:ff:ff:ff") /\
    IP(src="0.0.0.0", dst="255.255.255.255") /\
    UDP(sport=0, dport=27127) /\
    Raw(load=bytes(payload))

# sendp(crafted, iface='enp0s31f6')
sendp(crafted, iface='Realtek PCIe GBE Family Controller')
