#!/usr/bin/python3
from scapy.all import *
import time

pkt = rdpcap('reversing.pcapng')[0]

# First 20 bits contain the command?
#       b"\xc5\x74\x4" 36bits
command = b"\xc5\x74\x40"

#       b"0\x03\x00\x30\x7a\xf5" 44bits
data1 = b"\x03\x00\x30\x7a\xf5"

# This is the address the plc will respond to.
# Depending on the network mask the first bits will not matter, as they are used from the plc's configuration.
# NOTE1: I noticed that the first two bytes should be set to 0 or lte 0x0f when added if the netmask is /16?
#        We should see if this behaviour continues if we set the netmask to /24 or more exotic ones.
reply_ip = bytes([0, 0, 3, 2])

# No idea what this is, presumably extra function data?
# Byte0: ?
# Byte1: ?
# Byte2: ?
# Byte3: ?
# Byte4: ?
# Byte5: Seems to be fixed at 0xc2
#       b"\x90\x00\x00\x00\x02\xc2" 48bits
data2 = b"\x90\x00\x00\x00\x02\xc2"
data2 = bytes([145, 0, 0, 0, 2, 194])

# This doesn't seem to alter the response, so padding?
#         b"\x03\x01\x3f\xaa\x00\x00" 48bits
padding = b"\xff\xff\xff\xff\xff\xff"

#                        64bits                32bits              48bits                 48bits
#          <--------------todo---------->  <--reply_ip-->  <--------todo-------->  <------padding?------>
#          ??  ??  ??  ??  ??  ??  ??  ??  ip  ip  ip  ip  ??  ??  ??  ??  ??  ??  ??  ??  ??  ??  ??  ??
# data = b"\xc5\x74\x40\x03\x00\x30\x7a\xf5\x00\x00\x03\x2D\x90\x00\x00\x00\x02\xc2\x03\x01\x3f\xaa\x00\x00" 192 bits

for b in range(600):
    # data2 = bytes([b, 0, 0, 0, 2, 194])

    data = command+data1+reply_ip+data2+padding

    pkt[IP].src = '172.20.3.2'
    pkt[IP].dst = '172.20.255.255'
    pkt[Raw].load = data
    del pkt[IP].len
    del pkt[UDP].len
    del pkt[IP].chksum
    del pkt[UDP].chksum

    # sendp(pkt, iface='enp0s31f6')
    sendp(pkt, iface='Realtek PCIe GBE Family Controller')
    time.sleep(0.5)
