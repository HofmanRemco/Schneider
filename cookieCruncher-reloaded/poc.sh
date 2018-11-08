#!/bin/bash

# rm -f PlcLog.txt
# wget --quiet ${1}/usr/Syslog/PlcLog.txt
grep "Network interface <interface>USB</interface> registered" PlcLog.txt | tail -n1 | cut -d',' -f1