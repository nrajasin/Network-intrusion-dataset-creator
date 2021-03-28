# MIT License

# Copyright (c) 2018 nrajasin

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import ipaddress
import set
from services import *

import threading
import subprocess
import json
from queue import *
from detectors import *
from counts import *

# separate out tcp,udp and arp traffic


class packetanalyze (threading.Thread):
    def __init__(self, threadID, name):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name

    def run(self):
        print("detectors.packetanalyze: run()")
        while True:
            if set.sharedQ.empty() == False:
                fortcp = set.sharedQ.get()
                Data = fortcp
                Tcp(Data)

            if set.notTCPQ.empty() == False:
                forudp = set.notTCPQ.get()
                Udp(forudp)

            if set.notUDPQ.empty() == False:
                forarp = set.notUDPQ.get()
                Arp(forarp)

# pass in strings that are the ip addresses from the p;acket
def generateSrcDstKey(src,dst):
    return int(ipaddress.ip_address(src))+int(ipaddress.ip_address(dst))

# Picks interested attributes from packets and saves them into a list
def Tcp(Data):
    # print("TCP\n",Data,"\n")

    try:
        if 'tcp.srcport' in Data and (generateSrcDstKey(Data['ip.src'],Data['ip.dst']) in set.tcp.keys() or generateSrcDstKey(Data['ip.dst'], Data['ip.src']) in set.tcp.keys()):

            try:
                ky = generateSrcDstKey(Data['ip.src'] ,Data['ip.dst'])
                temp = set.tcp[ky]
            except KeyError:
                ky = generateSrcDstKey(Data['ip.dst'], Data['ip.src'])
                temp = set.tcp[ky]
            pack_count = temp[len(temp)-1]
            pack_count = pack_count+1
            # print(pack_count)
            set.servicesQ.put([ky, Data, "tcp"])

            temp.append(Data['ip.src'])
            temp.append(Data['ip.dst'])
            temp.append(Data['tcp.flags.res'])
            temp.append(Data['tcp.flags.ns'])
            temp.append(Data['tcp.flags.cwr'])
            temp.append(Data['tcp.flags.ecn'])
            temp.append(Data['tcp.flags.urg'])
            temp.append(Data['tcp.flags.ack'])
            temp.append(Data['tcp.flags.push'])
            temp.append(Data['tcp.flags.reset'])
            temp.append(Data['tcp.flags.syn'])
            temp.append(Data['tcp.flags.fin'])
            temp.append(pack_count)

            set.tcp[ky] = temp
            set.tcp_count = set.tcp_count+1
        elif 'ip.src' in Data and 'tcp.flags.syn' in Data:

            status = []
            pack_count = 1

            status.append(Data['ip.src'])
            status.append(Data['ip.dst'])
            status.append(Data['tcp.flags.res'])
            status.append(Data['tcp.flags.ns'])
            status.append(Data['tcp.flags.cwr'])
            status.append(Data['tcp.flags.ecn'])
            status.append(Data['tcp.flags.urg'])
            status.append(Data['tcp.flags.ack'])
            status.append(Data['tcp.flags.push'])
            status.append(Data['tcp.flags.reset'])
            status.append(Data['tcp.flags.syn'])
            status.append(Data['tcp.flags.fin'])
            status.append(pack_count)
            set.tcp[            generateSrcDstKey(Data['ip.src'], Data['ip.dst'])] = status
            set.servicesQ.put([ generateSrcDstKey(Data['ip.src'], Data['ip.dst']), Data, "tcp"])
            set.tcp_count = set.tcp_count+1
        else:
            set.notTCPQ.put(Data)

    except AttributeError:
        print(Data)


def Udp(Data):

    try:

        if 'udp.srcport' in Data and (generateSrcDstKey(Data['ip.src'],Data['ip.dst']) in set.udp.keys() or generateSrcDstKey(Data['ip.dst'],Data['ip.src']) in set.udp.keys()):

            try:
                ky = generateSrcDstKey(Data['ip.src'],Data['ip.dst'])
                temp = set.udp[ky]
            except KeyError:
                ky = generateSrcDstKey (Data['ip.dst'],Data['ip.src'])
                temp = set.udp[ky]

            set.servicesQ.put([ky, Data, "udp"])

            set.udp_count = set.udp_count+1

        elif 'udp.srcport' in Data:

            status = []
            # status.append(Data)
            status.append(Data['ip.src'])
            status.append(Data['ip.dst'])
            status.append(Data['udp.srcport'])
            status.append(Data['udp.dstport'])
            status.append(1)
            set.udp[           generateSrcDstKey(Data['ip.src'],Data['ip.dst'])] = status
            set.servicesQ.put([generateSrcDstKey(Data['ip.src'],Data['ip.dst']), Data, "udp"])
            set.udp_count = set.udp_count+1

        else:

            set.notUDPQ.put(Data)

    except KeyError:

        if 'udp.srcport' in Data and (int(ipaddress.IPv6Address(Data['ipv6.src']))+int(ipaddress.IPv6Address(Data['ipv6.dst'])) in set.udp.keys() or int(ipaddress.IPv6Address(Data['ipv6.dst']))+int(ipaddress.IPv6Address(Data['ipv6.src'])) in set.udp.keys()):

            try:
                ky = int(ipaddress.IPv6Address(
                    Data['ipv6.src']))+int(ipaddress.IPv6Address(Data['ipv6.dst']))
                temp = set.udp[ky]
            except KeyError:
                ky = int(ipaddress.IPv6Address(
                    Data['ipv6.dst']))+int(ipaddress.IPv6Address(Data['ipv6.src']))
                temp = set.udp[ky]

            set.servicesQ.put([ky, Data, "udp"])

            set.udp_count = set.udp_count+1

        elif 'udp.srcport' in Data:
            status = []
            status.append(Data['ipv6.src'])
            status.append(Data['ipv6.dst'])
            status.append(Data['udp.srcport'])
            status.append(Data['udp.dstport'])
            status.append(1)
            set.udp[int(ipaddress.IPv6Address(Data['ipv6.src'])) +
                    int(ipaddress.IPv6Address(Data['ipv6.dst']))] = status
            set.servicesQ.put([int(ipaddress.IPv6Address(
                Data['ipv6.src']))+int(ipaddress.IPv6Address(Data['ipv6.dst'])), Data, "udp"])

            set.udp_count = set.udp_count+1
        else:
            set.notUDPQ.put(Data)


def Arp(Data):

    try:

        if 'arp.src.proto_ipv4' in Data and ( generateSrcDstKey(Data['arp.src.proto_ipv4'],Data['arp.dst.proto_ipv4']) in set.arp.keys() or generateSrcDstKey(Data['arp.dst.proto_ipv4'],Data['arp.src.proto_ipv4']) in set.arp.keys()):

            try:
                ky = generateSrcDstKey(Data['arp.src.proto_ipv4'],Data['arp.dst.proto_ipv4'])
                temp = set.arp[ky]
            except KeyError:
                ky = generateSrcDstKey(Data['arp.dst.proto_ipv4'],Data['arp.src.proto_ipv4'])
                temp = set.arp[ky]

            pack_count = temp[len(temp)-1]
            pack_count = pack_count+1

            temp.append(Data['arp.src.proto_ipv4'])
            temp.append(Data['arp.dst.proto_ipv4'])
            temp.append(Data['arp.src.hw_mac'])
            temp.append(Data['arp.dst.hw_mac'])
            temp.append(pack_count)
            set.servicesQ.put([ky, Data, "arp"])

            set.arp_count = set.arp_count+1
        elif 'arp.src.proto_ipv4' in Data:

            # print('Tcp connection initiated')
            status = []
            pack_count = 1
            # status.append('ip.src')
            status.append(Data['arp.src.proto_ipv4'])
            # status.append('ip.dst')
            status.append(Data['arp.dst.proto_ipv4'])
            # status.append('tcp.flags.syn')
            status.append(Data['arp.src.hw_mac'])
            status.append(Data['arp.dst.hw_mac'])

            status.append(pack_count)
            set.arp[           generateSrcDstKey(Data['arp.src.proto_ipv4'],Data['arp.dst.proto_ipv4'])] = status
            set.servicesQ.put([generateSrcDstKey(Data['arp.src.proto_ipv4'],Data['arp.dst.proto_ipv4']), Data, "arp"])
            set.arp_count = set.arp_count+1
        else:
            set.notARPQ.put(Data)

    except AttributeError:
        print(Data)
