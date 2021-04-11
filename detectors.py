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
                packetUnderExamination = set.sharedQ.get()
                if Tcp(packetUnderExamination) == False: 
                    if Udp(packetUnderExamination) == False:
                        if Arp(packetUnderExamination) == False:
                            if Igmp(packetUnderExamination) == False:
                                print("Error was not TCP, UDP, ARP, IGMP proto type:",packetUnderExamination['ip.proto'])
                                print(packetUnderExamination)


# pass in strings that are the ip addresses from the packet
def generateSrcDstKey(src,dst):
    return int(ipaddress.ip_address(src))+int(ipaddress.ip_address(dst))

# pass in strings that are the ip addresses from the packet
def generateIPv6SrcDstKey(src,dst):
    return int(ipaddress.IPv6Address(src))+int(ipaddress.IPv6Address(dst))

# we mutate a parameter. oh the horror!
def populateBucket(ListBucket, Data, pack_count, ipSrcKey, ipDstKey):
    ListBucket.append(Data[ipSrcKey])
    ListBucket.append(Data[ipDstKey])
    ListBucket.append(Data['tcp.flags.res'])
    ListBucket.append(Data['tcp.flags.ns'])
    ListBucket.append(Data['tcp.flags.cwr'])
    ListBucket.append(Data['tcp.flags.ecn'])
    ListBucket.append(Data['tcp.flags.urg'])
    ListBucket.append(Data['tcp.flags.ack'])
    ListBucket.append(Data['tcp.flags.push'])
    ListBucket.append(Data['tcp.flags.reset'])
    ListBucket.append(Data['tcp.flags.syn'])
    ListBucket.append(Data['tcp.flags.fin'])
    ListBucket.append(pack_count)

# Picks interested attributes from packets and saves them into a list
def Tcp(Data):
    # print("TCP\n",Data,"\n")

    success = False

    try:
        if 'tcp.srcport' in Data and (generateSrcDstKey(Data['ip.src'],Data['ip.dst']) in set.tcp.keys() or generateSrcDstKey(Data['ip.dst'], Data['ip.src']) in set.tcp.keys()):

            try:
                ky = generateSrcDstKey(Data['ip.src'] ,Data['ip.dst'])
                temp = set.tcp[ky]
            except KeyError:
                ky = generateSrcDstKey(Data['ip.dst'], Data['ip.src'])
                temp = set.tcp[ky]
            pack_count = temp[len(temp)-1]
            pack_count +=1
            # print(pack_count)
            populateBucket(temp,Data,pack_count,'ip.src', 'ip.dst')

            set.servicesQ.put([ky, Data, "tcp"])
            set.tcp[ky] = temp
            set.tcp_count +=1
            success=True
        elif 'ip.src' in Data and 'tcp.flags.syn' in Data:

            ky = generateSrcDstKey(Data['ip.src'], Data['ip.dst'])
            status = []
            pack_count = 1
            populateBucket(status, Data, pack_count, 'ip.src', 'ip.dst')

            set.servicesQ.put([ ky, Data, "tcp"])
            set.tcp[ky] = status
            set.tcp_count +=1
            success=True
        else:
            success=False
    except KeyError:
        if 'tcp.srcport' in Data and (generateIPv6SrcDstKey(Data['ipv6.src'],Data['ipv6.dst']) in set.tcp.keys() or generateIPv6SrcDstKey(Data['ipv6.dst'], Data['ipv6.src']) in set.tcp.keys()):

            try:
                ky = generateIPv6SrcDstKey(Data['ipv6.src'] ,Data['ipv6.dst'])
                temp = set.tcp[ky]
            except KeyError:
                ky = generateIPv6SrcDstKey(Data['ipv6.dst'], Data['ipv6.src'])
                temp = set.tcp[ky]
            pack_count = temp[len(temp)-1]
            pack_count +=1
            # print(pack_count)
            populateBucket(temp,Data,pack_count,'ipv6.src', 'ipv6.dst')

            set.servicesQ.put([ky, Data, "tcp"])
            set.tcp[ky] = temp
            set.tcp_count +=1
            success=True
        elif 'ipv6.src' in Data and 'tcp.flags.syn' in Data:

            ky = generateIPv6SrcDstKey(Data['ipv6.src'], Data['ipv6.dst'])
            status = []
            pack_count = 1
            populateBucket(status, Data, pack_count, 'ipv6.src', 'ipv6.dst')

            set.servicesQ.put([ ky, Data, "tcp"])
            set.tcp[ky] = status
            set.tcp_count +=1
            success=True
        else:
            success=False

    except AttributeError:
        print(Data)
    return success


def Udp(Data):

    success = False
    try:

        if 'udp.srcport' in Data and (generateSrcDstKey(Data['ip.src'],Data['ip.dst']) in set.udp.keys() or generateSrcDstKey(Data['ip.dst'],Data['ip.src']) in set.udp.keys()):

            try:
                ky = generateSrcDstKey(Data['ip.src'],Data['ip.dst'])
                temp = set.udp[ky]
            except KeyError:
                ky = generateSrcDstKey (Data['ip.dst'],Data['ip.src'])
                temp = set.udp[ky]

            set.servicesQ.put([ky, Data, "udp"])

            set.udp_count +=1
            success = True
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
            set.udp_count +=1
            success = True
        else:
            success = False
    except KeyError:

        if 'udp.srcport' in Data and (generateIPv6SrcDstKey(Data['ipv6.src'],Data['ipv6.dst']) in set.udp.keys() or generateIPv6SrcDstKey(Data['ipv6.dst'],Data['ipv6.src']) in set.udp.keys()):

            try:
                ky = generateIPv6SrcDstKey(Data['ipv6.src'],Data['ipv6.dst'])
                temp = set.udp[ky]
            except KeyError:
                ky = generateIPv6SrcDstKey(Data['ipv6.dst'],Data['ipv6.src'])
                temp = set.udp[ky]

            set.servicesQ.put([ky, Data, "udp"])
            set.udp_count +=1
            success = True
        elif 'udp.srcport' in Data:
            status = []
            status.append(Data['ipv6.src'])
            status.append(Data['ipv6.dst'])
            status.append(Data['udp.srcport'])
            status.append(Data['udp.dstport'])
            status.append(1)
            set.udp[           generateIPv6SrcDstKey(Data['ipv6.src'],Data['ipv6.dst'])] = status
            set.servicesQ.put([generateIPv6SrcDstKey(Data['ipv6.src'],Data['ipv6.dst']), Data, "udp"])

            set.udp_count +=1
            success = True
        else:
            success = False
    return success

def Arp(Data):

    success = False
    try:

        if 'arp.src.proto_ipv4' in Data and ( generateSrcDstKey(Data['arp.src.proto_ipv4'],Data['arp.dst.proto_ipv4']) in set.arp.keys() or generateSrcDstKey(Data['arp.dst.proto_ipv4'],Data['arp.src.proto_ipv4']) in set.arp.keys()):

            try:
                ky = generateSrcDstKey(Data['arp.src.proto_ipv4'],Data['arp.dst.proto_ipv4'])
                temp = set.arp[ky]
            except KeyError:
                ky = generateSrcDstKey(Data['arp.dst.proto_ipv4'],Data['arp.src.proto_ipv4'])
                temp = set.arp[ky]

            pack_count = temp[len(temp)-1]
            pack_count +=1

            temp.append(Data['arp.src.proto_ipv4'])
            temp.append(Data['arp.dst.proto_ipv4'])
            temp.append(Data['arp.src.hw_mac'])
            temp.append(Data['arp.dst.hw_mac'])
            temp.append(pack_count)
            set.servicesQ.put([ky, Data, "arp"])
            set.arp_count +=1
            success=True
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
            set.arp_count +=1
            success=True
        else:
            success = False

    except AttributeError:
        print(Data)
        success=False

    return success

# only doing Igmp row counts until someone writes code here
def Igmp(Data):
    success = False

    try: 
        if 'ip.proto' in Data and (Data['ip.proto'] == '2') and 'ip.src' in Data and 'ip.dst' in Data:
            ky = generateSrcDstKey(Data['ip.src'], Data['ip.dst'])
            # I don't know anything about IGMP so just set the pack count to 1 all the time
            set.igmp_count +=1
            set.servicesQ.put([ ky, Data, "igmp"])
            success = True
        if 'ip.proto' in Data and (Data['ip.proto'] == '2') and 'ipv6.src' in Data and 'ipv6.dst' in Data:
            ky = generateIPv6SrcDstKey(Data['ipv6.src'],Data['ipv6.dst'])
            # I don't know anything about IGMP so just set the pack count to 1 all the time
            set.igmp_count +=1
            set.servicesQ.put([ ky, Data, "igmp"])
            success = True
    except AttributeError:
        print(Data)
        success=False
    return success

