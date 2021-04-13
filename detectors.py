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

# Protocol detectors

import ipaddress
from dvar import datasetSummary
import threading
from queue import *
import queues
import time

# separate out tcp,udp and arp traffic


class packetanalyze (threading.Thread):
    def __init__(self, threadID, name):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.dvar = datasetSummary()

    def run(self):
        start_timer = time.perf_counter()
        print("detectors.packetanalyze: run()")
        while True:
            if queues.sharedQ.empty() == False:
                packetUnderExamination = queues.sharedQ.get()
                if not packetUnderExamination:
                    print("detectors.packetanalyze.run: We're done - empty dictionary received on queue")
                    queues.servicesQ.put([])
                    break
                if self.Tcp(packetUnderExamination,self.dvar) == False: 
                    if self.Udp(packetUnderExamination,self.dvar) == False:
                        if self.Arp(packetUnderExamination,self.dvar) == False:
                            if self.Igmp(packetUnderExamination,self.dvar) == False:
                                dvar.not_analyzed_count +=1
                                # ip.proto does not always exist if not ip
                                # print("Packet was not TCP, UDP, ARP, IGMP proto type:",packetUnderExamination['ip.proto'])
                                # print("Packet was not TCP, UDP, ARP, IGMP ")
                                # print(packetUnderExamination)
        end_timer = time.perf_counter()
        coarse_pps = (self.dvar.tcp_count + self.dvar.udp_count + self.dvar.arp_count+ self.dvar.igmp_count + self.dvar.not_analyzed_count)/(end_timer-start_timer)
        final_message = ('detectors.packetanalyze.run: '
            ' detector pps:'+str(coarse_pps)+''
            ' detector tcp_count:'+str(self.dvar.tcp_count)+''
            ' detector udp_count:'+str(self.dvar.udp_count)+''
            ' detector arp_count:'+str(self.dvar.arp_count)+''
            ' detector igmp_count:'+str(self.dvar.igmp_count)+''
            ' detector not analyzed:'+str(self.dvar.not_analyzed_count)+''
            )
        print(final_message)
        print("detectors.packetanalyze.run: Exiting thread")


    # pass in strings that are the ip addresses from the packet
    def generateSrcDstKey(self, src,dst):
        return int(ipaddress.ip_address(src))+int(ipaddress.ip_address(dst))

    # pass in strings that are the ip addresses from the packet
    def generateIPv6SrcDstKey(self, src,dst):
        return int(ipaddress.IPv6Address(src))+int(ipaddress.IPv6Address(dst))

    # we mutate a parameter. oh the horror!
    def populateBucket(self, ListBucket, Data, pack_count, ipSrcKey, ipDstKey):
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
    def Tcp(self, Data, dvar):
        success = False
        if 'ip.proto' in Data and (Data['ip.proto'] != '6'):
            return success

        try:
            if 'tcp.srcport' in Data and (self.generateSrcDstKey(Data['ip.src'],Data['ip.dst']) in dvar.tcp.keys() or self.generateSrcDstKey(Data['ip.dst'], Data['ip.src']) in dvar.tcp.keys()):
                try:
                    ky = self.generateSrcDstKey(Data['ip.src'] ,Data['ip.dst'])
                    temp = dvar.tcp[ky]
                except KeyError:
                    ky = self.generateSrcDstKey(Data['ip.dst'], Data['ip.src'])
                    temp = dvar.tcp[ky]
                pack_count = temp[len(temp)-1]
                pack_count +=1
                # print(pack_count)
                self.populateBucket(temp,Data,pack_count,'ip.src', 'ip.dst')

                queues.servicesQ.put([ky, Data, "tcp"])
                dvar.tcp[ky] = temp
                dvar.tcp_count +=1
                success=True
            elif 'ip.src' in Data and 'tcp.flags.syn' in Data:

                ky = self.generateSrcDstKey(Data['ip.src'], Data['ip.dst'])
                status = []
                pack_count = 1
                self.populateBucket(status, Data, pack_count, 'ip.src', 'ip.dst')

                queues.servicesQ.put([ ky, Data, "tcp"])
                dvar.tcp[ky] = status
                dvar.tcp_count +=1
                success=True
            else:
                success=False
        except KeyError:
            if 'tcp.srcport' in Data and (
                self.generateIPv6SrcDstKey(Data['ipv6.src'],Data['ipv6.dst']) in dvar.tcp.keys() or 
                self.generateIPv6SrcDstKey(Data['ipv6.dst'], Data['ipv6.src']) in dvar.tcp.keys()):

                try:
                    ky = self.generateIPv6SrcDstKey(Data['ipv6.src'] ,Data['ipv6.dst'])
                    temp = dvar.tcp[ky]
                except KeyError:
                    ky = self.generateIPv6SrcDstKey(Data['ipv6.dst'], Data['ipv6.src'])
                    temp = dvar.tcp[ky]
                pack_count = temp[len(temp)-1]
                pack_count +=1
                # print(pack_count)
                self.populateBucket(temp,Data,pack_count,'ipv6.src', 'ipv6.dst')

                queues.servicesQ.put([ky, Data, "tcp"])
                dvar.tcp[ky] = temp
                dvar.tcp_count +=1
                success=True
            elif 'ipv6.src' in Data and 'tcp.flags.syn' in Data:

                ky = self.generateIPv6SrcDstKey(Data['ipv6.src'], Data['ipv6.dst'])
                status = []
                pack_count = 1
                self.populateBucket(status, Data, pack_count, 'ipv6.src', 'ipv6.dst')

                queues.servicesQ.put([ ky, Data, "tcp"])
                dvar.tcp[ky] = status
                dvar.tcp_count +=1
                success=True
            else:
                success=False

        except AttributeError:
            print(Data)
        return success


    def Udp(self, Data, dvar):
        success = False
        if 'ip.proto' in Data and (Data['ip.proto'] != '17'):
            return success

        try:

            if 'udp.srcport' in Data and (
                    self.generateSrcDstKey(Data['ip.src'],Data['ip.dst']) in dvar.udp.keys() 
                    or 
                    self.generateSrcDstKey(Data['ip.dst'],Data['ip.src']) in dvar.udp.keys()):

                try:
                    ky = self.generateSrcDstKey(Data['ip.src'],Data['ip.dst'])
                    temp = dvar.udp[ky]
                except KeyError:
                    ky = self.generateSrcDstKey (Data['ip.dst'],Data['ip.src'])
                    temp = dvar.udp[ky]

                queues.servicesQ.put([ky, Data, "udp"])

                dvar.udp_count +=1
                success = True
            elif 'udp.srcport' in Data:

                status = []
                # status.append(Data)
                status.append(Data['ip.src'])
                status.append(Data['ip.dst'])
                status.append(Data['udp.srcport'])
                status.append(Data['udp.dstport'])
                status.append(1)
                dvar.udp[             self.generateSrcDstKey(Data['ip.src'],Data['ip.dst'])] = status
                queues.servicesQ.put([self.generateSrcDstKey(Data['ip.src'],Data['ip.dst']), Data, "udp"])
                dvar.udp_count +=1
                success = True
            else:
                success = False
        except KeyError:

            if 'udp.srcport' in Data and (
                self.generateIPv6SrcDstKey(Data['ipv6.src'],Data['ipv6.dst']) in dvar.udp.keys() or 
                self.generateIPv6SrcDstKey(Data['ipv6.dst'],Data['ipv6.src']) in dvar.udp.keys()):

                try:
                    ky = self.generateIPv6SrcDstKey(Data['ipv6.src'],Data['ipv6.dst'])
                    temp = dvar.udp[ky]
                except KeyError:
                    ky = self.generateIPv6SrcDstKey(Data['ipv6.dst'],Data['ipv6.src'])
                    temp = dvar.udp[ky]

                queues.servicesQ.put([ky, Data, "udp"])
                dvar.udp_count +=1
                success = True
            elif 'udp.srcport' in Data:
                status = []
                status.append(Data['ipv6.src'])
                status.append(Data['ipv6.dst'])
                status.append(Data['udp.srcport'])
                status.append(Data['udp.dstport'])
                status.append(1)
                dvar.udp[             self.generateIPv6SrcDstKey(Data['ipv6.src'],Data['ipv6.dst'])] = status
                queues.servicesQ.put([self.generateIPv6SrcDstKey(Data['ipv6.src'],Data['ipv6.dst']), Data, "udp"])

                dvar.udp_count +=1
                success = True
            else:
                success = False
        return success

    def Arp(self, Data, dvar):

        success = False
        try:

            if 'arp.src.proto_ipv4' in Data and ( self.generateSrcDstKey(Data['arp.src.proto_ipv4'],Data['arp.dst.proto_ipv4']) in dvar.arp.keys() or self.generateSrcDstKey(Data['arp.dst.proto_ipv4'],Data['arp.src.proto_ipv4']) in dvar.arp.keys()):
                try:
                    ky = self.generateSrcDstKey(Data['arp.src.proto_ipv4'],Data['arp.dst.proto_ipv4'])
                    temp = dvar.arp[ky]
                except KeyError:
                    ky = self.generateSrcDstKey(Data['arp.dst.proto_ipv4'],Data['arp.src.proto_ipv4'])
                    temp = dvar.arp[ky]

                pack_count = temp[len(temp)-1]
                pack_count +=1

                temp.append(Data['arp.src.proto_ipv4'])
                temp.append(Data['arp.dst.proto_ipv4'])
                temp.append(Data['arp.src.hw_mac'])
                temp.append(Data['arp.dst.hw_mac'])
                temp.append(pack_count)
                queues.servicesQ.put([ky, Data, "arp"])
                dvar.arp_count +=1
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
                dvar.arp[             self.generateSrcDstKey(Data['arp.src.proto_ipv4'],Data['arp.dst.proto_ipv4'])] = status
                queues.servicesQ.put([self.generateSrcDstKey(Data['arp.src.proto_ipv4'],Data['arp.dst.proto_ipv4']), Data, "arp"])
                dvar.arp_count +=1
                success=True
            else:
                success = False

        except AttributeError:
            print(Data)
            success=False

        return success

    # only doing IGMP row counts until someone writes code here 
    # ipv6 not tested
    def Igmp(self, Data, dvar):
        success = False
        if 'ip.proto' in Data and (Data['ip.proto'] != '2'):
            return success

        try: 
            # TODO do we count all ip.proto or look for other markers
            if 'ip.src' in Data and 'ip.dst' in Data:
                ky = self.generateSrcDstKey(Data['ip.src'], Data['ip.dst'])
                # I don't know anything about IGMP so just set the pack count to 1 all the time
                dvar.igmp_count +=1
                queues.servicesQ.put([ ky, Data, "igmp"])
                success = True
            elif 'ipv6.src' in Data and 'ipv6.dst' in Data:
                ky = self.generateIPv6SrcDstKey(Data['ipv6.src'],Data['ipv6.dst'])
                # I don't know anything about IGMP so just set the pack count to 1 all the time
                dvar.igmp_count +=1
                queues.servicesQ.put([ ky, Data, "igmp"])
                success = True
        except AttributeError:
            print(Data)
            success=False
        return success

