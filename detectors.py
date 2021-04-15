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


class packetanalyze(threading.Thread):
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
                    print(
                        "detectors.packetanalyze.run: We're done - empty dictionary received on queue"
                    )
                    queues.timesQ.put([])
                    break
                if self.Tcp(packetUnderExamination, self.dvar) == False:
                    if self.Udp(packetUnderExamination, self.dvar) == False:
                        if self.Arp(packetUnderExamination, self.dvar) == False:
                            if self.Igmp(packetUnderExamination, self.dvar) == False:
                                dvar.not_analyzed_count += 1
                                # ip.proto does not always exist if not ip
                                # print("Packet was not TCP, UDP, ARP, IGMP ")
                                # print("Packet was not TCP, UDP, ARP, IGMP proto type:",packetUnderExamination['ip.proto'])
                                # print(packetUnderExamination)
        end_timer = time.perf_counter()
        coarse_pps = (
            self.dvar.tcp_count
            + self.dvar.udp_count
            + self.dvar.arp_count
            + self.dvar.igmp_count
            + self.dvar.not_analyzed_count
        ) / (end_timer - start_timer)
        final_message = (
            "detectors.packetanalyze.run: " " detector pps:",
            str(coarse_pps),
            " detector tcp_count:",
            str(self.dvar.tcp_count),
            " detector udp_count:",
            str(self.dvar.udp_count),
            " detector arp_count:",
            str(self.dvar.arp_count),
            " detector igmp_count:",
            str(self.dvar.igmp_count),
            " tcp pairs:",
            str(len(self.dvar.tcp)),
            " udp pairs:",
            str(len(self.dvar.udp)),
            " detector not analyzed:",
            str(self.dvar.not_analyzed_count),
        )
        print(final_message)
        print("detectors.packetanalyze.run: Exiting thread")

    # pass in strings that are the ip addresses from the packet
    def generateSrcDstKey(self, src, dst):
        return int(ipaddress.ip_address(src)) + int(ipaddress.ip_address(dst))

    # pass in strings that are the ip addresses from the packet
    def generateIPv6SrcDstKey(self, src, dst):
        return int(ipaddress.IPv6Address(src)) + int(ipaddress.IPv6Address(dst))

    # we mutate a parameter. oh the horror!
    def populateTcpBucket(self, StatusBucket, Data, ipSrcKey, ipDstKey):
        pack_count = 0
        if StatusBucket:
            pack_count = StatusBucket[len(StatusBucket) - 1]
            pack_count += 1

        StatusBucket.append(Data[ipSrcKey])
        StatusBucket.append(Data[ipDstKey])
        StatusBucket.append(Data["tcp.flags.res"])
        StatusBucket.append(Data["tcp.flags.ns"])
        StatusBucket.append(Data["tcp.flags.cwr"])
        StatusBucket.append(Data["tcp.flags.ecn"])
        StatusBucket.append(Data["tcp.flags.urg"])
        StatusBucket.append(Data["tcp.flags.ack"])
        StatusBucket.append(Data["tcp.flags.push"])
        StatusBucket.append(Data["tcp.flags.reset"])
        StatusBucket.append(Data["tcp.flags.syn"])
        StatusBucket.append(Data["tcp.flags.fin"])

        StatusBucket.append(pack_count)
        return StatusBucket

    def populateUdpBucket(self, StatusBucket, Data, ipSrcKey, ipDstKey):
        pack_count = 0
        if StatusBucket:
            pack_count = StatusBucket[len(StatusBucket) - 1]
            pack_count += 1

        StatusBucket.append(Data[ipSrcKey])
        StatusBucket.append(Data[ipDstKey])
        StatusBucket.append(Data["udp.srcport"])
        StatusBucket.append(Data["udp.dstport"])
        StatusBucket.append(pack_count)
        return StatusBucket

    # Picks interested attributes from packets and saves them into a list
    def Tcp(self, Data, dvar):
        success = False
        if "ip.proto" in Data and (Data["ip.proto"] != "6"):
            return success

        try:
            if "tcp.srcport" in Data and (
                self.generateSrcDstKey(Data["ip.src"], Data["ip.dst"])
                in dvar.tcp.keys()
                or self.generateSrcDstKey(Data["ip.dst"], Data["ip.src"])
                in dvar.tcp.keys()
            ):
                try:
                    ky = self.generateSrcDstKey(Data["ip.src"], Data["ip.dst"])
                    status = dvar.tcp[ky]
                except KeyError:
                    ky = self.generateSrcDstKey(Data["ip.dst"], Data["ip.src"])
                    status = dvar.tcp[ky]
                # print(pack_count)
                status = self.populateTcpBucket(status, Data, "ip.src", "ip.dst")
                dvar.tcp[ky] = status
                dvar.tcp_count += 1

                self.findServicesAndSend(ky, Data, "tcp")
                success = True
            elif "ip.src" in Data and "tcp.flags.syn" in Data:

                ky = self.generateSrcDstKey(Data["ip.src"], Data["ip.dst"])
                status = self.populateTcpBucket([], Data, "ip.src", "ip.dst")
                dvar.tcp[ky] = status
                dvar.tcp_count += 1

                self.findServicesAndSend(ky, Data, "tcp")
                success = True
            else:
                success = False
        except KeyError:
            if "tcp.srcport" in Data and (
                self.generateIPv6SrcDstKey(Data["ipv6.src"], Data["ipv6.dst"])
                in dvar.tcp.keys()
                or self.generateIPv6SrcDstKey(Data["ipv6.dst"], Data["ipv6.src"])
                in dvar.tcp.keys()
            ):

                try:
                    ky = self.generateIPv6SrcDstKey(Data["ipv6.src"], Data["ipv6.dst"])
                    status = dvar.tcp[ky]
                except KeyError:
                    ky = self.generateIPv6SrcDstKey(Data["ipv6.dst"], Data["ipv6.src"])
                    status = dvar.tcp[ky]
                # print(pack_count)
                status = self.populateTcpBucket(status, Data, "ipv6.src", "ipv6.dst")
                dvar.tcp[ky] = status
                dvar.tcp_count += 1

                self.findServicesAndSend(ky, Data, "tcp")
                success = True
            elif "ipv6.src" in Data and "tcp.flags.syn" in Data:

                ky = self.generateIPv6SrcDstKey(Data["ipv6.src"], Data["ipv6.dst"])
                status = self.populateTcpBucket([], Data, "ipv6.src", "ipv6.dst")
                dvar.tcp[ky] = status
                dvar.tcp_count += 1

                self.findServicesAndSend(ky, Data, "tcp")
                success = True
            else:
                success = False

        except AttributeError:
            print(Data)
        return success

    def Udp(self, Data, dvar):
        success = False
        if "ip.proto" in Data and (Data["ip.proto"] != "17"):
            return success

        try:

            if "udp.srcport" in Data and (
                self.generateSrcDstKey(Data["ip.src"], Data["ip.dst"])
                in dvar.udp.keys()
                or self.generateSrcDstKey(Data["ip.dst"], Data["ip.src"])
                in dvar.udp.keys()
            ):

                try:
                    ky = self.generateSrcDstKey(Data["ip.src"], Data["ip.dst"])
                    status = dvar.udp[ky]
                except KeyError:
                    ky = self.generateSrcDstKey(Data["ip.dst"], Data["ip.src"])
                    status = dvar.status[ky]
                status = self.populateUdpBucket(status, Data, "ip.src", "ip.dst")
                dvar.udp[ky] = status
                dvar.udp_count += 1

                self.findServicesAndSend(ky, Data, "udp")
                success = True
            elif "udp.srcport" in Data:

                ky = self.generateSrcDstKey(Data["ip.src"], Data["ip.dst"])
                status = self.populateUdpBucket([], Data, "ip.src", "ip.dst")
                dvar.udp[ky] = status
                dvar.udp_count += 1

                self.findServicesAndSend(ky, Data, "udp")
                success = True
            else:
                success = False
        except KeyError:

            if "udp.srcport" in Data and (
                self.generateIPv6SrcDstKey(Data["ipv6.src"], Data["ipv6.dst"])
                in dvar.udp.keys()
                or self.generateIPv6SrcDstKey(Data["ipv6.dst"], Data["ipv6.src"])
                in dvar.udp.keys()
            ):

                try:
                    ky = self.generateIPv6SrcDstKey(Data["ipv6.src"], Data["ipv6.dst"])
                    status = dvar.udp[ky]
                except KeyError:
                    ky = self.generateIPv6SrcDstKey(Data["ipv6.dst"], Data["ipv6.src"])
                    status = dvar.udp[ky]

                status = self.populateUdpBucket(status, Data, "ipv6.src", "ipv6.dst")
                dvar.udp[ky] = status
                dvar.udp_count += 1

                self.findServicesAndSend(ky, Data, "udp")
                success = True
            elif "udp.srcport" in Data:
                ky = self.generateIPv6SrcDstKey(Data["ipv6.src"], Data["ipv6.dst"])
                status = self.populateUdpBucket([], Data, "ipv6.src", "ipv6.dst")
                dvar.udp[ky] = status
                dvar.udp_count += 1

                self.findServicesAndSend(ky, Data, "udp")
                success = True
            else:
                success = False
        return success

    def Arp(self, Data, dvar):

        success = False
        try:

            if "arp.src.proto_ipv4" in Data and (
                self.generateSrcDstKey(
                    Data["arp.src.proto_ipv4"], Data["arp.dst.proto_ipv4"]
                )
                in dvar.arp.keys()
                or self.generateSrcDstKey(
                    Data["arp.dst.proto_ipv4"], Data["arp.src.proto_ipv4"]
                )
                in dvar.arp.keys()
            ):
                try:
                    ky = self.generateSrcDstKey(
                        Data["arp.src.proto_ipv4"], Data["arp.dst.proto_ipv4"]
                    )
                    status = dvar.arp[ky]
                except KeyError:
                    ky = self.generateSrcDstKey(
                        Data["arp.dst.proto_ipv4"], Data["arp.src.proto_ipv4"]
                    )
                    status = dvar.arp[ky]

                pack_count = status[len(status) - 1]
                pack_count += 1
                status.append(Data["arp.src.proto_ipv4"])
                status.append(Data["arp.dst.proto_ipv4"])
                status.append(Data["arp.src.hw_mac"])
                status.append(Data["arp.dst.hw_mac"])
                status.append(pack_count)
                dvar.arp[ky] = status
                dvar.arp_count += 1

                self.findServicesAndSend(ky, Data, "arp")
                success = True
            elif "arp.src.proto_ipv4" in Data:

                ky = self.generateSrcDstKey(
                    Data["arp.src.proto_ipv4"], Data["arp.dst.proto_ipv4"]
                )

                # print('Tcp connection initiated')
                status = []
                pack_count = 1
                status.append(Data["arp.src.proto_ipv4"])
                status.append(Data["arp.dst.proto_ipv4"])
                status.append(Data["arp.src.hw_mac"])
                status.append(Data["arp.dst.hw_mac"])
                status.append(pack_count)
                dvar.arp[ky] = status
                dvar.arp_count += 1

                self.findServicesAndSend(ky, Data, "arp")
                success = True
            else:
                success = False

        except AttributeError:
            print(Data)
            success = False

        return success

    # only doing IGMP row counts until someone writes code here
    # ipv6 not tested
    def Igmp(self, Data, dvar):
        success = False
        if "ip.proto" in Data and (Data["ip.proto"] != "2"):
            return success

        try:
            # TODO do we count all ip.proto or look for other markers
            if "ip.src" in Data and "ip.dst" in Data:
                ky = self.generateSrcDstKey(Data["ip.src"], Data["ip.dst"])
                # I don't know anything about IGMP so just set the pack count to 1 all the time
                dvar.igmp_count += 1
                self.findServicesAndSend(ky, Data, "igmp")
                success = True
            elif "ipv6.src" in Data and "ipv6.dst" in Data:
                ky = self.generateIPv6SrcDstKey(Data["ipv6.src"], Data["ipv6.dst"])
                # I don't know anything about IGMP so just set the pack count to 1 all the time
                dvar.igmp_count += 1
                self.findServicesAndSend(ky, Data, "igmp")
                success = True
        except AttributeError:
            print(Data)
            success = False
        return success

    from services import serviceidentify

    servicesIdentifier = serviceidentify()

    # slightly mixed concerns here - the old version posted to a servicesQ
    # find any higher level services on top of TCP/UDP and send to sliding window / counter
    def findServicesAndSend(self, ID, PacketData, PacketProtocol):
        services = self.servicesIdentifier.findServices(ID, PacketData, PacketProtocol)
        queues.timesQ.put([ID, PacketData, PacketProtocol, services])
