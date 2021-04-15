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
import threading
from queue import *
import queues
import time
from dvar import datasetSummary
from pairstats import pair_stats_tcp
from pairstats import pair_stats_udp
from pairstats import pair_stats_arp

# separate out tcp,udp and arp traffic


class PacketAnalyse(threading.Thread):
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
                    # print("detectors.packetanalyze.run: We're done - empty dictionary received on queue")
                    queues.timesQ.put([])
                    break
                if not self.find_tcp(packetUnderExamination, self.dvar):
                    if not self.find_udp(packetUnderExamination, self.dvar):
                        if not self.find_arp(packetUnderExamination, self.dvar):
                            if not self.find_igmp(packetUnderExamination, self.dvar):
                                dvar.not_analyzed_count += 1
                                # ip.proto does not always exist if not ip
                                # print("Packet was not TCP, UDP, ARP, IGMP ")
                                # print("Packet was not TCP, UDP, ARP, IGMP proto type:",packetUnderExamination['ip.proto'])
                                # print(packetUnderExamination)
        end_timer = time.perf_counter()
        recognized_count = (
            self.dvar.tcp_count
            + self.dvar.udp_count
            + self.dvar.arp_count
            + self.dvar.igmp_count
            + self.dvar.not_analyzed_count
        )
        coarse_pps = recognized_count / (end_timer - start_timer)
        final_message = (
            "detectors.packetanalyze.run: ",
            " read=",
            str(recognized_count),
            " pps=",
            str(coarse_pps),
            " tcp_count=",
            str(self.dvar.tcp_count),
            " udp_count=",
            str(self.dvar.udp_count),
            " arp_count=",
            str(self.dvar.arp_count),
            " igmp_count=",
            str(self.dvar.igmp_count),
            " tcp_pairs=",
            str(len(self.dvar.tcp)),
            " udp_pairs=",
            str(len(self.dvar.udp)),
            " not_analyzed=",
            str(self.dvar.not_analyzed_count),
        )
        print(final_message)
        print("detectors.packetanalyze.run: Exiting thread")

    # pass in strings that are the ip addresses from the packet
    def gen_src_dst_key(self, src, dst):
        return int(ipaddress.ip_address(src)) + int(ipaddress.ip_address(dst))

    # pass in strings that are the ip addresses from the packet
    def gen_ipv6_src_dst_key(self, src, dst):
        return int(ipaddress.IPv6Address(src)) + int(ipaddress.IPv6Address(dst))

    # tcp, ipand arp are separate in case they want to add custom properties like lists of port combos
    # we mutate a parameter. oh the horror!
    def gen_tcp_stats(self, existing_stats, Data, srcKey, dstKey):
        pack_count = 0
        if existing_stats:
            pack_count = existing_stats.count
            pack_count += 1

        result = pair_stats_tcp()
        result.src = Data[srcKey]
        result.dst = Data[dstKey]
        result.count = pack_count

        return result

    def gen_udp_stats(self, existing_stats, Data, srcKey, dstKey):
        pack_count = 0
        if existing_stats:
            pack_count = existing_stats.count
            pack_count += 1

        result = pair_stats_udp()
        result.src = Data[srcKey]
        result.dst = Data[dstKey]
        result.count = pack_count

        return result

    def gen_tcp_stats(self, existing_stats, Data, srcKey, dstKey):
        pack_count = 0
        if existing_stats:
            pack_count = existing_stats.count
            pack_count += 1

        result = pair_stats_arp()
        result.src = Data[srcKey]
        result.dst = Data[dstKey]
        result.count = pack_count

        return result

    # Picks interested attributes from packets and saves them into a list
    def find_tcp(self, Data, dvar):
        success = False
        if "ip.proto" in Data and (Data["ip.proto"] != "6"):
            return success

        try:
            if "tcp.srcport" in Data and (
                self.gen_src_dst_key(Data["ip.src"], Data["ip.dst"]) in dvar.tcp.keys()
                or self.gen_src_dst_key(Data["ip.dst"], Data["ip.src"])
                in dvar.tcp.keys()
            ):
                try:
                    ky = self.gen_src_dst_key(Data["ip.src"], Data["ip.dst"])
                    status = dvar.tcp[ky]
                except KeyError:
                    ky = self.gen_src_dst_key(Data["ip.dst"], Data["ip.src"])
                    status = dvar.tcp[ky]
                # print(pack_count)
                dvar.tcp[ky] = self.gen_tcp_stats(status, Data, "ip.src", "ip.dst")
                dvar.tcp_count += 1

                self.find_svcs_then_send(ky, Data, "tcp")
                success = True
            elif "ip.src" in Data and "tcp.flags.syn" in Data:

                ky = self.gen_src_dst_key(Data["ip.src"], Data["ip.dst"])
                dvar.tcp[ky] = self.gen_tcp_stats([], Data, "ip.src", "ip.dst")
                dvar.tcp_count += 1

                self.find_svcs_then_send(ky, Data, "tcp")
                success = True
            else:
                success = False
        except KeyError:
            if "tcp.srcport" in Data and (
                self.gen_ipv6_src_dst_key(Data["ipv6.src"], Data["ipv6.dst"])
                in dvar.tcp.keys()
                or self.gen_ipv6_src_dst_key(Data["ipv6.dst"], Data["ipv6.src"])
                in dvar.tcp.keys()
            ):

                try:
                    ky = self.gen_ipv6_src_dst_key(Data["ipv6.src"], Data["ipv6.dst"])
                    status = dvar.tcp[ky]
                except KeyError:
                    ky = self.gen_ipv6_src_dst_key(Data["ipv6.dst"], Data["ipv6.src"])
                    status = dvar.tcp[ky]
                # print(pack_count)
                dvar.tcp[ky] = self.gen_tcp_stats(status, Data, "ipv6.src", "ipv6.dst")
                dvar.tcp_count += 1

                self.find_svcs_then_send(ky, Data, "tcp")
                success = True
            elif "ipv6.src" in Data and "tcp.flags.syn" in Data:

                ky = self.gen_ipv6_src_dst_key(Data["ipv6.src"], Data["ipv6.dst"])
                dvar.tcp[ky] = self.gen_tcp_stats([], Data, "ipv6.src", "ipv6.dst")
                dvar.tcp_count += 1

                self.find_svcs_then_send(ky, Data, "tcp")
                success = True
            else:
                success = False

        except AttributeError:
            print(Data)
        return success

    def find_udp(self, Data, dvar):
        success = False
        if "ip.proto" in Data and (Data["ip.proto"] != "17"):
            return success

        try:

            if "udp.srcport" in Data and (
                self.gen_src_dst_key(Data["ip.src"], Data["ip.dst"]) in dvar.udp.keys()
                or self.gen_src_dst_key(Data["ip.dst"], Data["ip.src"])
                in dvar.udp.keys()
            ):

                try:
                    ky = self.gen_src_dst_key(Data["ip.src"], Data["ip.dst"])
                    status = dvar.udp[ky]
                except KeyError:
                    ky = self.gen_src_dst_key(Data["ip.dst"], Data["ip.src"])
                    status = dvar.status[ky]
                dvar.udp[ky] = self.gen_udp_stats(status, Data, "ip.src", "ip.dst")
                dvar.udp_count += 1

                self.find_svcs_then_send(ky, Data, "udp")
                success = True
            elif "udp.srcport" in Data:

                ky = self.gen_src_dst_key(Data["ip.src"], Data["ip.dst"])
                dvar.udp[ky] = self.gen_udp_stats([], Data, "ip.src", "ip.dst")
                dvar.udp_count += 1

                self.find_svcs_then_send(ky, Data, "udp")
                success = True
            else:
                success = False
        except KeyError:

            if "udp.srcport" in Data and (
                self.gen_ipv6_src_dst_key(Data["ipv6.src"], Data["ipv6.dst"])
                in dvar.udp.keys()
                or self.gen_ipv6_src_dst_key(Data["ipv6.dst"], Data["ipv6.src"])
                in dvar.udp.keys()
            ):

                try:
                    ky = self.gen_ipv6_src_dst_key(Data["ipv6.src"], Data["ipv6.dst"])
                    status = dvar.udp[ky]
                except KeyError:
                    ky = self.gen_ipv6_src_dst_key(Data["ipv6.dst"], Data["ipv6.src"])
                    status = dvar.udp[ky]

                dvar.udp[ky] = self.gen_udp_stats(status, Data, "ipv6.src", "ipv6.dst")
                dvar.udp_count += 1

                self.find_svcs_then_send(ky, Data, "udp")
                success = True
            elif "udp.srcport" in Data:
                ky = self.gen_ipv6_src_dst_key(Data["ipv6.src"], Data["ipv6.dst"])
                dvar.udp[ky] = self.gen_udp_stats([], Data, "ipv6.src", "ipv6.dst")
                dvar.udp_count += 1

                self.find_svcs_then_send(ky, Data, "udp")
                success = True
            else:
                success = False
        return success

    def find_arp(self, Data, dvar):

        success = False
        try:

            if "arp.src.proto_ipv4" in Data and (
                self.gen_src_dst_key(
                    Data["arp.src.proto_ipv4"], Data["arp.dst.proto_ipv4"]
                )
                in dvar.arp.keys()
                or self.gen_src_dst_key(
                    Data["arp.dst.proto_ipv4"], Data["arp.src.proto_ipv4"]
                )
                in dvar.arp.keys()
            ):
                try:
                    ky = self.gen_src_dst_key(
                        Data["arp.src.proto_ipv4"], Data["arp.dst.proto_ipv4"]
                    )
                    status = dvar.arp[ky]
                except KeyError:
                    ky = self.gen_src_dst_key(
                        Data["arp.dst.proto_ipv4"], Data["arp.src.proto_ipv4"]
                    )
                    status = dvar.arp[ky]
                dvar.arp[ky] = self.gen_tcp_stats(
                    status, Data, "arp.src.proto_ipv4", "arp.dst.proto_ipv4"
                )
                dvar.arp_count += 1

                self.find_svcs_then_send(ky, Data, "arp")
                success = True
            elif "arp.src.proto_ipv4" in Data:

                ky = self.gen_src_dst_key(
                    Data["arp.src.proto_ipv4"], Data["arp.dst.proto_ipv4"]
                )

                dvar.arp[ky] = self.gen_tcp_stats(
                    [], Data, "arp.src.proto_ipv4", "arp.dst.proto_ipv4"
                )
                dvar.arp_count += 1

                self.find_svcs_then_send(ky, Data, "arp")
                success = True
            else:
                success = False

        except AttributeError:
            print(Data)
            success = False

        return success

    # only doing IGMP row counts until someone writes code here
    # ipv6 not tested
    def find_igmp(self, Data, dvar):
        success = False
        if "ip.proto" in Data and (Data["ip.proto"] != "2"):
            return success

        try:
            # TODO do we count all ip.proto or look for other markers
            if "ip.src" in Data and "ip.dst" in Data:
                ky = self.gen_src_dst_key(Data["ip.src"], Data["ip.dst"])
                # I don't know anything about IGMP so just set the pack count to 1 all the time
                dvar.igmp_count += 1
                self.find_svcs_then_send(ky, Data, "igmp")
                success = True
            elif "ipv6.src" in Data and "ipv6.dst" in Data:
                ky = self.gen_ipv6_src_dst_key(Data["ipv6.src"], Data["ipv6.dst"])
                # I don't know anything about IGMP so just set the pack count to 1 all the time
                dvar.igmp_count += 1
                self.find_svcs_then_send(ky, Data, "igmp")
                success = True
        except AttributeError:
            print(Data)
            success = False
        return success

    from services import ServiceIdentity

    servicesIdentifier = ServiceIdentity()

    # slightly mixed concerns here - the old version posted to a servicesQ
    # find any higher level services on top of TCP/UDP and send to sliding window / counter
    def find_svcs_then_send(self, ID, PacketData, PacketProtocol):
        services = self.servicesIdentifier.findServices(ID, PacketData, PacketProtocol)
        queues.timesQ.put([ID, PacketData, PacketProtocol, services])
