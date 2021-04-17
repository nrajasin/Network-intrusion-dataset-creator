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
import multiprocessing
import time
from dvar import datasetSummary
from pairstats import pair_stats_tcp
from pairstats import pair_stats_udp
from pairstats import pair_stats_arp

# separate out tcp,udp and arp traffic


class PacketAnalyse(multiprocessing.Process):
    def __init__(self, name, inQ, outQ):
        multiprocessing.Process.__init__(self)
        self.name = name
        self.inQ = inQ
        self.outQ = outQ
        self.dvar = datasetSummary()

    def run(self):
        start_timer = time.perf_counter()
        print("PacketAnalyze: run()")
        while True:
            if not self.inQ.empty():
                thePacket = self.inQ.get()
                if not thePacket:
                    # print("PacketAnalyze.run: We're done - empty dictionary received on queue")
                    self.outQ.put([])
                    break
                if not self.find_tcp(thePacket, self.dvar):
                    if not self.find_udp(thePacket, self.dvar):
                        if not self.find_arp(thePacket, self.dvar):
                            if not self.find_igmp(thePacket, self.dvar):
                                dvar.not_analyzed_count += 1
                                # ip.proto does not always exist if not ip
                                # print("PacketAnalyze.run Packet was not TCP, UDP, ARP, IGMP ")
                                print(
                                    "PacketAnalyze: No protocol filter for:",
                                    thePacket["ip.proto"],
                                )
                                # print(PacketAnalyze.run thePacket)
        end_timer = time.perf_counter()
        recognized_count = (
            self.dvar.tcp_count
            + self.dvar.udp_count
            + self.dvar.arp_count
            + self.dvar.igmp_count
            + self.dvar.not_analyzed_count
        )
        coarse_pps = recognized_count / (end_timer - start_timer)
        print(
            "PacketAnalyze.run:",
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
        print("PacketAnalyze.run: Exiting thread")

    # orders the src and dst before hashing
    # pass in strings that are the ip addresses from the packet
    def gen_src_dst_key(self, src, dst):
        if src < dst:
            return str(ipaddress.ip_address(src)) + "-" + str(ipaddress.ip_address(dst))
        else:
            return str(ipaddress.ip_address(dst)) + "-" + str(ipaddress.ip_address(src))

    # orders the src and dst before hashing
    # pass in strings that are the ip addresses from the packet
    def gen_ipv6_src_dst_key(self, src, dst):
        if src < dst:
            return (
                str(ipaddress.IPv6Address(src)) + "-" + str(ipaddress.IPv6Address(dst))
            )
        else:
            return (
                str(ipaddress.IPv6Address(dst)) + "-" + str(ipaddress.IPv6Address(src))
            )

    # tcp, ipand arp are separate in case they want to add custom properties like lists of port combos
    # we mutate a parameter. oh the horror!
    def gen_tcp_stats(self, existing_stats, packet_dict, srcKey, dstKey):
        pack_count = 0
        if existing_stats:
            pack_count = existing_stats.count
            pack_count += 1

        result = pair_stats_tcp()
        result.src = packet_dict[srcKey]
        result.dst = packet_dict[dstKey]
        result.count = pack_count

        return result

    def gen_udp_stats(self, existing_stats, packet_dict, srcKey, dstKey):
        pack_count = 0
        if existing_stats:
            pack_count = existing_stats.count
            pack_count += 1

        result = pair_stats_udp()
        result.src = packet_dict[srcKey]
        result.dst = packet_dict[dstKey]
        result.count = pack_count

        return result

    def gen_tcp_stats(self, existing_stats, packet_dict, srcKey, dstKey):
        pack_count = 0
        if existing_stats:
            pack_count = existing_stats.count
            pack_count += 1

        result = pair_stats_arp()
        result.src = packet_dict[srcKey]
        result.dst = packet_dict[dstKey]
        result.count = pack_count

        return result

    # Picks interested attributes from packets and saves them into a list
    def find_tcp(self, packet_dict, dvar):
        success = False
        if "ip.proto" in packet_dict and (packet_dict["ip.proto"] != "6"):
            return success

        try:
            if (
                "tcp.srcport" in packet_dict
                and self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                in dvar.tcp.keys()
            ):
                ky = self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                status = dvar.tcp[ky]
                # print("PacketAnalyze ", pack_count)
                dvar.tcp[ky] = self.gen_tcp_stats(
                    status, packet_dict, "ip.src", "ip.dst"
                )
                dvar.tcp_count += 1

                self.send(ky, packet_dict, "tcp")
                success = True
            elif "ip.src" in packet_dict and "tcp.flags.syn" in packet_dict:

                ky = self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                dvar.tcp[ky] = self.gen_tcp_stats(
                    set(), packet_dict, "ip.src", "ip.dst"
                )
                dvar.tcp_count += 1

                self.send(ky, packet_dict, "tcp")
                success = True
            else:
                success = False
        except KeyError:
            if (
                "tcp.srcport" in packet_dict
                and self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                in dvar.tcp.keys()
            ):

                ky = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                status = dvar.tcp[ky]
                # print("PacketAnalyze ",pack_count)
                dvar.tcp[ky] = self.gen_tcp_stats(
                    status, packet_dict, "ipv6.src", "ipv6.dst"
                )
                dvar.tcp_count += 1

                self.send(ky, packet_dict, "tcp")
                success = True
            elif "ipv6.src" in packet_dict and "tcp.flags.syn" in packet_dict:

                ky = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                dvar.tcp[ky] = self.gen_tcp_stats(
                    set(), packet_dict, "ipv6.src", "ipv6.dst"
                )
                dvar.tcp_count += 1

                self.send(ky, packet_dict, "tcp")
                success = True
            else:
                success = False

        except AttributeError:
            print("PacketAnalyze ", packet_dict)
        return success

    def find_udp(self, packet_dict, dvar):
        success = False
        if "ip.proto" in packet_dict and (packet_dict["ip.proto"] != "17"):
            return success

        try:

            if (
                "udp.srcport" in packet_dict
                and self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                in dvar.udp.keys()
            ):

                ky = self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                status = dvar.udp[ky]
                dvar.udp[ky] = self.gen_udp_stats(
                    status, packet_dict, "ip.src", "ip.dst"
                )
                dvar.udp_count += 1

                self.send(ky, packet_dict, "udp")
                success = True
            elif "udp.srcport" in packet_dict:

                ky = self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                dvar.udp[ky] = self.gen_udp_stats(
                    set(), packet_dict, "ip.src", "ip.dst"
                )
                dvar.udp_count += 1

                self.send(ky, packet_dict, "udp")
                success = True
            else:
                success = False
        except KeyError:

            if (
                "udp.srcport" in packet_dict
                and self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                in dvar.udp.keys()
            ):

                ky = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                status = dvar.udp[ky]

                dvar.udp[ky] = self.gen_udp_stats(
                    status, packet_dict, "ipv6.src", "ipv6.dst"
                )
                dvar.udp_count += 1

                self.send(ky, packet_dict, "udp")
                success = True
            elif "udp.srcport" in packet_dict:
                ky = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                dvar.udp[ky] = self.gen_udp_stats(
                    set(), packet_dict, "ipv6.src", "ipv6.dst"
                )
                dvar.udp_count += 1

                self.send(ky, packet_dict, "udp")
                success = True
            else:
                success = False
        return success

    def find_arp(self, packet_dict, dvar):

        success = False
        try:

            if (
                "arp.src.proto_ipv4" in packet_dict
                and self.gen_src_dst_key(
                    packet_dict["arp.dst.proto_ipv4"], packet_dict["arp.src.proto_ipv4"]
                )
                in dvar.arp.keys()
            ):
                ky = self.gen_src_dst_key(
                    packet_dict["arp.src.proto_ipv4"],
                    packet_dict["arp.dst.proto_ipv4"],
                )
                status = dvar.arp[ky]
                dvar.arp[ky] = self.gen_tcp_stats(
                    status, packet_dict, "arp.src.proto_ipv4", "arp.dst.proto_ipv4"
                )
                dvar.arp_count += 1

                self.send(ky, packet_dict, "arp")
                success = True
            elif "arp.src.proto_ipv4" in packet_dict:

                ky = self.gen_src_dst_key(
                    packet_dict["arp.src.proto_ipv4"], packet_dict["arp.dst.proto_ipv4"]
                )

                dvar.arp[ky] = self.gen_tcp_stats(
                    set(), packet_dict, "arp.src.proto_ipv4", "arp.dst.proto_ipv4"
                )
                dvar.arp_count += 1

                self.send(ky, packet_dict, "arp")
                success = True
            else:
                success = False

        except AttributeError:
            print("PacketAnalyze ", packet_dict)
            success = False

        return success

    # only doing IGMP row counts until someone writes code here
    # ipv6 not tested
    def find_igmp(self, packet_dict, dvar):
        success = False
        if "ip.proto" in packet_dict and (packet_dict["ip.proto"] != "2"):
            return success

        try:
            # TODO do we count all ip.proto or look for other markers
            if "ip.src" in packet_dict and "ip.dst" in packet_dict:
                ky = self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                # I don't know anything about IGMP so just set the pack count to 1 all the time
                dvar.igmp_count += 1
                self.send(ky, packet_dict, "igmp")
                success = True
            elif "ipv6.src" in packet_dict and "ipv6.dst" in packet_dict:
                ky = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                # I don't know anything about IGMP so just set the pack count to 1 all the time
                dvar.igmp_count += 1
                self.send(ky, packet_dict, "igmp")
                success = True
        except AttributeError:
            print("PacketAnalyze", packet_dict)
            success = False
        return success

    from services import ServiceIdentity

    def send(self, ID, PacketData, PacketProtocol):
        self.outQ.put([ID, PacketData, PacketProtocol])
