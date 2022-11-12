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

import transitkeys
import ipaddress
import time
from dvar import datasetSummary
from pairstats import pair_stats_tcp
from pairstats import pair_stats_udp
from pairstats import pair_stats_arp
import logging

# separate out tcp,udp and arp traffic


class PacketAnalyse:
    def __init__(self, name, inQ, outQ):
        self.logger = logging.getLogger(__name__)
        self.name = name
        self.inQ = inQ
        self.outQ = outQ

    def run(self):
        dvar = datasetSummary()
        start_timer = time.perf_counter()
        self.logger.info("Starting")
        while True:
            if not self.inQ.empty():
                thePacket = self.inQ.get()
                if not thePacket:
                    self.logger.debug("We're done - empty dictionary received on queue")
                    self.outQ.put([])
                    break
                if not self.find_ip(thePacket, dvar):
                    self.find_non_ip(thePacket, dvar)
        end_timer = time.perf_counter()
        recognized_count = (
            dvar.tcp_count + dvar.udp_count + dvar.arp_count + dvar.igmp_count
        )
        unrecognized_count = dvar.not_analyzed_ip_count + dvar.not_analyzed_not_ip_count
        coarse_pps = recognized_count / (end_timer - start_timer)
        dvar_dict = vars(dvar).copy()
        # TODO determine if we really want to remove the pairs from the output or output something
        # dvar_dict.pop("tcp")
        # dvar_dict.pop("udp")
        # dvar_dict.pop("arp")
        long_string = (
            f"recognized={recognized_count} unrecognized={unrecognized_count} pps={coarse_pps} "
            f"{dvar_dict}"
        )
        self.logger.info(long_string)
        self.logger.info("Exiting thread")

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

    def gen_arp_stats(self, existing_stats, packet_dict, srcKey, dstKey):
        pack_count = 0
        if existing_stats:
            pack_count = existing_stats.count
            pack_count += 1

        result = pair_stats_arp()
        result.src = packet_dict[srcKey]
        result.dst = packet_dict[dstKey]
        result.count = pack_count

        return result

    # The return code just says we categorized as non-ip not that we detected specific non-IP
    def find_non_ip(self, packet_dict, dvar):
        if not self.find_arp(packet_dict, dvar):
            # TODO probably should filter out any with ip.proto or an ipv6.<something> and return False
            dvar.not_analyzed_not_ip_count += 1
            # Could look for things like ipx for non IP
            self.logger.debug("Packet was not IP not ARP")
            # should this be debug() info() or warn() You could have a lot of these
            self.logger.debug(
                "Packet not analyzed: No detector for non IP %s", packet_dict
            )
        return True

    # Cover for all the IP based detectors
    # The return code says we categorized as IP - not that detected specific IP
    def find_ip(self, packet_dict, dvar):
        if not self.find_tcp(packet_dict, dvar):
            if not self.find_udp(packet_dict, dvar):
                if not self.find_igmp(packet_dict, dvar):
                    # Can't filter on ip.proto at the top because of IPv6 picked up in the detectors
                    if "ip.proto" in packet_dict:
                        dvar.not_analyzed_ip_count += 1
                        # ip.proto does not always exist if not ip
                        self.logger.debug("Packet was IPv4 but not TCP, UDP, IGMP ")
                        packet_ip_proto = packet_dict["ip.proto"]
                        dvar.not_analyzed_ip.add(packet_ip_proto)
                        # should this be debug() info() or warn() You could have a lot of these
                        self.logger.debug(
                            "Packet not analyzed: no detector for IP protocol: %s",
                            packet_ip_proto,
                        )
                    else:
                        # TODO: Capture ipv6.<something> to put it in the ip not analyzed bucket
                        # TODO: Unrecognized IPv6 may leak out of here and get categorized as non IP
                        return False
        return True

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
                packet_key = self.gen_src_dst_key(
                    packet_dict["ip.src"], packet_dict["ip.dst"]
                )
                status = dvar.tcp[packet_key]
                self.logger.debug("%s, %s", packet_key, status)
                dvar.tcp[packet_key] = self.gen_tcp_stats(
                    status, packet_dict, "ip.src", "ip.dst"
                )
                dvar.tcp_count += 1

                self.send(packet_key, packet_dict, "tcp")
                success = True
            elif "ip.src" in packet_dict and "tcp.flags.syn" in packet_dict:

                packet_key = self.gen_src_dst_key(
                    packet_dict["ip.src"], packet_dict["ip.dst"]
                )
                dvar.tcp[packet_key] = self.gen_tcp_stats(
                    {}, packet_dict, "ip.src", "ip.dst"
                )
                dvar.tcp_count += 1

                self.send(packet_key, packet_dict, "tcp")
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

                packet_key = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                status = dvar.tcp[packet_key]
                self.logger.debug("{packet_key} {status}")
                dvar.tcp[packet_key] = self.gen_tcp_stats(
                    status, packet_dict, "ipv6.src", "ipv6.dst"
                )
                dvar.tcp_count += 1

                self.send(packet_key, packet_dict, "tcp")
                success = True
            elif "ipv6.src" in packet_dict and "tcp.flags.syn" in packet_dict:

                packet_key = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                dvar.tcp[packet_key] = self.gen_tcp_stats(
                    {}, packet_dict, "ipv6.src", "ipv6.dst"
                )
                dvar.tcp_count += 1

                self.send(packet_key, packet_dict, "tcp")
                success = True
            else:
                success = False

        except AttributeError:
            self.logger.info("%s", packet_dict)
        return success

    def find_udp(self, packet_dict, dvar):
        success = False
        # filters out IPV4 non UDP - could still have IPv6 UDP
        if "ip.proto" in packet_dict and (packet_dict["ip.proto"] != "17"):
            return success

        try:

            if (
                "udp.srcport" in packet_dict
                and self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                in dvar.udp.keys()
            ):

                packet_key = self.gen_src_dst_key(
                    packet_dict["ip.src"], packet_dict["ip.dst"]
                )
                status = dvar.udp[packet_key]
                dvar.udp[packet_key] = self.gen_udp_stats(
                    status, packet_dict, "ip.src", "ip.dst"
                )
                dvar.udp_count += 1

                self.send(packet_key, packet_dict, "udp")
                success = True
            elif "udp.srcport" in packet_dict:

                packet_key = self.gen_src_dst_key(
                    packet_dict["ip.src"], packet_dict["ip.dst"]
                )
                dvar.udp[packet_key] = self.gen_udp_stats(
                    {}, packet_dict, "ip.src", "ip.dst"
                )
                dvar.udp_count += 1

                self.send(packet_key, packet_dict, "udp")
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

                packet_key = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                status = dvar.udp[packet_key]

                dvar.udp[packet_key] = self.gen_udp_stats(
                    status, packet_dict, "ipv6.src", "ipv6.dst"
                )
                dvar.udp_count += 1

                self.send(packet_key, packet_dict, "udp")
                success = True
            elif "udp.srcport" in packet_dict:
                packet_key = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                dvar.udp[packet_key] = self.gen_udp_stats(
                    {}, packet_dict, "ipv6.src", "ipv6.dst"
                )
                dvar.udp_count += 1

                self.send(packet_key, packet_dict, "udp")
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
                packet_key = self.gen_src_dst_key(
                    packet_dict["arp.src.proto_ipv4"],
                    packet_dict["arp.dst.proto_ipv4"],
                )
                status = dvar.arp[packet_key]
                dvar.arp[packet_key] = self.gen_arp_stats(
                    status, packet_dict, "arp.src.proto_ipv4", "arp.dst.proto_ipv4"
                )
                dvar.arp_count += 1

                self.send(packet_key, packet_dict, "arp")
                success = True
            elif "arp.src.proto_ipv4" in packet_dict:

                packet_key = self.gen_src_dst_key(
                    packet_dict["arp.src.proto_ipv4"], packet_dict["arp.dst.proto_ipv4"]
                )

                dvar.arp[packet_key] = self.gen_arp_stats(
                    {}, packet_dict, "arp.src.proto_ipv4", "arp.dst.proto_ipv4"
                )
                dvar.arp_count += 1

                self.send(packet_key, packet_dict, "arp")
                success = True
            else:
                success = False

        except AttributeError:
            # traceback.self.logger.info_exc()
            self.logger.info("%s", packet_dict)
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
                packet_key = self.gen_src_dst_key(
                    packet_dict["ip.src"], packet_dict["ip.dst"]
                )
                # I don't know anything about IGMP so just set the pack count to 1 all the time
                dvar.igmp_count += 1
                self.send(packet_key, packet_dict, "igmp")
                success = True
            elif "ipv6.src" in packet_dict and "ipv6.dst" in packet_dict:
                packet_key = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                # I don't know anything about IGMP so just set the pack count to 1 all the time
                dvar.igmp_count += 1
                self.send(packet_key, packet_dict, "igmp")
                success = True
        except AttributeError:
            self.logger.info("attribute error %s", packet_dict)
            success = False
        return success

    def send(self, ID, PacketData, PacketProtocol):
        self.outQ.put(
            {
                transitkeys.key_id: ID,
                transitkeys.key_packet: PacketData,
                transitkeys.key_protocol: PacketProtocol,
            }
        )
