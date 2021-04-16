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

import threading
import queues

# check the traffic for different services in the traffic suhc as tls,http,smtp


class ServiceIdentity:
    def findServices(self, ID, packet_dict, PacketProtocol):
        FoundServices = set()
        if PacketProtocol == "tcp" or PacketProtocol == "udp":
            self.tls(packet_dict, FoundServices)
            self.http(packet_dict, FoundServices)
            self.ftp(packet_dict, FoundServices)
            self.ssh(packet_dict, FoundServices)
            self.dns(packet_dict, FoundServices)
            self.smtp(packet_dict, FoundServices)
            self.dhcp(packet_dict, FoundServices)
            self.nbns(packet_dict, FoundServices)
            self.smb(packet_dict, FoundServices)
            self.smb2(packet_dict, FoundServices)
            self.pnrp(packet_dict, FoundServices)
            self.wsdd_ssdp(packet_dict, FoundServices)
            if not FoundServices:
                # uncomment to see packets not marked as services
                # print("ServiceIdentity ",packet_dict)
                pass
        return FoundServices

    # if more services are needed they can be added in the following template
    def tls(self, packet_dict, FoundServices):

        if "tls.record.content_type" in packet_dict:

            FoundServices.add("tls")

    def http(self, packet_dict, FoundServices):

        if "http.request.method" in packet_dict:

            FoundServices.add("http")

    # not yet validated

    def ftp(self, packet_dict, FoundServices):

        if "ftp.request" in packet_dict:
            FoundServices.add("ftp")

    def ssh(self, packet_dict, FoundServices):

        # ssh.message_code?
        # was ssh.payload
        if "ssh.encrypted_packet" in packet_dict:
            FoundServices.add("ssh")

    def dns(self, packet_dict, FoundServices):

        if "dns.flags" in packet_dict:
            FoundServices.add("dns")

    # not yet validated

    def smtp(self, packet_dict, FoundServices):
        if "smtp.response" in packet_dict:
            FoundServices.add("smtp")

    def dhcp(self, packet_dict, FoundServices):
        if "dhcp.type" in packet_dict or "dhcpv6.msgtype" in packet_dict:
            FoundServices.add("dhcp")

    # we want to count nbns request and responses but not fragments. Is this the right one?

    def nbns(self, packet_dict, FoundServices):
        if "nbns.id" in packet_dict:
            FoundServices.add("nbns")

    # we want to count smb request and responses but not fragments. Is this the right one?
    # could subdivide by cmd type
    def smb(self, packet_dict, FoundServices):
        if "smb.cmd" in packet_dict:
            FoundServices.add("smb")

    # we want to count smb2 request and responses but not fragments. Is this the right one?
    # could subdivide by cmd type
    def smb2(self, packet_dict, FoundServices):
        if "smb2.cmd" in packet_dict:
            FoundServices.add("smb2")

    def pnrp(self, packet_dict, FoundServices):
        if "pnrp.messageType" in packet_dict:
            FoundServices.add("pnrp")

    # web service dynamic discovery - no obvious tshark hook
    # wireshark tags ssdp on srcport 1900 without the broadcast
    def wsdd_ssdp(self, packet_dict, FoundServices):
        if (
            "udp.dst" in packet_dict and packet_dict["udp.dst"] == "239.255.255.250"
        ) or ("ipv6.dst" in packet_dict and packet_dict["ipv6.dst"] == "ff02::c"):
            if "udp.dstport" in packet_dict and packet_dict["udp.dstport"] == "3702":
                FoundServices.add("wsdd")
            if "udp.dstport" in packet_dict and packet_dict["udp.dstport"] == "1900":
                FoundServices.add("ssdp")
