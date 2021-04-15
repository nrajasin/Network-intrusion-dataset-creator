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


class serviceidentify:
    def findServices(self, ID, Data, PacketProtocol):
        FoundServices = []
        if PacketProtocol == "tcp" or PacketProtocol == "udp":
            self.tls(Data, FoundServices)
            self.http(Data, FoundServices)
            self.ftp(Data, FoundServices)
            self.ssh(Data, FoundServices)
            self.dns(Data, FoundServices)
            self.smtp(Data, FoundServices)
            self.dhcp(Data, FoundServices)
            self.nbns(Data, FoundServices)
            self.smb(Data, FoundServices)
            self.smb2(Data, FoundServices)
            self.pnrp(Data, FoundServices)
            self.wsdd_ssdp(Data, FoundServices)
            if not FoundServices:
                # uncomment to see packets not marked as services
                # print(Data)
                pass
        return FoundServices

    # if more services are needed they can be added in the following template
    def tls(self, Data, FoundServices):

        if "tls.record.content_type" in Data:

            FoundServices.append("tls")

    def http(self, Data, FoundServices):

        if "http.request.method" in Data:

            FoundServices.append("http")

    # not yet validated

    def ftp(self, Data, FoundServices):

        if "ftp.request" in Data:
            FoundServices.append("ftp")

    def ssh(self, Data, FoundServices):

        # ssh.message_code?
        # was ssh.payload
        if "ssh.encrypted_packet" in Data:
            FoundServices.append("ssh")

    def dns(self, Data, FoundServices):

        if "dns.flags" in Data:
            FoundServices.append("dns")

    # not yet validated

    def smtp(self, Data, FoundServices):
        if "smtp.response" in Data:
            FoundServices.append("smtp")

    def dhcp(self, Data, FoundServices):
        if "dhcp.type" in Data or "dhcpv6.msgtype" in Data:
            FoundServices.append("dhcp")

    # we want to count nbns request and responses but not fragments. Is this the right one?

    def nbns(self, Data, FoundServices):
        if "nbns.id" in Data:
            FoundServices.append("nbns")

    # we want to count smb request and responses but not fragments. Is this the right one?
    # could subdivide by cmd type
    def smb(self, Data, FoundServices):
        if "smb.cmd" in Data:
            FoundServices.append("smb")

    # we want to count smb2 request and responses but not fragments. Is this the right one?
    # could subdivide by cmd type
    def smb2(self, Data, FoundServices):
        if "smb2.cmd" in Data:
            FoundServices.append("smb2")

    def pnrp(self, Data, FoundServices):
        if "pnrp.messageType" in Data:
            FoundServices.append("pnrp")

    # web service dynamic discovery - no obvious tshark hook
    # wireshark tags ssdp on srcport 1900 without the broadcast
    def wsdd_ssdp(self, Data, FoundServices):
        if ("udp.dst" in Data and Data["udp.dst"] == "239.255.255.250") or (
            "ipv6.dst" in Data and Data["ipv6.dst"] == "ff02::c"
        ):
            if "udp.dstport" in Data and Data["udp.dstport"] == "3702":
                FoundServices.append("wsdd")
            if "udp.dstport" in Data and Data["udp.dstport"] == "1900":
                FoundServices.append("ssdp")
