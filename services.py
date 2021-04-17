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

import multiprocessing
import queues

# check the traffic for different services in the traffic suhc as tls,http,smtp


class ServiceIdentity(multiprocessing.Process):
    def __init__(self, name, inQ, outQ):
        multiprocessing.Process.__init__(self)
        self.name = name
        self.inQ = inQ
        self.outQ = outQ

    def run(self):
        print("ServiceIdentity: run()")
        service_count = 0
        while True:
            if not self.inQ.empty():
                Datalist = self.inQ.get()
                if not Datalist:
                    # empty datalist means done
                    # print("ServiceIdentity: We're done - empty dataset received")
                    self.outQ.put([])
                    break
                # print("ServiceIdentity: ",Datalist)
                # print("ServiceIdentity: NotifiedAbout=",Datalist[0],"invoke",str(service_count)," times")
                service_count += 1
                ID = Datalist[0]
                packet_dict = Datalist[1]
                packet_protocol = Datalist[2]
                found_services = self.findServices(ID, packet_dict, packet_protocol)
                if found_services:
                    Datalist.append(found_services)
                else:
                    Datalist.append({"no service"})
                self.outQ.put(Datalist)
        print("services.serviceidentity.run: Exiting thread")

    def findServices(self, ID, packet_dict, packet_protocol):
        found_services = set()
        if packet_protocol == "tcp" or packet_protocol == "udp":
            self.tls(packet_dict, found_services)
            self.http(packet_dict, found_services)
            self.ftp(packet_dict, found_services)
            self.ssh(packet_dict, found_services)
            self.dns(packet_dict, found_services)
            self.smtp(packet_dict, found_services)
            self.dhcp(packet_dict, found_services)
            self.nbns(packet_dict, found_services)
            self.smb(packet_dict, found_services)
            self.smb2(packet_dict, found_services)
            self.pnrp(packet_dict, found_services)
            self.wsdd_ssdp(packet_dict, found_services)
            if not found_services:
                # uncomment to see packets not marked as services
                # print("ServiceIdentity ",packet_dict)
                pass
        return found_services

    # if more services are needed they can be added in the following template
    def tls(self, packet_dict, found_services):

        if "tls.record.content_type" in packet_dict:

            found_services.add("tls")

    def http(self, packet_dict, found_services):

        if "http.request.method" in packet_dict:

            found_services.add("http")

    # not yet validated

    def ftp(self, packet_dict, found_services):

        if "ftp.request" in packet_dict:
            found_services.add("ftp")

    def ssh(self, packet_dict, found_services):

        # ssh.message_code?
        # was ssh.payload
        if "ssh.encrypted_packet" in packet_dict:
            found_services.add("ssh")

    def dns(self, packet_dict, found_services):

        if "dns.flags" in packet_dict:
            found_services.add("dns")

    # not yet validated

    def smtp(self, packet_dict, found_services):
        if "smtp.response" in packet_dict:
            found_services.add("smtp")

    def dhcp(self, packet_dict, found_services):
        if "dhcp.type" in packet_dict or "dhcpv6.msgtype" in packet_dict:
            found_services.add("dhcp")

    # we want to count nbns request and responses but not fragments. Is this the right one?

    def nbns(self, packet_dict, found_services):
        if "nbns.id" in packet_dict:
            found_services.add("nbns")

    # we want to count smb request and responses but not fragments. Is this the right one?
    # could subdivide by cmd type
    def smb(self, packet_dict, found_services):
        if "smb.cmd" in packet_dict:
            found_services.add("smb")

    # we want to count smb2 request and responses but not fragments. Is this the right one?
    # could subdivide by cmd type
    def smb2(self, packet_dict, found_services):
        if "smb2.cmd" in packet_dict:
            found_services.add("smb2")

    def pnrp(self, packet_dict, found_services):
        if "pnrp.messageType" in packet_dict:
            found_services.add("pnrp")

    # web service dynamic discovery - no obvious tshark hook
    # wireshark tags ssdp on srcport 1900 without the broadcast
    def wsdd_ssdp(self, packet_dict, found_services):
        if (
            "udp.dst" in packet_dict and packet_dict["udp.dst"] == "239.255.255.250"
        ) or ("ipv6.dst" in packet_dict and packet_dict["ipv6.dst"] == "ff02::c"):
            if "udp.dstport" in packet_dict and packet_dict["udp.dstport"] == "3702":
                found_services.add("wsdd")
            if "udp.dstport" in packet_dict and packet_dict["udp.dstport"] == "1900":
                found_services.add("ssdp")
