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
class serviceidentify (threading.Thread):
    def __init__(self, threadID, name):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name

    def run(self):
        print("services.services: run()")
        service_count = 0
        while True:

            if queues.servicesQ.empty() == False:

                Datalist = queues.servicesQ.get()
                if not Datalist:
                    print("services.serviceidentity.run: We're done - empty dictionary received on queue")
                    queues.timesQ.put([])
                    break
                service_count +=1
                #print("services invoked "+str(service_count)+" times. Notified about ", Datalist[0])
                ID = Datalist[0]
                Data = Datalist[1]
                Prot1 = Datalist[2]
                found_services = []
                if Prot1 == "tcp" or Prot1 == "udp":

                    tls(Data,found_services)
                    http(Data,found_services)
                    ftp(Data,found_services)
                    ssh(Data,found_services)
                    dns(Data,found_services)
                    smtp(Data,found_services)
                    dhcp(Data,found_services)
                    nbns(Data,found_services)
                    smb(Data, found_services)
                    smb2(Data, found_services)
                    wsdd_ssdp(Data, found_services)

                # next module expects a 4th element in Datalist
                if len(found_services) > 0:
                    Datalist.append(found_services)
                else:
                    Datalist.append(["no service"])
                    # un-comment to see packets that had  no found service - 
                    # falling into here is expected a lot of TCP/UDP don't have services here, ARP for instance
                    #print(Data)
                queues.timesQ.put(Datalist)
        print("services.serviceidentity.run: Exiting thread")


# if more services are needed they can be added in the following template
def tls(Data,found_services):

    if "tls.record.content_type" in Data:

        found_services.append("tls")


def http(Data,found_services):

    if "http.request.method" in Data:

        found_services.append("http")


# not yet validated
def ftp(Data,found_services):

    if "ftp.request" in Data:
        found_services.append("ftp")


def ssh(Data,found_services):

    # ssh.message_code?
    # was ssh.payload
    if 'ssh.encrypted_packet' in Data:
        found_services.append("ssh")


def dns(Data,found_services):

    if 'dns.flags' in Data:
        found_services.append("dns")


# not yet validated
def smtp(Data,found_services):
    if 'smtp.response' in Data:
        found_services.append("smtp")


def dhcp(Data,found_services):
    if 'dhcp.type' in Data or 'dhcpv6.msgtype' in Data:
        found_services.append("dhcp")


# we want to count nbns request and responses but not fragments. Is this the right one?
def nbns(Data,found_services):
    if 'nbns.id' in Data:
        found_services.append("nbns")

# we want to count smb request and responses but not fragments. Is this the right one?
# could subdivide by cmd type
def smb(Data,found_services):
    if 'smb.cmd' in Data:
        found_services.append("smb")

# we want to count smb2 request and responses but not fragments. Is this the right one?
# could subdivide by cmd type
def smb2(Data,found_services):
    if 'smb2.cmd' in Data:
        found_services.append("smb2")

# web service dynamic discovery - no obvious tshark hook
def wsdd_ssdp(Data,found_services):
    if (('udp.dst' in Data and Data['udp.dst'] == "239.255.255.250") or ('ipv6.dst' in Data and Data['ipv6.dst'] == "ff02::c")):
        if 'udp.dstport' in Data and Data['udp.dstport'] == "3702" :
            found_services.append("wsdd")
        if 'udp.dstport' in Data and Data['udp.dstport'] == "1900" :
            found_services.append("ssdp")

