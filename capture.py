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
import subprocess
import json
from queue import *
import ipaddress
import set
from detectors import *
from services import *
from counts import *


# capture packets using wireshark and convert them to python dictionary objects
# args input-file-name, ethernet-interface, how-long
class packetcap (threading.Thread):
    def __init__(self, threadID, name, counter, *args):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.args = args
        self.tshark_program = args[0]
        self.input_file_name = args[1]
        self.interface = args[2]
        self.howlong = args[3]

    def run(self):
        cmd = "sudo "+self.tshark_program+" -V -i -l -T ek"
        if (self.input_file_name is not None):
            cmd = ""+self.tshark_program+" -V -r " +self.input_file_name + " -T ek"
        else:
            cmd = "sudo "+self.tshark_program+" -V -i " +self.interface+" -a duration:" + str(self.howlong) + " -l -T ek"
        print ("capture.packetcap: run(): Capturing with: ", cmd)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             bufsize=1, shell=True, universal_newlines=True)
        json_str = ""
        # for line in p.stdout:
        while True:

            line = p.stdout.readline()
            if "layers" in line:
                #print("capture.packetcap: working with line ", line)
                json_obj = json.loads(line.strip())
                source_filter = json_obj['layers']
                keyval = source_filter.items()
                #print("capture.packetcap: working with dict ", line)
                a = unwrap(keyval, {})
                #print("capture.packetcap: working with packet ", a)
                send_data(a)
            else:
                # print("capture.packetcap: ignoring: ",line)
                pass
            if (not line and p.poll() is not None):
                # possible could delay here to let processing complete
                print("capture.packetcap: We're done - no input and tshark exited")
                set.end_of_file=True
                break
        p.stdout.close()
        p.wait()


# saves each dictionary object into a Queue

def send_data(dictionary):
    #print("sending dictionary size: ", len(dictionary))
    #print("sending dictionary : ", dictionary)
    set.packet_count +=1
    set.sharedQ.put(dictionary)

# this function unwraps a multi level JSON object into a python dictionary with key value pairs


def unwrap(keyval, temp):

    for key1, value1 in keyval:
        if isinstance(value1, (str, bool, list)):
            # weirdness in the export format when using EK
            # The json has some with xxx.flags xxx.flags_tree xx.flags.yyy the _tree doesn't show up in this format
            temp[key1
                 .replace("tcp_tcp_", "tcp.")
                 .replace("udp_udp_", "udp.")
                 .replace("igmp_igmp", "igmp.")
                 .replace("ip_ip_", "ip.")
                 .replace("ipv6_ipv6_","ipv6.")
                 .replace("frame_frame_", "frame.")
                 .replace("eth_eth_", "eth.")
                 .replace("dns_dns_", "dns.")
                 .replace("ssh_ssh_", "ssh.")
                 .replace("tls_tls_", "tls.")
                 .replace("http_http_","http.")
                 .replace("https_https_","https.")
                 .replace("dhcp_dhcp_","dhcp.")
                 # these are inside a key and maybe should be more qualified
                 .replace("request_","request.")
                 .replace("record_", "record.")
                 .replace("flags_", "flags.")
                 ] = value1
        elif value1 is None:
            #print("Ignoring and tossing null value", key1)
            pass
        else:
            unwrap(value1.items(), temp)
    return(temp)
