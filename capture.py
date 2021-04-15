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

import re
import threading
import subprocess
import json
from queue import *
import queues

# capture packets using wireshark and convert them to python dictionary objects
# args input-file-name, ethernet-interface, how-long


class packetcapture(threading.Thread):
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
        cmd = "sudo " + self.tshark_program + " -V -i -l -T ek"
        if self.input_file_name is not None:
            cmd = "" + self.tshark_program + " -V -r " + self.input_file_name + " -T ek"
        else:
            cmd = (
                "sudo "
                + self.tshark_program
                + " -V -i "
                + self.interface
                + " -a duration:"
                + str(self.howlong)
                + " -l -T ek"
            )
        print("capture.packetcapture: run(): Capturing with: ", cmd)
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            shell=True,
            universal_newlines=True,
        )
        json_str = ""
        # for line in p.stdout:
        while True:

            line = p.stdout.readline()
            if "layers" in line:
                # print("capture.packetcapture: working with line ", line)
                json_obj = json.loads(line.strip())
                source_filter = json_obj["layers"]
                keyval = source_filter.items()
                # print("capture.packetcapture: working with dict ", line)
                a = unwrap(keyval)
                # print("capture.packetcapture: working with packet ", a)
                send_data(a)
            else:
                # print("capture.packetcapture: ignoring: ",line)
                pass
            if not line and p.poll() is not None:
                # possible could delay here to let processing complete
                print("capture.packetcapture: We're done - no input and tshark exited")
                send_data({})
                break
        print("capture.packetcapture.run: Exiting thread")
        p.stdout.close()
        p.wait()


# saves each dictionary object into a Queue


def send_data(dictionary):
    # print("sending dictionary size: ", len(dictionary))
    # print("sending dictionary : ", dictionary)
    queues.sharedQ.put(dictionary)


# This is a global foo_foo_ to foo. keymap that is shared across all packets
keymap = {}

# this function unwraps a multi level JSON object into a python dictionary with key value pairs


def unwrap(keyval):

    newKeyval = {}
    for key1, value1 in keyval:

        if key1 not in keymap:
            # weirdness in the export format when using EK which we use because all on one line
            # The json has some with xxx.flags xxx.flags_tree xx.flags.yyy the _tree doesn't show up in this format
            # couldn't figure out how to convert 'xxx_xxx_' to 'xxx.' so converted 'xxx_xxx_' to 'xxx__' and then 'xxx.'
            # found src_ and dst_ in arp
            # found request_ record_ flags_ inside some keys.  Might want to tighten down record_ can be an inner key
            massagedKey1 = (
                re.sub(r"(\w+_)(\1)+", r"\1_", key1)
                .replace("__", ".")
                .replace("request_", "request.")
                .replace("record_", "record.")
                .replace("flags_", "flags.")
                .replace("src_", "src.")
                .replace("dst_", "dst.")
            )
            # add the before and after to the map so we don't have to calculate again
            keymap[key1] = massagedKey1
            # print("registered mapping: ", key1, " --> ",massagedKey1)

        if isinstance(value1, (str, bool, list)):
            newKeyval[keymap[key1]] = value1
        elif value1 is None:
            # print("Ignoring and tossing null value", key1)
            pass
        else:
            newKeyval.update(unwrap(value1.items()))
    return newKeyval
