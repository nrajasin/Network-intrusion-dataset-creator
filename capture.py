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
import subprocess
import json
import time
import logging


# capture packets using wireshark and convert them to python dictionary objects
# args input-file-name, ethernet-interface, how-long


class PacketCapture:
    def __init__(
        self, name, tshark_program, input_file_name, interface, how_long, outQ
    ):
        self.name = name
        self.logger = logging.getLogger(__name__)

        self.tshark_program = tshark_program
        self.input_file_name = input_file_name
        self.interface = interface
        self.how_long = how_long
        self.outQ = outQ
        # This is a global foo_foo_ to foo. keymap that is shared across all packets
        self.keymap = {}

    def run(self):
        cmd = "sudo --help"
        if self.input_file_name is not None:
            cmd = "" + self.tshark_program + " -V -r " + self.input_file_name + " -T ek"
        else:
            cmd = (
                "sudo "
                + self.tshark_program
                + " -V -i "
                + self.interface
                + " -a duration:"
                + str(self.how_long)
                + " -l -T ek"
            )
        self.logger.info("Starting: Capturing with: %s", cmd)
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            shell=True,
            universal_newlines=True,
        )
        json_str = ""
        num_read = 0
        start_timer = time.perf_counter()

        # for line in p.stdout:
        while True:

            line = p.stdout.readline()
            if "layers" in line:
                num_read += 1
                self.logger.debug("Working with line %s", line)
                json_obj = json.loads(line.strip())
                source_filter = json_obj["layers"]
                keyval = source_filter.items()
                self.logger.debug("Working with dict %s", keyval)
                a = self.unwrap(keyval)
                self.logger.debug("Working with packet %s", a)
                self.send_data(a)
            else:
                # we get blank lines
                self.logger.debug("Ignoring: %s", line)
                pass
            if not line and p.poll() is not None:
                # possible could delay here to let processing complete
                self.logger.debug("We're done - no input and tshark exited")
                self.send_data({})
                break
        end_timer = time.perf_counter()
        calc_rate = num_read / (end_timer - start_timer)
        self.logger.info("Ingested: %d rate: %f ", num_read, calc_rate)
        p.stdout.close()
        p.wait()
        self.logger.info("Exiting thread")

    # saves each dictionary object into a Queue

    def send_data(self, dictionary):
        self.logger.debug("Sending dictionary size: %d", len(dictionary))
        self.logger.debug("Sending dictionary : %s", dictionary)
        self.outQ.put(dictionary)

    # this function unwraps a multi level JSON object into a python dictionary with key value pairs

    def unwrap(self, keyval):

        newKeyval = {}
        for key1, value1 in keyval:

            if key1 not in self.keymap:
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
                    .replace("tcp_flags", "tcp.flags")
                    .replace("flags_", "flags.")
                    .replace("src_", "src.")
                    .replace("dst_", "dst.")
                )
                # add the before and after to the map so we don't have to calculate again
                self.keymap[key1] = massagedKey1
                self.logger.debug("Registered mapping: %s --> %s", key1, massagedKey1)

            if isinstance(value1, (str, bool, list)):
                newKeyval[self.keymap[key1]] = value1
            elif value1 is None:
                self.logger.debug("Ignoring and tossing null value %s", key1)
                pass
            else:
                newKeyval.update(self.unwrap(value1.items()))
        return newKeyval
