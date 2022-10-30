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
import math
import csv
from datetime import datetime
from datetime import time
from cvar import windowcounts
from tumblingwindow import TumblingWindow
import transitkeys
import logging


# Creates the window counts and writes them to the CSV
# Divide the packet_dict into time windows so that you can get average information for a given time


class TimesAndCounts(multiprocessing.Process):

    fieldnames = [
        "tcp_frame_length",
        "tcp_ip_length",
        "tcp_length",
        "udp_frame_length",
        "udp_ip_length",
        "udp_length",
        "arp_frame_length",
        "num_tls",
        "num_http",
        "num_ftp",
        "num_ssh",
        "num_smtp",
        "num_dhcp",
        "num_dns",
        "num_nbns",
        "num_smb",
        "num_smb2",
        "num_pnrp",
        "num_wsdd",
        "num_ssdp",
        "num_tcp",
        "num_udp",
        "num_arp",
        "num_igmp",
        "num_connection_pairs",
        "num_ports",
        "num_packets",
        "window_start_time",
        "window_end_time",
    ]

    def __init__(
        self, name, window_length_time, window_length_count, csv_file_path, inQ
    ):
        multiprocessing.Process.__init__(self)
        self.name = name
        self.logger = logging.getLogger(__name__)
        self.window_length_time = window_length_time
        self.csv_file_path = csv_file_path
        self.inQ = inQ
        self.tumbling_window = TumblingWindow(
            window_length_time=window_length_time,
            window_length_count=window_length_count,
        )

    def run(self):
        self.logger.info("Starting")
        with open(self.csv_file_path, "w") as csvfile:

            writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames, restval="0")
            writer.writeheader()
            csvfile.flush()

            pack_count_total = 0
            window_index = 0
            current_window = None

            while True:

                if not self.inQ.empty():

                    window_start_time = None
                    # read from teh queue
                    Datalist = self.inQ.get()
                    if not Datalist:
                        break
                    self.logger.debug("Processing packet_dict list: %s", Datalist)
                    pack_count_total += 1

                    ID = Datalist[transitkeys.key_id]
                    packet_dict = Datalist[transitkeys.key_packet]
                    Prot1 = Datalist[transitkeys.key_protocol]
                    services = Datalist[transitkeys.key_services]
                    # align windows on msec boundaries even though we have finer resolution
                    # convert this float in seconds to an int in msec - convert epoch time to msec
                    frame_time_epoch = int(
                        float(packet_dict["frame.time_epoch"]) * 1000
                    )

                    # set the window to start on the first packet
                    if current_window is None:
                        # determine the window start time, stop time and index this packet belongs in
                        window_start_time = (
                            self.tumbling_window.calculate_tumbling_window(
                                frame_time_epoch=frame_time_epoch,
                                window_start_time_previous=None,
                                window_count_previous=None,
                            )
                        )
                        window_index += 1
                        # create the calculated window
                        current_window = self.create_window(
                            window_start_time=window_start_time,
                            window_index=window_index,
                        )

                    # flush and create windows until we are in the one for this packet
                    while self.tumbling_window.is_outside_current_window(
                        frame_time_epoch=frame_time_epoch,
                        window_start_time_previous=current_window.window_start_time,
                        window_count_previous=current_window.num_packets,
                    ):
                        self.logger.debug(
                            "Flushing window %d - %d",
                            current_window.window_start_time,
                            current_window.window_end_time,
                        )
                        self.write_window(writer, current_window)
                        csvfile.flush()
                        # advance 1 window
                        window_index += 1
                        # this will advance window calculator if packet not in current window

                        window_start_time = self.tumbling_window.calculate_tumbling_window(
                            frame_time_epoch=frame_time_epoch,
                            window_start_time_previous=current_window.window_start_time,
                            window_count_previous=current_window.num_packets,
                        )
                        current_window = self.create_window(
                            window_start_time=window_start_time,
                            window_index=window_index,
                        )

                    # update current window current_window
                    self.analyze_update_window(
                        ID=ID,
                        packet_dict=packet_dict,
                        Prot1=Prot1,
                        services=services,
                        target_window=current_window,
                    )

            if current_window.num_packets > 0:
                self.write_window(writer, current_window)
                csvfile.flush()

            # it is possible that we will get this before all messages have flowed through
            self.logger.info(
                "End of packet_dict. total timed packet_count: %d", pack_count_total
            )
            csvfile.close()
        self.logger.info("Exiting thread")

    # updates the passed in cvar with values derived from packet_dict
    def analyze_update_window(
        self,
        ID,
        packet_dict,
        Prot1,
        services,
        target_window,
    ):

        self.logger.debug("Received %s %s %s", ID, Prot1, services)
        # Adding or changing attributes

        target_window.num_packets += 1

        # set the window end time to the time of the last packet
        frame_time_epoch = int(float(packet_dict["frame.time_epoch"]) * 1000)
        target_window.window_end_time = frame_time_epoch

        if Prot1 == "tcp":
            target_window.tcp_frame_length = target_window.tcp_frame_length + int(
                packet_dict["frame.len"]
            )
            try:
                target_window.tcp_ip_length = target_window.tcp_ip_length + int(
                    packet_dict["ip.len"]
                )
            except KeyError:  # does not exist in ipv6
                target_window.tcp_ip_length = target_window.tcp_ip_length + 0

            target_window.tcp_length = target_window.tcp_length + int(
                packet_dict["tcp.len"]
            )
            self.count_services(services, target_window)
            target_window.num_tcp += 1
            self.accumulate_IDs(ID, target_window)
            self.accumulate_ports(
                [packet_dict["tcp.srcport"], packet_dict["tcp.dstport"]], target_window
            )

        elif Prot1 == "udp":
            target_window.udp_frame_length = target_window.udp_frame_length + int(
                packet_dict["frame.len"]
            )
            try:
                target_window.udp_ip_length = target_window.udp_ip_length + int(
                    packet_dict["ip.len"]
                )
            except KeyError:  # does not exist in ipv6
                target_window.udp_ip_length = target_window.udp_ip_length + 0

            target_window.udp_length = target_window.udp_length + int(
                packet_dict["udp.length"]
            )
            self.count_services(services, target_window)
            target_window.num_udp += 1
            self.accumulate_IDs(ID, target_window)
            self.accumulate_ports(
                [packet_dict["udp.srcport"], packet_dict["udp.dstport"]], target_window
            )

        elif Prot1 == "arp":
            target_window.arp_frame_length = target_window.arp_frame_length + int(
                packet_dict["frame.len"]
            )
            target_window.num_arp += 1
            self.accumulate_IDs(ID, target_window)
        elif Prot1 == "igmp":
            # TODO become more clever about igmp if needed
            target_window.num_igmp += 1

    # an individual packet could be more than one thing.  Some SSDP traffic has HTTP over UDP
    def count_services(self, slist, target_window):

        # should a packet only fit in one bucket?
        # is HTTP a service or a ?? that others can use?
        if "http" in slist:
            target_window.num_http += 1

        if "tls" in slist:
            target_window.num_tls += 1

        if "ftp" in slist:
            target_window.num_ftp += 1
        elif "ssh" in slist:
            target_window.num_ssh += 1
        elif "dns" in slist:
            target_window.num_dns += 1
        elif "smtp" in slist:
            target_window.num_smtp += 1
        elif "dhcp" in slist:
            target_window.num_dhcp += 1
        elif "nbns" in slist:
            target_window.num_nbns += 1
        elif "smb2" in slist:
            target_window.num_smb2 += 1
        elif "smb" in slist:
            target_window.num_smb += 1
        elif "pnrp" in slist:
            target_window.num_pnrp += 1
        elif "wsdd" in slist:
            target_window.num_wsdd += 1
        elif "ssdp" in slist:
            target_window.num_ssdp += 1

    def accumulate_IDs(self, ID, target_window):
        # rely on set semantics, add if not present
        target_window.IDs.add(ID)
        self.logger.debug("%s", target_window.IDs)

    # Accumulated for TCP and IP

    def accumulate_ports(self, ports, target_window):
        # rely on set symantics, add array elements if not present
        target_window.ports.update(ports)

    # map target_window to a dictonary to bind to the csv writer
    # Write one time window as a row to the CSV file
    def write_window(self, writer, one_record):
        start_time_seconds = datetime.utcfromtimestamp(
            one_record.window_start_time / 1000
        )
        end_time_seconds = datetime.utcfromtimestamp(one_record.window_end_time / 1000)
        self.logger.info(
            "Window: %d packetCount: %d startTime: %s endTime: %s",
            one_record.window_index,
            one_record.num_packets,
            start_time_seconds,
            end_time_seconds,
        )

        # this works but leaves unused fields empty instead of with zeros
        # we can tell the csv writer to fill empty cells with zeros
        record_for_csv = one_record.__dict__.copy()
        record_for_csv.pop("IDs", None)
        record_for_csv.pop("ports", None)
        record_for_csv.pop("window_index", None)
        record_for_csv["num_connection_pairs"] = len(one_record.IDs)
        record_for_csv["num_ports"] = len(one_record.ports)

        writer.writerow(record_for_csv)

    # Reset all the values for this window
    def create_window(self, window_start_time, window_index):
        self.logger.debug(
            "Creating new window: %d start %d ",
            window_index,
            window_start_time,
        )
        new_window = windowcounts(
            window_start_time=window_start_time,
            window_index=window_index,
        )
        return new_window
