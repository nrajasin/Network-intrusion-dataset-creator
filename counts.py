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
import math
import csv
from datetime import datetime
from datetime import time
from cvar import windowcounts
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

    def __init__(self, name, time_window, csv_file_path, inQ):
        multiprocessing.Process.__init__(self)
        self.name = name
        self.logger = logging.getLogger(__name__)
        self.time_window = time_window
        self.csv_file_path = csv_file_path
        self.inQ = inQ

    def run(self):
        self.logger.info("Starting")
        with open(self.csv_file_path, "w") as csvfile:

            writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames, restval="0")
            writer.writeheader()
            csvfile.flush()

            pack_count_total = 0
            window_index = 0
            window_start_time = None
            window_end_time = None
            current_window = None

            while True:

                if not self.inQ.empty():

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
                    # convert this float in seconds to an int in msec - convert epoch time to msec
                    frame_time_epoch = int(
                        float(packet_dict["frame.time_epoch"]) * 1000
                    )

                    # determine the window start time, stop time and index this packet belongs in
                    (
                        window_start_time,
                        window_end_time,
                    ) = self.calculate_window_parameters(
                        frame_time_epoch=frame_time_epoch,
                        window_start_time=window_start_time,
                        window_end_time=window_end_time,
                    )
                    # reset the window to start on the first packet
                    if current_window is None:
                        window_index += 1
                        current_window = self.create_window(
                            window_start_time=window_start_time,
                            window_end_time=window_end_time,
                            window_index=window_index,
                        )

                    # determine if we can use this window or the next one
                    if (
                        frame_time_epoch >= current_window.window_start_time
                        and frame_time_epoch <= current_window.window_end_time
                    ):
                        # if we didn't end up in the next window then just add to the current
                        self.logger.debug("Add to existing time window")
                    else:
                        self.logger.debug(
                            "In new time window. Flushing %d and creating new window: %d",
                            current_window.window_start_time,
                            window_start_time,
                        )
                        self.write_window(writer, current_window)
                        csvfile.flush()
                        # create next time window
                        window_index += 1
                        current_window = self.create_window(
                            window_start_time=window_start_time,
                            window_end_time=window_end_time,
                            window_index=window_index,
                        )

                    # update current window current_window
                    self.calculate_and_populate(
                        ID=ID,
                        packet_dict=packet_dict,
                        Prot1=Prot1,
                        services=services,
                        cvar=current_window,
                    )

            # it is possible that we will get this before all messages have flowed through
            self.logger.info(
                "End of packet_dict. total timed packet_count: %d", pack_count_total
            )
            csvfile.close()
        self.logger.info("Exiting thread")

    # calculate the new time offsets
    # frame_time_epoch - time in message in msec from epoch
    # first time slot is aligns with the first packet
    # return the calculated window parameters for the passed in time
    def calculate_window_parameters(
        self, frame_time_epoch, window_start_time, window_end_time
    ):
        self.logger.debug(
            "frame_time_epoch: %d start: %d stop: %d",
            frame_time_epoch,
            window_start_time,
            window_end_time,
        )

        if window_end_time is not None and frame_time_epoch <= window_end_time:
            # return the same time if still in the window
            pass
        else:
            # move to the next window
            # first interval starts on the first packet. all others are locked to that
            if window_end_time is None:
                window_start_time = frame_time_epoch
            else:
                window_start_time = window_end_time
            window_end_time = window_start_time + self.time_window
            self.logger.debug(
                "new window: %d startTime: %d, stopTime: %d",
                window_start_time,
                window_end_time,
            )

        # return the calculated window parameters for the passed in time
        return (window_start_time, window_end_time)

    # updates the passed in cvar with values derived from packet_dict
    def calculate_and_populate(
        self,
        ID,
        packet_dict,
        Prot1,
        services,
        cvar,
    ):

        self.logger.debug("Received %s %s %s", ID, Prot1, services)
        # Adding or changing attributes

        cvar.num_packets += 1

        if Prot1 == "tcp":
            cvar.tcp_frame_length = cvar.tcp_frame_length + int(
                packet_dict["frame.len"]
            )
            try:
                cvar.tcp_ip_length = cvar.tcp_ip_length + int(packet_dict["ip.len"])
            except KeyError:  # does not exist in ipv6
                cvar.tcp_ip_length = cvar.tcp_ip_length + 0

            cvar.tcp_length = cvar.tcp_length + int(packet_dict["tcp.len"])
            self.count_services(services, cvar)
            cvar.num_tcp += 1
            self.accumulate_IDs(ID, cvar)
            self.accumulate_ports(
                [packet_dict["tcp.srcport"], packet_dict["tcp.dstport"]], cvar
            )

        elif Prot1 == "udp":
            cvar.udp_frame_length = cvar.udp_frame_length + int(
                packet_dict["frame.len"]
            )
            try:
                cvar.udp_ip_length = cvar.udp_ip_length + int(packet_dict["ip.len"])
            except KeyError:  # does not exist in ipv6
                cvar.udp_ip_length = cvar.udp_ip_length + 0

            cvar.udp_length = cvar.udp_length + int(packet_dict["udp.length"])
            self.count_services(services, cvar)
            cvar.num_udp += 1
            self.accumulate_IDs(ID, cvar)
            self.accumulate_ports(
                [packet_dict["udp.srcport"], packet_dict["udp.dstport"]], cvar
            )

        elif Prot1 == "arp":
            cvar.arp_frame_length = cvar.arp_frame_length + int(
                packet_dict["frame.len"]
            )
            cvar.num_arp += 1
            self.accumulate_IDs(ID, cvar)
        elif Prot1 == "igmp":
            # TODO become more clever about igmp if needed
            cvar.num_igmp += 1

    # an individual packet could be more than one thing.  Some SSDP traffic has HTTP over UDP
    def count_services(self, slist, cvar):

        # should a packet only fit in one bucket?
        # is HTTP a service or a ?? that others can use?
        if "http" in slist:
            cvar.num_http += 1

        if "tls" in slist:
            cvar.num_tls += 1

        if "ftp" in slist:
            cvar.num_ftp += 1
        elif "ssh" in slist:
            cvar.num_ssh += 1
        elif "dns" in slist:
            cvar.num_dns += 1
        elif "smtp" in slist:
            cvar.num_smtp += 1
        elif "dhcp" in slist:
            cvar.num_dhcp += 1
        elif "nbns" in slist:
            cvar.num_nbns += 1
        elif "smb2" in slist:
            cvar.num_smb2 += 1
        elif "smb" in slist:
            cvar.num_smb += 1
        elif "pnrp" in slist:
            cvar.num_pnrp += 1
        elif "wsdd" in slist:
            cvar.num_wsdd += 1
        elif "ssdp" in slist:
            cvar.num_ssdp += 1

    def accumulate_IDs(self, ID, cvar):
        # rely on set semantics, add if not present
        cvar.IDs.add(ID)
        self.logger.debug("%s", cvar.IDs)

    # Accumulated for TCP and IP

    def accumulate_ports(self, ports, cvar):
        # rely on set symantics, add array elements if not present
        cvar.ports.update(ports)

    # map cvar to a dictonary to bind to the csv writer
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
    def create_window(self, window_start_time, window_end_time, window_index):
        new_window = windowcounts(
            window_start_time=window_start_time,
            window_end_time=window_end_time,
            window_index=window_index,
        )
        return new_window
