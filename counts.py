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
        "window_end_time",
    ]

    def __init__(self, name, time_window, csv_file_path, inQ):
        multiprocessing.Process.__init__(self)
        self.name = name
        self.time_window = time_window
        self.csv_file_path = csv_file_path
        self.inQ = inQ

        self.cvar = windowcounts()
        self.current_time = 0

    def run(self):
        print("TimesAndCounts: run()")
        with open(self.csv_file_path, "w") as csvfile:

            writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames, restval="0")
            writer.writeheader()
            csvfile.flush()

            pack_count = 0
            time_window_index = 0
            time_window_stop = 0

            while True:

                if not self.inQ.empty():

                    pack_count += 1
                    Datalist = self.inQ.get()
                    if not Datalist:
                        break
                    # print("TimesAndCounts.run: processing packet_dict list: ", Datalist)

                    ID = Datalist[transitkeys.key_id]
                    packet_dict = Datalist[transitkeys.key_packet]
                    Prot1 = Datalist[transitkeys.key_protocol]
                    services = Datalist[transitkeys.key_services]

                    if pack_count == 1:
                        # claim stop time was 0 which will cause a new window to be built
                        # starting time and current time are the message frame.time_epoch field
                        (
                            time_window_index,
                            time_window_stop,
                            self.current_time,
                        ) = self.timecheck(
                            packet_dict["frame.time_epoch"], 0, time_window_index
                        )
                        self.cvar.window_end_time = time_window_stop

                    (
                        time_window_index,
                        time_window_stop,
                        self.current_time,
                    ) = self.timecheck(
                        packet_dict["frame.time_epoch"],
                        time_window_stop,
                        time_window_index,
                    )

                    if time_window_index == self.cvar.window_index:
                        # print("TimesAndCounts.run: add to existing time block")
                        self.cvar.num_packets += 1
                    else:
                        # print("TimesAndCounts.run: in new time block so aggregating and creating new block: ")
                        self.write_window(writer, self.cvar)
                        csvfile.flush()
                        # clear variables for the next time window
                        self.cvar = self.reset_window(
                            time_window_stop, self.cvar.window_index
                        )

                    self.calculate(
                        ID,
                        packet_dict,
                        Prot1,
                        services,
                        time_window_index,
                        time_window_stop,
                        self.cvar,
                    )
            # it is possible that we will get this before all messages have flowed through
            print(
                "TimesAndCounts.run: End of packet_dict. total timed packet_count:",
                str(pack_count),
            )
            csvfile.close()

    # calculate the new time offsets
    # fame.time_epoch - time in message.

    def timecheck(self, frame_time_epoch, time_window_stop, time_window_index):
        # this float lh=to the second rh is msec - convert epoch time to msec
        packet_frame_time = int(float(frame_time_epoch) * 1000)
        # print ("packet_frame_time:",str(packet_frame_time)," stop:",str(time_window_stop))

        if packet_frame_time <= time_window_stop:
            # return the same time if still in the window
            pass
        else:
            time_window_index += 1
            # first interval starts on the first packet. all others are locked to that
            if time_window_stop == 0:
                time_window_start_ceil = packet_frame_time
            else:
                time_window_start_ceil = time_window_stop
            time_window_stop = time_window_start_ceil + self.time_window
            # print("TimesAndCounts.timecheck count:",str(time_window_index)," stopTime:",str(time_window_stop))

        return (time_window_index, time_window_stop, packet_frame_time)

    def calculate(
        self,
        ID,
        packet_dict,
        Prot1,
        services,
        time_window_index,
        time_window_stop,
        cvar,
    ):

        # print("TimesAndCounts calculate: ",ID, Prot1, services)
        # Adding or changing attributes

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
        # print(cvar.IDs)

    # Accumulated for TCP and IP

    def accumulate_ports(self, ports, cvar):
        # rely on set symantics, add array elements if not present
        cvar.ports.update(ports)

    # map cvar to a dictonary to bind to the csv writer
    # Write one time window as a row to the CSV file
    def write_window(self, writer, one_record):
        print(
            "    TimesAndCounts.calculate: Window: ",
            one_record.window_index,
            "packetCount:",
            one_record.num_packets,
            "endTime",
            datetime.utcfromtimestamp(one_record.window_end_time / 1000),
        )

        # this work but leaves unused fields empty instead of with zeros
        # we can tell the csv writer to fill empty cells with zeros
        record_for_csv = one_record.__dict__.copy()
        record_for_csv.pop("IDs", None)
        record_for_csv.pop("ports", None)
        record_for_csv.pop("window_index", None)
        record_for_csv["num_connection_pairs"] = len(one_record.IDs)
        record_for_csv["num_ports"] = len(one_record.ports)

        writer.writerow(record_for_csv)

    # Reset all the values for this window
    def reset_window(self, time_window_end, window_index):
        cvar = windowcounts(
            time_window_end=time_window_end, window_index=window_index + 1
        )
        return cvar
