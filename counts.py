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
import math
import csv
from datetime import datetime
from datetime import time
from cvar import windowcounts

# Creates the window counts and writes them to the CSV
# Divide the data into time windows so that you can get average information for a given time


class timesandcounts (threading.Thread):

    fieldnames = ['tcp_frame_length', 'tcp_ip_length', 'tcp_length',
                  'udp_frame_length', 'udp_ip_length', 'udp_length',
                  'arp_frame_length',
                  'num_tls', 'num_http', 'num_ftp', 'num_ssh', 'num_smtp', 'num_dhcp', 'num_dns',
                  'num_nbns', 'num_smb', 'num_smb2', 'num_pnrp', 'num_wsdd', 'num_ssdp',
                  'num_tcp', 'num_udp', 'num_arp', 'num_igmp',
                  'connection_pairs', 'num_ports', 'num_packets', 'window_end_time']

    def __init__(self, threadID, name, counter, time_window, *args):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.current_time = 0
        self.counter = counter
        self.time_window = time_window
        self.args = args
        self.csv_file_path = args[0]

        self.cvar = windowcounts()

    def run(self):
        print("counts.times: run()")
        with open(self.csv_file_path, 'w') as csvfile:

            writer = csv.DictWriter(
                csvfile, fieldnames=self.fieldnames, restval='0')
            writer.writeheader()
            csvfile.flush()

            pack_count = 0
            time_window_index = 0
            time_window_stop = 0

            while True:

                if not queues.timesQ.empty():

                    pack_count += 1
                    Datalist = queues.timesQ.get()
                    if not Datalist:
                        break
                    #print("counts.times.run: processing data list: ", Datalist)

                    ID = Datalist[0]
                    Data = Datalist[1]
                    Prot1 = Datalist[2]
                    services = Datalist[3]

                    if pack_count == 1:
                        # claim stop time was 0 which will cause a new window to be built
                        # starting time and current time are the message frame.time_epoch field
                        time_window_index, time_window_stop, self.current_time = self.timecheck(
                            Data['frame.time_epoch'], 0, time_window_index)
                        self.cvar.window_end_time = time_window_stop

                    time_window_index, time_window_stop, self.current_time = self.timecheck(
                        Data['frame.time_epoch'], time_window_stop, time_window_index)

                    if time_window_index == self.cvar.out_window_index:
                        #print("counts.times.run: add to existing time block")
                        self.cvar.num_packets += 1
                    else:
                        #print("counts.times.run: in new time block so aggregating and creating new block: ")
                        self.writewindow(writer, self.cvar)
                        csvfile.flush()
                        # clear variables for the next time window
                        self.cvar = self.resetwindow(
                            time_window_stop, self.cvar.out_window_index)

                    self.calculate(ID, Data, Prot1, services,
                                   time_window_index, time_window_stop, self.cvar)
            # it is possible that we will get this before all messages have flowed through
            print(
                "counts.times.run: End of data. total timed packet_count:", str(pack_count))
            csvfile.close()

    # calculate the new time offsets
    # fame.time_epoch - time in message.

    def timecheck(self, frame_time_epoch, time_window_stop, time_window_index):
        # this float lh=to the second rh is msec - convert epoch time to msec
        packet_frame_time = int(float(frame_time_epoch)*1000)
        #print ("packet_frame_time:",str(packet_frame_time)," stop:",str(time_window_stop))

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
            #print("counts.timecheck count:",str(time_window_index)," stopTime:",str(time_window_stop))

        return(time_window_index, time_window_stop, packet_frame_time)

    def calculate(self, ID, Data, Prot1, services, time_window_index, time_window_stop, cvar):

        #print("calculate: ",ID, Prot1, services)
        # Adding or changing attributes

        if Prot1 == 'tcp':
            cvar.tcp_frame_length = cvar.tcp_frame_length + \
                int(Data['frame.len'])
            try:
                cvar.tcp_ip_length = cvar.tcp_ip_length + int(Data['ip.len'])
            except KeyError:  # does not exist in ipv6
                cvar.tcp_ip_length = cvar.tcp_ip_length + 0
            cvar.tcp_length = cvar.tcp_length + int(Data['tcp.len'])
            self.count_services(services, cvar)
            cvar.num_tcp += 1
            self.accumulate_IDs(ID, cvar)
            self.accumulate_ports(
                [Data['tcp.srcport'], Data['tcp.dstport']], cvar)

        elif Prot1 == 'udp':
            cvar.udp_frame_length = cvar.udp_frame_length + \
                int(Data['frame.len'])
            try:
                cvar.udp_ip_length = cvar.udp_ip_length + int(Data['ip.len'])
            except KeyError:  # does not exist in ipv6
                cvar.udp_ip_length = cvar.udp_ip_length+0
            cvar.udp_length = cvar.udp_length + int(Data['udp.length'])
            self.count_services(services, cvar)
            cvar.num_udp += 1
            self.accumulate_IDs(ID, cvar)
            self.accumulate_ports(
                [Data['udp.srcport'], Data['udp.dstport']], cvar)

        elif Prot1 == 'arp':
            cvar.arp_frame_length = cvar.arp_frame_length + \
                int(Data['frame.len'])
            cvar.num_arp += 1
            self.accumulate_IDs(ID, cvar)
        elif Prot1 == 'igmp':
            # TODO become more clever about igmp if needed
            cvar.num_igmp += 1

    def count_services(self, slist, cvar):

        if 'tls' in slist:
            cvar.num_tls += 1
        elif 'http' in slist:
            cvar.num_http += 1
        elif 'ftp' in slist:
            cvar.num_ftp += 1
        elif 'ssh' in slist:
            cvar.num_ssh += 1
        elif 'dns' in slist:
            cvar.num_dns += 1
        elif 'smtp' in slist:
            cvar.num_smtp += 1
        elif 'dhcp' in slist:
            cvar.num_dhcp += 1
        elif 'nbns' in slist:
            cvar.num_nbns += 1
        elif 'smb' in slist:
            cvar.num_smb += 1
        elif 'smb2' in slist:
            cvar.num_smb2 += 1
        elif 'pnrp' in slist:
            cvar.num_pnrp += 1
        elif 'wsdd' in slist:
            cvar.num_wsdd += 1
        elif 'ssdp' in slist:
            cvar.num_ssdp += 1

    def accumulate_IDs(self, ID, cvar):
        if not ID in cvar.IDs:
            cvar.IDs.add(ID)
            # print(cvar.IDs)

    # Accumulated for TCP and IP

    def accumulate_ports(self, ports, cvar):
        for p in ports:
            if not p in cvar.ports:
                cvar.ports.add(p)

    # map cvar to a dictonary to bind to the csv writer
    # Write one time window as a row to the CSV file
    def writewindow(self, writer, rowdata):
        print("    counts.times.calculate: Window: ", rowdata.out_window_index,
              "packetCount:", rowdata.num_packets,
              "endTime", datetime.utcfromtimestamp(rowdata.window_end_time/1000))

        # this work but leaves unused fields empty instead of with zeros
        # csvrowdata = rowdata.__dict__.copy()
        # csvrowdata.pop('IDs', None)
        # csvrowdata.pop('ports', None)
        # csvrowdata.pop('out_window_index',None)
        # csvrowdata['connection_pairs'] = len(rowdata.IDs)
        # csvrowdata['num_ports'] = len(rowdata.ports)

        csvrowdata = {}
        csvrowdata['tcp_frame_length'] = rowdata.tcp_frame_length
        csvrowdata['tcp_ip_length'] = rowdata.tcp_ip_length
        csvrowdata['tcp_length'] = rowdata.tcp_length

        csvrowdata['udp_frame_length'] = rowdata.udp_frame_length
        csvrowdata['udp_ip_length'] = rowdata.udp_ip_length
        csvrowdata['udp_length'] = rowdata.udp_length

        csvrowdata['arp_frame_length'] = rowdata.arp_frame_length

        csvrowdata['num_tls'] = rowdata.num_tls
        csvrowdata['num_http'] = rowdata.num_http
        csvrowdata['num_ftp'] = rowdata.num_ftp
        csvrowdata['num_ssh'] = rowdata.num_ssh
        csvrowdata['num_smtp'] = rowdata.num_smtp
        csvrowdata['num_dhcp'] = rowdata.num_dhcp
        csvrowdata['num_dns'] = rowdata.num_dns
        csvrowdata['num_nbns'] = rowdata.num_nbns
        csvrowdata['num_smb'] = rowdata.num_smb
        csvrowdata['num_smb2'] = rowdata.num_smb2
        csvrowdata['num_pnrp'] = rowdata.num_pnrp
        csvrowdata['num_wsdd'] = rowdata.num_wsdd
        csvrowdata['num_ssdp'] = rowdata.num_ssdp

        csvrowdata['num_tcp'] = rowdata.num_tcp
        csvrowdata['num_udp'] = rowdata.num_udp
        csvrowdata['num_arp'] = rowdata.num_arp
        csvrowdata['num_igmp'] = rowdata.num_igmp
        csvrowdata['connection_pairs'] = len(rowdata.IDs)
        csvrowdata['num_ports'] = len(rowdata.ports)
        csvrowdata['num_packets'] = rowdata.num_packets

        csvrowdata['window_end_time'] = rowdata.window_end_time

        writer.writerow(csvrowdata)

    # Reset all the values for this window
    def resetwindow(self, time_window_end, out_window_index):
        cvar = windowcounts(time_window_end=time_window_end,
                            out_window_index=out_window_index+1)
        return cvar
