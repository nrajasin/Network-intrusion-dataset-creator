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
import set
import math
import cvar
import csv


# Divide the data into time windows so that you can get average information for a given time

class times (threading.Thread):
    def __init__(self, threadID, name, counter, *args):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.current_time = 0
        self.counter = counter
        self.args = args
        
    def run(self):
        print("counts.times: run()")
        with open(self.args[0], 'w') as csvfile:
            fieldnames = ['tcp_frame_length', 'tcp_ip_length', 'tcp_length', 'udp_frame_length',
                          'udp_ip_length', 'udp_length', 'arp_frame_length', 'src_length', 'dst_length', 'num_tls',
                          'num_http', 'num_ftp', 'num_ssh', 'num_smtp', 'num_dhcp', 'num_dns', 'num_tcp',
                          'num_udp', 'num_arp', 'connection_pairs', 'num_ports', 'num_packets']

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            csvfile.flush()

            pack_count = 0
            time_count = 0
            time_window_stop = 0

            while set.end_of_file == False:

                if not set.timesQ.empty():

                    pack_count = pack_count+1
                    Datalist = set.timesQ.get()
                    #print("processing data list: ", Datalist)

                    ID = Datalist[0]
                    Data = Datalist[1]
                    Prot1 = Datalist[2]
                    services = Datalist[3]
                    timec = 0

                    if pack_count == 1:

                        time_count = time_count+1
                        # time in message. this float lh=to the second rh is msec - onvert epoch time to msec
                        full_time = Data['frame.time_epoch']
                        full_time = int(float(full_time)*1000)
                        timestamp = (full_time)
                        # starting time and current time are the message frame.time_epoch field
                        set.starting = timestamp
                        self.current_time = timestamp
                        # first message in set so use time in message
                        time_window_start_ceil = timestamp
                        # initial stop time would be first message plus time window
                        time_window_stop = time_window_start_ceil + set.time_window

                    rec = timecheck(Data, time_window_stop, time_count, timec)
                    self.current_time = rec[2]
                    time_window_stop = rec[1]
                    time_count = rec[0]
                    timec = rec[0]
                    calculate(ID, Data, Prot1, services, timec, writer)
                    # should really only do this if row written out
                    csvfile.flush()
            # it is possible that we will get this before all messages have flowed through
            print("counts.times: notified of end of file.  closing down")
            csvfile.close()
            import os
            os._exit(1)


# calculate the new time offsets
def timecheck(Data, time_window_stop, time_count, timec):

    # time in message. this float lh=to the second rh is msec - onvert epoch time to msec
    full_time = Data['frame.time_epoch']
    full_time = int(float(full_time)*1000)
    timestamp = (full_time)

    if timestamp <= time_window_stop:
        # return the same time if still in the window
        timec = time_count
    else:
        time_count = time_count+1
        time_window_start_ceil = timestamp

        time_window_stop = time_window_start_ceil + set.time_window
        timec = time_count

    return(timec, time_window_stop, timestamp)


def calculate(ID, Data, Prot1, services, t, writer):

    #print("calculate: ",ID, Prot1, services)
    # Adding or changing attributes

    if t == cvar.out_record_count:
        #print("add to existing time block")
        cvar.tot_pack = cvar.tot_pack+1

        if Prot1 == 'tcp':
            cvar.tcp_frame_length = cvar.tcp_frame_length + \
                int(Data['frame.len'])
            cvar.tcp_ip_length = cvar.tcp_ip_length+int(Data['ip.len'])
            cvar.tcp_length = cvar.tcp_length+int(Data['tcp.len'])
            get_services(services)
            cvar.tcp = cvar.tcp+1
            check_ID(ID)
            ports([Data['tcp.srcport'], Data['tcp.dstport']])

        elif Prot1 == 'udp':
            cvar.udp_frame_length = cvar.udp_frame_length + \
                int(Data['frame.len'])
            try:
                cvar.udp_ip_length = cvar.udp_ip_length+int(Data['ip.len'])
            except KeyError:
                cvar.udp_ip_length = cvar.udp_ip_length+0
            cvar.udp_length = cvar.udp_length+int(Data['udp.length'])
            get_services(services)
            cvar.udp = cvar.udp+1
            check_ID(ID)
            ports([Data['udp.srcport'], Data['udp.dstport']])

        elif Prot1 == 'arp':
            cvar.arp_frame_length = cvar.arp_frame_length + \
                int(Data['frame.len'])
            cvar.arp = cvar.arp+1
            check_ID(ID)

    else:
        #print("in new time block so aggregating and creating new block: ")
        # save the attributes to a dictionary

        cvar.localdat['tcp_frame_length'] = cvar.tcp_frame_length
        cvar.localdat['tcp_ip_length'] = cvar.tcp_ip_length
        cvar.localdat['tcp_length'] = cvar.tcp_length

        cvar.localdat['udp_frame_length'] = cvar.udp_frame_length
        cvar.localdat['udp_ip_length'] = cvar.udp_ip_length
        cvar.localdat['udp_length'] = cvar.udp_length

        cvar.localdat['arp_frame_length'] = cvar.arp_frame_length

        cvar.localdat['src_length'] = cvar.udp_ip_length
        cvar.localdat['dst_length'] = cvar.udp_length

        cvar.localdat['num_tls'] = cvar.tls
        cvar.localdat['num_http'] = cvar.http
        cvar.localdat['num_ftp'] = cvar.ftp
        cvar.localdat['num_ssh'] = cvar.ssh
        cvar.localdat['num_smtp'] = cvar.smtp
        cvar.localdat['num_dhcp'] = cvar.dhcp
        cvar.localdat['num_dns'] = cvar.dns

        cvar.localdat['num_tcp'] = cvar.tcp
        cvar.localdat['num_udp'] = cvar.udp
        cvar.localdat['num_arp'] = cvar.arp
        cvar.localdat['connection_pairs'] = len(cvar.IDs)
        cvar.localdat['num_ports'] = len(cvar.ports)
        cvar.localdat['num_packets'] = cvar.tot_pack

        # add the ips

        # clear variables for the next time window

        cvar.tcp = 0
        cvar.udp = 0
        cvar.arp = 0

        cvar.tls = 0
        cvar.http = 0
        cvar.ftp = 0
        cvar.ssh = 0
        cvar.dns = 0
        cvar.smtp = 0
        cvar.dhcp = 0

        cvar.IDs = []
        cvar.ports = []
        cvar.tot_pack = 1

        cvar.tcp_frame_length = 0
        cvar.tcp_ip_length = 0
        cvar.tcp_length = 0

        cvar.udp_frame_length = 0
        cvar.udp_ip_length = 0
        cvar.udp_length = 0

        cvar.arp_frame_length = 0

        #print("counts.calculate.calculate: Writing row: ", cvar.out_record_count, "data:", cvar.localdat)
        print("counts.calculate.calculate: Writing row: ", cvar.out_record_count)
        writer.writerow(cvar.localdat)

        cvar.out_record_count = cvar.out_record_count+1

        if Prot1 == 'tcp':
            cvar.tcp_frame_length = cvar.tcp_frame_length + \
                int(Data['frame.len'])
            cvar.tcp_ip_length = cvar.tcp_ip_length+int(Data['ip.len'])
            cvar.tcp_length = cvar.tcp_length+int(Data['tcp.len'])
            cvar.src_length = cvar.src_length+int(Data['tcp.len'])
            get_services(services)
            cvar.tcp = cvar.tcp+1
            check_ID(ID)
            ports([Data['tcp.srcport'], Data['tcp.dstport']])

        elif Prot1 == 'udp':
            cvar.udp_frame_length = cvar.udp_frame_length + \
                int(Data['frame.len'])
            try:
                cvar.udp_ip_length = cvar.udp_ip_length+int(Data['ip.len'])
            except KeyError:
                cvar.udp_ip_length = cvar.udp_ip_length+0
            cvar.udp_length = cvar.udp_length+int(Data['udp.length'])
            get_services(services)
            cvar.udp = cvar.udp+1
            check_ID(ID)
            ports([Data['udp.srcport'], Data['udp.dstport']])

        elif Prot1 == 'arp':
            cvar.arp_frame_length = cvar.arp_frame_length + \
                int(Data['frame.len'])
            cvar.arp = cvar.arp+1
            check_ID(ID)

        cvar.localdat = {}
    #print("set.Dataset: ", set.Dataset)


def get_services(slist):

    if 'tls' in slist:
        cvar.tls = cvar.tls+1
    elif 'http' in slist:
        cvar.http = cvar.http+1
    elif 'ftp' in slist:
        cvar.ftp = cvar.ftp+1
    elif 'ssh' in slist:
        cvar.ssh = cvar.ssh+1
    elif 'dns' in slist:
        cvar.dns = cvar.dns+1
    elif 'smtp' in slist:
        cvar.smtp = cvar.smtp+1
    elif 'dhcp' in slist:
        cvar.dhcp = cvar.dhcp+1


def check_ID(ID):
    if not ID in cvar.IDs:
        cvar.IDs.append(ID)


def ports(port):
    for p in port:

        if not p in cvar.ports:
            cvar.ports.append(p)
