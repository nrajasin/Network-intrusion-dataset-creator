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
                          'src_length', 'dst_length', 
                          'num_tls', 'num_http', 'num_ftp', 'num_ssh', 'num_smtp', 'num_dhcp', 'num_dns', 
                          'num_nbns', 'num_smb', 'num_smb2',
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
        self.csv_file_path=args[0]

        self.cvar = windowcounts()
        

    def run(self):
        print("counts.times: run()")
        with open(self.csv_file_path, 'w') as csvfile:

            writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
            writer.writeheader()
            csvfile.flush()

            pack_count = 0
            time_window_index = 0
            time_window_stop = 0

            while True:

                if not queues.timesQ.empty():

                    pack_count +=1
                    Datalist = queues.timesQ.get()
                    if not Datalist: 
                        break
                    #print("processing data list: ", Datalist)

                    ID = Datalist[0]
                    Data = Datalist[1]
                    Prot1 = Datalist[2]
                    services = Datalist[3]

                    if pack_count == 1:
                        # claim stop time was 0 which will cause a new window to be built
                        # starting time and current time are the message frame.time_epoch field
                        time_window_index, time_window_stop, self.current_time = self.timecheck(Data, 0, time_window_index)
                        self.cvar.window_end_time = time_window_stop

                    time_window_index, time_window_stop, self.current_time = self.timecheck(Data, time_window_stop, time_window_index)

                    if time_window_index == self.cvar.out_record_count:
                        #print("add to existing time block")
                        self.cvar.tot_pack +=1
                    else: 
                        #print("in new time block so aggregating and creating new block: ")
                        self.writewindow(writer,self.cvar)
                        csvfile.flush()
                        # clear variables for the next time window
                        self.resetwindow(time_window_stop)

                    self.calculate(ID, Data, Prot1, services, time_window_index, time_window_stop, self.cvar)
            # it is possible that we will get this before all messages have flowed through
            print("counts.times.run: End of data. total timed packet_count:"+str(pack_count))
            csvfile.close()


    # calculate the new time offsets
    def timecheck(self, Data, time_window_stop, time_window_index):

        # time in message. this float lh=to the second rh is msec - convert epoch time to msec
        full_time = Data['frame.time_epoch']
        full_time = int(float(full_time)*1000)
        packet_frame_time = full_time
        #print ("packet_frame_time:"+str(packet_frame_time)+" stop:"+str(time_window_stop))

        if packet_frame_time <= time_window_stop:
            # return the same time if still in the window
            pass
        else:
            time_window_index +=1
            time_window_start_ceil = packet_frame_time
            time_window_stop = time_window_start_ceil + self.time_window
            #print("counts.timecheck count:"+str(time_window_index)+" stopTime:"+str(time_window_stop))

        return(time_window_index, time_window_stop, packet_frame_time)


    def calculate(self, ID, Data, Prot1, services, time_window_index, time_window_stop, cvar):

        #print("calculate: ",ID, Prot1, services)
        # Adding or changing attributes

        if Prot1 == 'tcp':
            cvar.tcp_frame_length = cvar.tcp_frame_length + int(Data['frame.len'])
            try: 
                cvar.tcp_ip_length = cvar.tcp_ip_length + int(Data['ip.len'])
            except KeyError:  # does not exist in ipv6
                cvar.tcp_ip_length = cvar.tcp_ip_length + 0
            cvar.tcp_length = cvar.tcp_length + int(Data['tcp.len'])
            self.count_services(services, cvar)
            cvar.tcp +=1
            self.accumulate_IDs(ID,cvar)
            self.accumulate_ports([Data['tcp.srcport'], Data['tcp.dstport']], cvar)

        elif Prot1 == 'udp':
            cvar.udp_frame_length = cvar.udp_frame_length + int(Data['frame.len'])
            try:
                cvar.udp_ip_length = cvar.udp_ip_length + int(Data['ip.len'])
            except KeyError: # does not exist in ipv6
                cvar.udp_ip_length = cvar.udp_ip_length+0
            cvar.udp_length = cvar.udp_length + int(Data['udp.length'])
            self.count_services(services, cvar)
            cvar.udp +=1
            self.accumulate_IDs(ID, cvar)
            self.accumulate_ports([Data['udp.srcport'], Data['udp.dstport']], cvar)

        elif Prot1 == 'arp':
            cvar.arp_frame_length = cvar.arp_frame_length + int(Data['frame.len'])
            cvar.arp +=1
            self.accumulate_IDs(ID, cvar)
        elif Prot1 == 'igmp':
            # TODO become more clever about igmp if needed
            cvar.igmp += 1


    def count_services(self, slist, cvar):

        if 'tls' in slist:
            cvar.tls +=1
        elif 'http' in slist:
            cvar.http +=1
        elif 'ftp' in slist:
            cvar.ftp +=1
        elif 'ssh' in slist:
            cvar.ssh +=1
        elif 'dns' in slist:
            cvar.dns +=1
        elif 'smtp' in slist:
            cvar.smtp +=1
        elif 'dhcp' in slist:
            cvar.dhcp +=1
        elif 'nbns' in slist:
            cvar.nbns +=1
        elif 'smb' in slist:
            cvar.smb +=1
        elif 'smb2' in slist:
            cvar.smb2 +=1


    def accumulate_IDs(self, ID, cvar):
        if not ID in cvar.IDs:
            cvar.IDs.append(ID)


    def accumulate_ports(self, port, cvar):
        for p in port:

            if not p in cvar.ports:
                cvar.ports.append(p)

    # map cvar to a dictonary to bind to the csv writer
    # Write one time window as a row to the CSV file
    def writewindow(self, writer, rowdata):
        print("    counts.times.calculate: Window: ", rowdata.out_record_count, 
                "packetCount:", rowdata.tot_pack, 
                "endTime", datetime.utcfromtimestamp(rowdata.window_end_time/1000))

        csvrowdata = {}
        csvrowdata['tcp_frame_length'] = rowdata.tcp_frame_length
        csvrowdata['tcp_ip_length'] = rowdata.tcp_ip_length
        csvrowdata['tcp_length'] = rowdata.tcp_length

        csvrowdata['udp_frame_length'] = rowdata.udp_frame_length
        csvrowdata['udp_ip_length'] = rowdata.udp_ip_length
        csvrowdata['udp_length'] = rowdata.udp_length

        csvrowdata['arp_frame_length'] = rowdata.arp_frame_length

        csvrowdata['src_length'] = rowdata.udp_ip_length
        csvrowdata['dst_length'] = rowdata.udp_length

        csvrowdata['num_tls'] = rowdata.tls
        csvrowdata['num_http'] = rowdata.http
        csvrowdata['num_ftp'] = rowdata.ftp
        csvrowdata['num_ssh'] = rowdata.ssh
        csvrowdata['num_smtp'] = rowdata.smtp
        csvrowdata['num_dhcp'] = rowdata.dhcp
        csvrowdata['num_dns'] = rowdata.dns
        csvrowdata['num_nbns'] = rowdata.nbns
        csvrowdata['num_smb'] = rowdata.smb
        csvrowdata['num_smb2'] = rowdata.smb2

        csvrowdata['num_tcp'] = rowdata.tcp
        csvrowdata['num_udp'] = rowdata.udp
        csvrowdata['num_arp'] = rowdata.arp
        csvrowdata['num_igmp'] = rowdata.igmp
        csvrowdata['connection_pairs'] = len(rowdata.IDs)
        csvrowdata['num_ports'] = len(rowdata.ports)
        csvrowdata['num_packets'] = rowdata.tot_pack

        csvrowdata['window_end_time'] = rowdata.window_end_time

        writer.writerow(csvrowdata)

    # Reset all the values for this window
    def resetwindow(self, time_window_end):
        self.cvars = windowcounts()
        self.cvar.window_end_time = time_window_end
        self.cvar.out_record_count +=1

