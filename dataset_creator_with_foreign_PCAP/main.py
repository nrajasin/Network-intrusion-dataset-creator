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

set.tcp_count=0
set.udp_count=0
set.packet_count=0



## capture packets using wireshark and convert them to python dictionary objects
class packetcap (threading.Thread):
	def __init__(self, threadID, name):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.name = name
	def run(self):
		cmd = "sudo tshark -r path/sample.pcap -V -T json"
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=1, shell=True, universal_newlines=True)
		json_str = ""
		try:
			for line  in p.stdout:
				if line.strip('\n') == '[':
					continue
				if line.strip('\n') in ['  },', ']']:
					if line.strip('\n') in ['  },']:
						json_str += '}'
					json_obj = json.loads(json_str)
					source_filter = json_obj['_source']['layers']
					keyval=source_filter.items()
					set.allkeyval={}
					a=unwrap(keyval,{})
				
					json_str = ""

					send_data(a)

				else:
					json_str += line
				
			send_data("done")
			p.stdout.close()
			p.wait()
		except:
			print('cant read')
			send_data("done")
			p.stdout.close()
			p.wait()
		

## separate out tcp,udp and arp traffic

class packetanalyze (threading.Thread):
	def __init__(self, threadID, name):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.name = name
	def run(self):
		while set.end_of_file==False:
			if set.sharedQ.empty()==False:

				fortcp=set.sharedQ.get()
				
				Data=fortcp
			
				Tcp(Data)


			if set.notTCP.empty()==False:
				
				forudp=set.notTCP.get()
				
				Udp(forudp)


			if set.notUDP.empty()==False:
				forarp=set.notUDP.get()
				Arp(forarp)



## saves each dictionary object into a Queue

def send_data(dictionary):
	
	set.packet_count =set.packet_count+1
	# if set.packet_count < 50000:
		
	set.sharedQ.put(dictionary)




## this function unwraps a multi level JSON object into a python dictionary with key value pairs


def unwrap(keyval,temp):
	
	for key1,value1 in keyval:
		if type(value1)== str :
			
			temp[key1]=value1

			
		else:
			
			unwrap(value1.items(),temp)

					
	return(temp)



datacollect = packetcap (1, 'packet capture data')
datacollect.start()

dataprocess = packetanalyze (2,'packet analyzing thread')
dataprocess.start()

dataservices =  services (3 ,'service analyzing thread')
dataservices.start()



timecounts =  times (4 ,'time the packets')
timecounts.start()



