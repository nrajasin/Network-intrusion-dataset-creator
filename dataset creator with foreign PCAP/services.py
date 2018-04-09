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


## check the traffic for different services in the traffic suhc as ssl,http,smtp

class services (threading.Thread):
	def __init__(self, threadID, name):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.name = name
	def run(self):
		service_count=0
		while True:

			if set.servicesQ.empty()==False:
				
				Datalist=set.servicesQ.get()
				global service_count
				service_count=service_count+1
				global serv
				serv =[]
				global ID
				ID=Datalist[0]
				Data=Datalist[1]
				global Prot1
				Prot1=Datalist[2]
				if Prot1=="tcp" or Prot1=="udp" :
									
					ssl(Data)
					http(Data)
					ftp(Data)
					ssh(Data)
					dns(Data)
					smtp(Data)
					dhcp(Data)
					
				if len(serv)>0:
					Datalist.append(serv)
					set.timesQ.put(Datalist)
				else:
					Datalist.append(["no service"])
					set.timesQ.put(Datalist)


	
				
				


# if more services are needed they can be added in the following template

def ssl(Data):
	
	if "ssl.record.content_type" in Data :
		
		serv.append("ssl")
		

def http(Data):
	
	if "http.request.method" in Data :
		
		serv.append("ssl")
		

def ftp(Data):
	
	if "ftp.request" in Data :
		serv.append("ssl")
		

def ssh(Data):
	
	if  'ssh.payload' in Data :
		serv.append("ssl")
	
	
def dns(Data):
	
	if  'dns.flags' in Data :
		serv.append("ssl")

def smtp(Data):
	if 'smtp.response' in Data :
		serv.append("ssl")

def dhcp(Data):
	if 'dhcpv6.msgtype' in Data :
		serv.append("dhcp")