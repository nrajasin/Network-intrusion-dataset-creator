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



from queue import *
import set

global packet_count
packet_count=0
global tcp_count
tcp_count=0
global udp_count
udp_count=0
global arp_count
arp_count=0

global allkeyval
allkeyval={}

global sharedQ
sharedQ=Queue()

global notTCP
notTCP=Queue() 

global notUDP
notUDP=Queue() 

global notARP
notARP=Queue() 

global tcp
tcp={}

global tcpQ
tcpQ=Queue()

global udp
udp={}

global udpQ
udpQ=Queue()

global arp
arp={}

global arpQ
arpQ=Queue()

global servicesQ
servicesQ=Queue()

global timesQ
timesQ=Queue()

global timed
timed=Queue()

global Dataset
Dataset={}

global starting
starting=0

global howlong
howlong=60000