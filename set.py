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

# counters across all processing
global packet_count
packet_count = 0
global tcp_count
tcp_count = 0
global udp_count
udp_count = 0
global arp_count
arp_count = 0

global sharedQ
sharedQ = Queue()

global notTCPQ
notTCPQ = Queue()

global notUDPQ
notUDPQ = Queue()

global notARPQ
notARPQ = Queue()

global tcp
tcp = {}

global udp
udp = {}

global arp
arp = {}

global servicesQ
servicesQ = Queue()

global timesQ
timesQ = Queue()

global timed
timed = Queue()

# when we started
global first_packet_time
first_packet_time = 0

# sliding window size
global time_window
time_window = 5000  # msec

# when streaming - how long to run in seconds
global howlong
howlong = 120

global interface
interface = "eth0"

# setting this to some value tells capture to read from file
global input_file_name
input_file_name = None

global output_file_name
output_file_name = 'dataset.csv'

global tshark_program
tshark_program = "tshark"

# when reading a file
global end_of_file
end_of_file = False
