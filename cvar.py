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

# cvars should only be used from counts.py

class windowcounts():

    window_end_time = 0

    out_window_index = 1

    # frame.len
    tcp_frame_length = 0
    # ip.len
    tcp_ip_length = 0
    # tcp.len
    tcp_length = 0

    # frame.len
    udp_frame_length = 0
    # ip.len
    udp_ip_length = 0
    # udp.length
    udp_length = 0

    # frame.len
    arp_frame_length = 0

    # TCP / UDP service counts for an individual window
    num_tls = 0
    num_http = 0
    num_ftp = 0
    num_ssh = 0
    num_dns = 0
    num_smtp = 0
    num_dhcp = 0
    num_nbns = 0
    num_smb = 0
    num_smb2 = 0
    num_pnrp = 0

    # derived from broadcast address and port
    num_wsdd = 0
    # derived from broadcast address and port
    num_ssdp = 0

    # protocol counts for an individual window
    num_tcp = 0
    num_udp = 0
    num_arp = 0
    num_igmp = 0

    # all the calculated src/dst combinations
    IDs = set()
    # all the ports in this window
    ports = set()

    num_packets = 1

    # The class "constructor" - It's actually an initializer
    # Not sure why but non primitives must be initialized
    def __init__(self, time_window_end=0, out_window_index=1):
        self.num_packets = 1
        self.IDs = set()
        self.ports = set()
        self.window_end_time = time_window_end
        self.out_window_index = out_window_index
