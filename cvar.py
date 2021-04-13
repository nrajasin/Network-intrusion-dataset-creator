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

    out_record_count = 1

    tcp_frame_length = 0
    tcp_ip_length = 0
    tcp_length = 0

    udp_frame_length = 0
    udp_ip_length = 0
    udp_length = 0

    arp_frame_length = 0

    src_length = 0

    dst_length = 0

    # TCP / UDP service counts for an individual window
    tls = 0
    http = 0
    ftp = 0
    ssh = 0
    dns = 0
    smtp = 0
    dhcp = 0
    nbns = 0
    smb = 0
    smb2 = 0

    # protocol counts for an individual window
    tcp = 0
    udp = 0
    arp = 0
    igmp = 0

    IDs = []


    ports = []

    tot_pack = 1
