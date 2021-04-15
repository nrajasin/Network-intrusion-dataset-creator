#!/usr/bin/env python3
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

from settings import appsettings
from detectors import *
from services import *
from counts import *
from capture import *
import argparse


def main():
    # load the settings
    settings = appsettings()

    parser = argparse.ArgumentParser(description = "Create time window statistics for pcap stream or file")
    parser.add_argument("-s","--sourcefile", default=settings.input_file_name,  help="provide a pcap input file name instead of reading live stream",action="store")
    parser.add_argument("-i","--interface",  default=settings.interface,        help="use an interface.  ["+ settings.interface +"]",                     action="store")
    parser.add_argument("-l","--howlong",    default=settings.howlong,          help="number of seconds to run live mode. ["+str(settings.howlong)+"]",   action="store", type=int)
    parser.add_argument("-o","--outfile",    default=settings.output_file_name, help="change the name of the output file ["+settings.output_file_name+"]",action="store")
    parser.add_argument("-w","--window",     default=settings.time_window,      help="time window in msec ["+str(settings.time_window)+"]",               action="store", type=int)
    parser.add_argument("-t","--tshark",     default=settings.tshark_program,   help="tshark program ["+settings.tshark_program+"]",                      action="store")
    args = parser.parse_args()
    print("main:main Running with: ", vars(args))
    
    if (args.sourcefile):
        settings.input_file_name=args.sourcefile
    if (args.interface):
        settings.interface = args.interface
    if (args.howlong):
        settings.howlong = args.howlong
    if (args.outfile):
        settings.output_file_name=args.outfile
    if (args.window):
        settings.time_window=args.window
    if (args.tshark):
        settings.tshark_program=args.tshark

    datacollect = packetcapture(1, 'packet capture data',1, settings.tshark_program, settings.input_file_name, settings.interface, settings.howlong)
    datacollect.start()

    dataprocess = packetanalyze(2, 'packet analyzing thread')
    dataprocess.start()

    timecounts = timesandcounts(4, 'time the packets',1, settings.time_window, settings.output_file_name)
    timecounts.start()


if __name__ == "__main__":
    main()
