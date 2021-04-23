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

from settings import AppSettings
from detectors import *
from services import *
from counts import *
from capture import *
import argparse
import queues


def main():
    # load the settings
    settings = AppSettings()

    parser = argparse.ArgumentParser(
        description="Create time window statistics for pcap stream or file"
    )
    parser.add_argument(
        "-s",
        "--sourcefile",
        default=settings.input_file_name,
        help="provide a pcap input file name instead of reading live stream",
        action="store",
    )
    parser.add_argument(
        "-i",
        "--interface",
        default=settings.interface,
        help="use an interface.  [" + settings.interface + "]",
        action="store",
    )
    parser.add_argument(
        "-l",
        "--howlong",
        default=settings.how_long,
        help="number of seconds to run live mode. [" + str(settings.how_long) + "]",
        action="store",
        type=int,
    )
    parser.add_argument(
        "-o",
        "--outfile",
        default=settings.output_file_name,
        help="change the name of the output file [" + settings.output_file_name + "]",
        action="store",
    )
    parser.add_argument(
        "-w",
        "--window",
        default=settings.time_window,
        help="time window in msec [" + str(settings.time_window) + "]",
        action="store",
        type=int,
    )
    parser.add_argument(
        "-t",
        "--tshark",
        default=settings.tshark_program,
        help="tshark program [" + settings.tshark_program + "]",
        action="store",
    )
    args = parser.parse_args()
    print("main:main Running with: ", vars(args))

    if args.sourcefile:
        settings.input_file_name = args.sourcefile
    if args.interface:
        settings.interface = args.interface
    if args.howlong:
        settings.how_long = args.howlong
    if args.outfile:
        settings.output_file_name = args.outfile
    if args.window:
        settings.time_window = args.window
    if args.tshark:
        settings.tshark_program = args.tshark

    data_collect = PacketCapture(
        "packet capture packet_dict",
        settings.tshark_program,
        settings.input_file_name,
        settings.interface,
        settings.how_long,
        queues.sharedQ,
    )
    data_c_p = data_collect.start()
    # if not data_c_p:
    #     print("tshark may not be installed try 'sudo apt install tshark'")
    #     return


    data_process = PacketAnalyse(
        "packet analyzing thread", queues.sharedQ, queues.serviceQ
    )
    data_p_p = data_process.start()

    services_process = ServiceIdentity(
        "service detecter", queues.serviceQ, queues.timesQ
    )
    services_p_p = services_process.start()

    time_counts = TimesAndCounts(
        "time the packets",
        settings.time_window,
        settings.output_file_name,
        queues.timesQ,
    )
    time_c_p = time_counts.start()

    # try:
    #     time_c_p.wait
    # except KeyboardInterrupt:
    #     # This does not reliably clean up :-(
    #     # Without cleanup have to do this on dev box pkill -f tshark and pkill -f python3
    #     data_c_p.terminate()
    #     data_p_p.terminate()
    #     services_p_p.terminate()
    #     time_c_p.terminate()


if __name__ == "__main__":
    main()
