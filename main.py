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
import multiprocessing as mp
import logging
import sys
from loggingconfig import load_logging


def main():
    load_logging()
    logger = logging.getLogger(__name__)
    # as of 2022/10 this only works with fork mode with in memory queues
    logger.info(
        "multiprocessing start method: %s out of %s",
        mp.get_start_method(),
        mp.get_all_start_methods(),
    )

    # load the settings
    settings = AppSettings()

    parser = argparse.ArgumentParser(
        description="Create time/count window statistics for tshark pcap stream or file"
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
        "-wt",
        "--windowtime",
        default=settings.time_window,
        help="size of time window in msec [" + str(settings.time_window) + "]",
        action="store",
        type=int,
    )
    parser.add_argument(
        "-wp",
        "--windowpackets",
        default=settings.packet_window,
        help="maximum number of packets in a window ["
        + str(settings.packet_window)
        + "]",
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
    logger.info("main:main Running with: %s", vars(args))

    if args.sourcefile:
        settings.input_file_name = args.sourcefile
    if args.interface:
        settings.interface = args.interface
    if args.howlong:
        settings.how_long = args.howlong
    if args.outfile:
        settings.output_file_name = args.outfile
    if args.windowtime:
        settings.time_window = args.windowtime
    if args.windowpackets:
        settings.packet_window = args.windowpackets
    if args.tshark:
        settings.tshark_program = args.tshark

    if settings.time_window is None and settings.packet_window is None:
        logger.error(
            "Must specifiy either the time window or the packet count window see --help"
        )
        sys.exit(2)

    data_collect = PacketCapture(
        "packet capture packet_dict",
        settings.tshark_program,
        settings.input_file_name,
        settings.interface,
        settings.how_long,
        queues.sharedQ,
    )
    data_c_p = mp.Process(target=data_collect.run)
    data_c_p.start()
    # if not data_c_p:
    #     self.logger.info("tshark may not be installed try 'sudo apt install tshark'")
    #     return

    data_process = PacketAnalyse(
        "packet analyzing thread", queues.sharedQ, queues.serviceQ
    )
    data_p_p = mp.Process(target=data_process.run)
    data_p_p.start()

    services_process = ServiceIdentity(
        "service detecter", queues.serviceQ, queues.timesQ
    )
    services_p_p = mp.Process(target=services_process.run)
    services_p_p.start()

    time_counts = TimesAndCounts(
        "time the packets",
        settings.time_window,
        settings.packet_window,
        settings.output_file_name,
        queues.timesQ,
    )
    time_c_p = mp.Process(target=time_counts.run)
    time_c_p.start()

    data_c_p.join()
    data_p_p.join()
    services_p_p.join()
    time_c_p.join()

    logger.info("Party like its 1999")


if __name__ == "__main__":
    # Required for Mac Python 3.8+
    mp.set_start_method("fork", force=True)
    main()
