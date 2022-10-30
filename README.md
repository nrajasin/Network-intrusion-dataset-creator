# Customizable Network intrusion dataset creator
This software enables the creation of a network intrusion dataset in CSV format. You can run it on a local server to create
your own dataset or use this to read a PCAP from another source and convert that to CSV format based on the attributes you pick.

## Theory
This program accepts a network log, _pcap_, and creates summary statistics using sliding window that moves through the log stream.
The resulting _CSV_ file contains one row of packet_dict for each time segment.

![Sliding window](https://1.bp.blogspot.com/-Lm8r_RqO_MI/YHqa7w-ywmI/AAAAAAAAEZU/5d9v4sUa4osfCQl1Z21CcTjqRQCSozgbgCLcBGAsYHQ/s696/Packet-Stream-Windowing.png)

### Major components
This runs as a multi-processing application with 4 python processes plus tshark

| Stage | Python Module  | | Explanation |
| - | - | -  | - |
| Ethernet interface _or_ pcap or pcapng file |                     | \| | data source for packet_dict |
|                                             | _tshark not Python_ | \| | converts to one line per packet json-sh format |
| subprocess pipe                             |                   | \| | communication between tshark and the Python program
|                                             | `PacketCapture`   | \| | reads from tshark output - massages labels |
| sharedQ                                     |                   | \| | communication Queue |
|                                             | `PacketAnalyze`   | \| | protocol detectors and protocol statistics |
| servicesQ                                   |                   | \| | communicaton Queue  |
|                                             | `ServiceIdentity` | \| | higher level TCP and UDP service counts |
| timesQ                                      |                   | \| | communicaton Queue  |
|                                             | `TimesAndCounts`  | \| | time windowing and file writer |
| csv file                                    |                   | \| | feature file for model training |

1. `tshark` captures live data or replays data from a pcap/pcapng file. It each packet as a line of text output in their ek format. I chose it because each record is on a single line so now multi-line json assembly is required. The Python processes launch it and listen to standard out.
1. `PacketCapture` is a python process that reads tshark and then transforms the data to make it more consumable.  It converts the EK to true JSON and massages some of the label styles to json standard.  The final text is pushed into a message queue
1. `PacketAnalyze` accepts the dictionary from the Queue.  It creates a node pair identifier and identifies the protocol and forwards the original data, the id and protocol to the next stage via a Queue.  PacketAnalyze also captures aggregated statistics across the run. Nothing is done with those at this time and they are lost when the program exists.
1. `ServiceIdentity` This module reads and ID, Protocol, packet data structure.  It analyzes the packet to identify the higher-level service type of the message.  Examples include DNS, SMTP, FTP, TLS, HTTP, SMB, SMB2, etc.  The service list is added to the incoming data set and sent to a topic.
1. `TimesAndCounts` manages the time windows and calculates the time bucket/window statistics and writes them to output.  it reads from the inbound topic and aggregates statistics across a set of incoming packets.  The statistics are retained for a single time window and are written to csv file, one record for each time window.

### Tumbling Windows
The program creates a series of adjacent, non-overlapping, windows. Each packet is included in _just one_ window.
Each window starts at the `start_time` until but not including the `start_time + window_width`
* `start_time` >= `packet times` < `start_time + window_width

The `end_time` is the time of the last packet in the window

## Issues

1. A packet can be flagged as more than one services.  Services like SSDP are implemented using HTTP. That service is currently counted as both. This means you can see a HTTP with no TCP
1. IPV6 traffic does not have a `ip.len` field.  This means that the `tcp_ip_length` value in the result set only includes ipv4 traffic.
    * This is true for TCP and UDP
1. Runs as a multi-processing application because Python does not support parallel concurrent threads
    * Was: This application has multiple concurrent threads but does not execute as parallel operations due to limitations in Python and the GIL.
1. NBNS , SMB and SMB2 service counts have not ben vetted. They may be correct or overcount. 

## Sample CSV output

| tcp_frame_length|tcp_ip_length|tcp_length|udp_frame_length|udp_ip_length|udp_length|arp_frame_length|num_tls|num_http|num_ftp|num_ssh|num_smtp|num_dhcp|num_dns|num_nbns|num_smb|num_smb2|num_pnrp|num_wsdd|num_ssdp|num_tcp|num_udp|num_arp|num_igmp|num_connection_pairs|num_ports|num_packets|window_start_time|window_end_time |
| -|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|--|-|-|-|-|-|-|-|
| 0 | 0 | 0 | 2006 | 1084 | 1118 | 210 | 0 | 2 | 0 | 0 | 0 | 0 | 16 | 4 | 0 | 0 | 0 | 0 | 1 | 0 | 22 | 5 | 18 | 8 | 14 | 46 | 14806 | 19806 |
| 0 | 0 | 0 | 3479 | 2699 | 2487 | 0 | 0 | 5 | 0 | 0 | 0 | 0 | 6 | 15 | 2 | 0 | 0 | 0 | 2 | 0 | 28 | 0 | 6 | 4 | 8 | 34 | 19806 | 24806 |
| 0 | 0 | 0 | 16524 | 2781 | 14822 | 0 | 0 | 17 | 0 | 0 | 0 | 3 | 4 | 0 | 1 | 0 | 0 | 6 | 16 | 0 | 33 | 0 | 9 | 5 | 13 | 42 | 24806 | 29806 |
| 0 | 0 | 0 | 9798 | 1810 | 8636 | 84 | 0 | 18 | 0 | 0 | 0 | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 18 | 0 | 23 | 2 | 2 | 5 | 7 | 27 | 29806 | 34806 |
| 0 | 0 | 0 | 16843 | 5915 | 15239 | 420 | 0 | 10 | 0 | 0 | 0 | 0 | 12 | 4 | 0 | 0 | 0 | 6 | 7 | 0 | 36 | 10 | 20 | 10 | 14 | 66 | 34806 | 39806 |
| 0 | 0 | 0 | 14842 | 7344 | 12918 | 168 | 0 | 33 | 0 | 0 | 0 | 1 | 10 | 2 | 0 | 0 | 0 | 0 | 15 | 0 | 46 | 4 | 6 | 8 | 12 | 56 | 39806 | 44806 |
| 0 | 0 | 0 | 8476 | 4324 | 7168 | 0 | 0 | 22 | 0 | 0 | 0 | 0 | 2 | 8 | 0 | 0 | 0 | 0 | 11 | 0 | 32 | 0 | 0 | 4 | 7 | 32 | 44806 | 49806 |
| 0 | 0 | 0 | 5126 | 2956 | 4244 | 0 | 0 | 5 | 0 | 0 | 0 | 0 | 6 | 6 | 2 | 0 | 0 | 2 | 3 | 0 | 23 | 0 | 0 | 4 | 11 | 23 | 49806 | 54806 |
| 0 | 0 | 0 | 2602 | 1535 | 1924 | 210 | 0 | 6 | 0 | 0 | 0 | 1 | 2 | 4 | 4 | 0 | 0 | 0 | 4 | 0 | 17 | 5 | 0 | 6 | 10 | 22 | 54806 | 59806 |
| 0 | 0 | 0 | 4914 | 2800 | 4168 | 84 | 0 | 6 | 0 | 0 | 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2 | 3 | 0 | 19 | 2 | 0 | 5 | 12 | 21 | 59806 | 64806 |
| 6857 | 6615 | 6111 | 18677 | 9873 | 16171 | 504 | 0 | 16 | 0 | 0 | 0 | 7 | 21 | 2 | 4 | 0 | 2 | 4 | 7 | 13 | 59 | 12 | 21 | 16 | 33 | 105 | 64806 | 69806 |
| 6929 | 6747 | 6203 | 34439 | 17134 | 29359 | 420 | 0 | 31 | 0 | 0 | 0 | 5 | 23 | 30 | 2 | 0 | 15 | 6 | 14 | 13 | 120 | 10 | 24 | 15 | 36 | 167 | 69806 | 74806 |
| 29150 | 14857 | 26074 | 15555 | 8969 | 12973 | 0 | 0 | 17 | 0 | 0 | 0 | 0 | 13 | 17 | 4 | 0 | 5 | 2 | 7 | 46 | 63 | 0 | 4 | 11 | 24 | 113 | 74806 | 79806 |

## Attribution
If you are using this for research purposes please cite the publication listed below. The bibtex is as follows. 

```
    @INPROCEEDINGS{Raja1805:INSecS,
        AUTHOR="Nadun Rajasinghe and Jagath Samarabandu and Xianbin Wang",
        TITLE="{INSecS-DCS:} A Highly Customizable Network Intrusion Dataset Creation
        Framework",
        BOOKTITLE="2018 IEEE Canadian Conference on Electrical \& Computer Engineering (CCECE)
        (CCECE 2018)",
        ADDRESS="Quebec City, Canada",
        DAYS=13,
        MONTH=may,
        YEAR=2018,
        KEYWORDS="Network Intrusion Detection; Dataset creation; Security",
        ABSTRACT="One critical challenge in design and operation of network intrusion
        detection systems (IDS) is the limited datasets used for IDS training and
        its impact on the system performance. If the training dataset is not
        updated or lacks necessary attributes, it will affect the performance of
        the IDS. To overcome this challenge, we propose a highly customizable
        software framework capable of generating labeled network intrusion datasets
        on demand. In addition to the capability to customize attributes, it
        accepts two modes of packet_dict input and output. One input method is to collect
        real-time packet_dict by running the software at a chosen network node and the
        other is to get Raw PCAP files from another packet_dict provider. The output can
        be either Raw PCAP with selected attributes per packet or a processed
        dataset with customized attributes related to both individual packet
        features and overall traffic behavior within a time window. The abilities
        of this software are compared with a product which has similar intentions
        and notable novelties and capabilities of the proposed system have been
        noted."
    }
```
You can find the original research paper on [researchgate](https://www.researchgate.net/profile/Nadun-Rajasinghe/project/A-customizable-Network-Intrusion-Detection-dataset-creating-framework/attachment/5aff08f8b53d2f63c3ccae32/AS:627686015766528@1526663416701/download/1570426776.pdf?context=ProjectUpdatesLog) and related papers at [University of Western Ontario](https://ir.lib.uwo.ca/cgi/viewcontent.cgi?article=7681&context=etd)

## Additions to the original project
1. Migrated from print() statements to logging.  Logging levels and formats are configured in `logging_config.yaml`
1. Added IGMP counts
1. Added num_smb, num_smb2, num_pnrp, num_wsdd, num_ssdp
1. Added column that shows when that row ends
1. Eliminated global variables
1. Unified pcap and live tshark into single set of classes
1. Added command line options
1. Added IPv6 to one of the detectors.  Can't remember which one
1. Migrated from multi-threaded to multi-processors to make use of multiple cores.  A way to get around the GIL
1. Added support for count based tumbling window.  Added support for -wt or -wp.
    * Supports either or both time based or count based window boundaries.  
    * The window behavior must be specified as a parameter in order to support one or both window parametrs.

## References
1. Tumbling time windows for network analysis https://www.youtube.com/watch?v=b3MaxbAAdDw
    * http://joe.blog.freemansoft.com/2021/04/network-intrusion-features-via-sliding.html
1. Using Python to implement tumbling time windows for network analysis https://www.youtube.com/watch?v=jKgGh5a5gFA
    * http://joe.blog.freemansoft.com/2021/04/creating-features-in-python-using.html


# Running this program 

## Prerequisites

1. Wireshark/Tshark (`tshark`) is installed, reachable and, on the PATH.. Installation would vary depending on your OS.
    * Ubuntuinstall : `sudo apt install tshark`
1. This software is written in python3 so you will need to install python3. Most updated linux distributes already have it installed. 
Install it the way you wish.  These were my notes.
    ```
    sudo apt-get update
    sudo apt-get install python3.8.5
    sudo update-alternatives --install /usr/bin/python python /usr/bin/python3.6 1
    sudo update-alternatives --install /usr/bin/python python /usr/bin/python3.8 2
    sudo update-alternatives --config python
    ```
    or if you are running anaconda

    ```
    conda update --prefix /home/joe/anaconda3 anaconda
    ```
1. Running in live capture mode may require *sudo* access to access the network in promiscuous mode.  You will be prompted for a password at execution time
    ```
    cmd = "sudo tshark -r /path/filename -V -T json"
    ```
1. The requirements.txt file has been deleted because the current code base does not seem to require any additional libraries. Create a new one if you find you need it and submit a pull request.
    1. Mac Python 3, cpython, requires a yaml install.  `pip3 instal pyyaml`
    1. pypy is slower than cpython as of 2022/10.  If running pypy then you need to instal pyyaml: ` pypy3 -mpip install pyyaml`

## Command line execution
1. You can see the command line options `python3 main.py --help`
    ```
    $ python3 main.py  --help
    usage: main.py [-h] [-s SOURCEFILE] [-i INTERFACE] [-l HOWLONG] [-o OUTFILE] [-wt WINDOWTIME] [-wp WINDOWPACKETS] [-t TSHARK]
    Create time/count window statistics for pcap/pcapng stream or file
    optional arguments:
    -h,            --help                   show this help message and exit
    -s SOURCEFILE, --sourcefile SOURCEFILE  provide a pcap input file name instead of reading live stream
    -i INTERFACE,  --interface INTERFACE    use an interface. [eth0]
    -l HOWLONG,    --howlong HOWLONG        number of seconds to run live mode. [120]
    -o OUTFILE,    --outfile OUTFILE        change the name of the output file [dataset.csv]
    -wt WINDOW,    --windowtime WINDOW      time window in msec [5000]
    -wp COUNT,     --windowpackets COUNT    max packets in window [None]
    -t TSHARK,     --tshark TSHARK          tshark command [tshark]
    ```
1. The system needs to know the windowing parameters. Tumbling Window behavior is specified with either _window time_ or the _window packet_. One **must be specified**.
1. The default behavior is to work off of live tshark output. You can change this by setting the `--sourcefile` on the command line.
    1. In this mode you will be running wireshark and capturing packets. These will be used to make your own dataset depending on the options you pick. 
1. The results are stored in a CSV file `dataset.csv`.  You can override with the `--outfile` command line option
1. You can set the capture time on a live network adapters with `--howlong <time>` option. The default is stored in `set.py:how_long`. The time is seconds. 
1. You can analyze an existing .pcap/.pcapng capture file and make a dataset in csv format. Specify the path to the input pcap/pcapng capture file with `--sourcefile <path>` The default is stored in `input_file_path` in `set.py`
1. You can define a time window for each aggregation record. Specify the time in _msec_ with the `--wt <size>` command line option. TThe default is stored in `settings.py` . The time is in milliseconds. 
1. You can define a packet window, the max number of packets, for each aggregation record.  Use the `-wp <count>` command line option.

## Usage Notes:
*Linux users can set the execute bit on main.py and run the main.py directly without the `python3` part.
```
chmod +x main.py
```

## Sample: Read from pcap file
| Description | Command |
|-|-|
| Use 5000 msec window reading from Razi...pcap file and write output to dataset.csv | `python3 main.py --sourcefile Razi_15012021.pcap -wt 5000` |
| Use 5000 msec window reading from smtp-ssl.pcapng file from https://wiki.wireshark.org/SampleCaptures and write output to dataset.csv | `python3 main.py --sourcefile smtp-ssl.pcapng -wt 5000` |
| Use 100 packet window reading from smtp-ssl.pcapng file from https://wiki.wireshark.org/SampleCaptures and write output to dataset.csv | `python3 main.py --sourcefile smtp-ssl.pcapng -wp 100` |

## Capture internet traffice from `eth0` and writes the output to pcap files with tshark
Try this
```
sudo tshark  -i eth0 -a duration:120 -w /tmp/foo.pcap -F pcap
```

## Zombie processes
You will end up with one zombie python3 process if you `ctrl-c` the command line you ran this under.
Run some version of this:

```
pkill -f tshark
pkill -f python3
```
# performance
This progam makes use of 5 cores, 4 for python Python and one for tshark.  
It maxes out the cores so hyperthreaded cores will not count towards performance.

These tests were run on two different machines
* 16 core xeon v2 2.0/2.5 Ghz from SSD. 
* 8 core Ryzen 5800X 3.8Ghz from NVMe


| Sample  | sample file size | real time                      |  analyzed packets  | time windows | sample period | python | CPU | 
| ------- | ---------------- | -------------------------------|  ----------------  | ------------ | ------------- | ------ | --- |
| Crylock |   143,446,091 B  | real 1:43 user 1:40  sys 0:15  | n/a                | n/a | 10.04 | tshark (only) | 16C Xeon E5 2640 V2 2.2Ghz SATA/SSD |
| Crylock |   143,446,091 B  | real 1:47 user 7:14  sys 2:36  | 128778 @ 1259/sec  | 122 | 10:04 | cpython       | 16C Xeon E5 2640 V2 2.2Ghz SATA/SSD |
| Crylock |   143,446,091 B  | real 1:15 user 5:17  sys 2:07  | 128778 @ 1578/sec  | 122 | 10:04 | cpython       | 20C Xeon E5 2680 V2 2.8Ghz SATA/SSD |
| Crylock |   143,446,091 B  | real 3:07 user 11:39 sys 1:21  | 128778 @ 754/sec   | 122 | 10:04 | pypy 3.6      | 16C Xeon E5 2640 V2 2.2Ghz SATA/SSD |
| Crylock |   143,446,091 B  | real 2:18 user 08:29 sys 0:50  | 128778 @ 1035/sec  | 122 | 10:04 | pypy 3.7      | 20C Xeon E5 2580 V2 2.8 Ghz SATA/SSD |
| Crylock |   143,446,091 B  | real 0:21 user 1:38  sys 0:27  | 128778 @ 6150/sec  | 122 | 10:14 | cypthon       |  8C Ryzen 5800X NVME    |
| Razi    |   767,491,552 B  |                                | 573523 @ 1106/sec  | 112 | 09:21 | cpython       | 16C Xeon E5 2640 V2 2.2Ghz SATA/SSD |
| Razi    |   767,491,552 B  | real 6:07 user 25:31 sys 11:17 | 573523 @ 1562/sec  | 112 | 09:21 | cpython       | 20C Xeon E5 2680 V2 2.8Ghz SATA/SSD |
| Razi    |   767,491,552 B  | real:1:37 user 7:28 sys:2:17   | 573523 @ 5874/sec  | 112 | 09:21 | cypthon       |  8C Ryzen 5800X NVME    |

This benchmark was for 2-queue 3-python process version.  It was a test to see how much impact the queues vs the uplift of having extra processors.  For this test we removed the queue between detectors and services.

| Sample  | sample file size | real time                      |  analyzed packets  | time windows | sample period | python |
| ------- | ---------------- | -------------------------------|  ----------------  | ------------ | ------------- | ------ |
| Crylock |   143,446,091 b  | real:1:47 user:6:07 sys:1:22   | 128778 @ 1201/sec  | 122 | 10:04 | cpython |
| Maze    | 1,045,083,415 b  | real:11:21 user:38:38 sys:8:33 | 770,987 @ 1131/sec | 94  | 7:59  | cpython |

1. Analysis times are linear with the number of packets processed
1. Tested with ransomware samples from unavarra.es some of which may have originated on other sites.
1. Running the 5 process (4 queue) version on quad core machines results in  **degraded** performance by 10%.  This is because we are CPU bound and have more processes that cores.
1. Crylock and Razi retrieved from http://dataset.tlm.unavarra.es/ransomware/

# Windowing behavior
These examples all use the same sample data set available on the wireshark site

## 5 second (5000msec) time window
Purely time based window
```
~/Network-intrusion-dataset-creator$ python3 main.py --sourcefile smtp-ssl.pcapng -wt 5000
1 packetCount: 21 startTime: 11:31:42.005000 endTime: 11:31:42.450000
2 packetCount: 0 startTime: 11:31:47.005000 endTime: 11:31:47.005000
3 packetCount: 0 startTime: 11:31:52.005000 endTime: 11:31:52.005000
4 packetCount: 4 startTime: 11:31:57.005000 endTime: 11:31:58.335000
5 packetCount: 0 startTime: 11:32:02.005000 endTime: 11:32:02.005000
6 packetCount: 0 startTime: 11:32:07.005000 endTime: 11:32:07.005000
7 packetCount: 0 startTime: 11:32:12.005000 endTime: 11:32:12.005000
8 packetCount: 0 startTime: 11:32:17.005000 endTime: 11:32:17.005000
9 packetCount: 0 startTime: 11:32:22.005000 endTime: 11:32:22.005000
10 packetCount: 4 startTime: 11:32:27.005000 endTime: 11:32:29.517000
11 packetCount: 0 startTime: 11:32:32.005000 endTime: 11:32:32.005000
12 packetCount: 9 startTime: 11:32:37.005000 endTime: 11:32:41.025000 
```

## 10 second time window
Purely time based window. The larger (>5000msec) means fewer windows.
```
~/Network-intrusion-dataset-creator$ python3 main.py --sourcefile smtp-ssl.pcapng -wt 10000
1 packetCount: 21 startTime: 11:31:42.005000 endTime: 11:31:42.450000
2 packetCount: 4 startTime: 11:31:52.005000 endTime: 11:31:58.335000
3 packetCount: 0 startTime: 11:32:02.005000 endTime: 11:32:02.005000
4 packetCount: 0 startTime: 11:32:12.005000 endTime: 11:32:12.005000
5 packetCount: 4 startTime: 11:32:22.005000 endTime: 11:32:29.517000
6 packetCount: 9 startTime: 11:32:32.005000 endTime: 11:32:41.025000
```


### 4 packet maximum or 10 seconds (10000msec)
Maximum of 4 packets or 10 seconds whichever is first. The small packet max means more windows. There is one window in the middle that timed out before filling.
```
~/Network-intrusion-dataset-creator$ python3 main.py --sourcefile smtp-ssl.pcapng -wp 4 -wt 10000
1 packetCount: 4 startTime: 11:31:42.005000 endTime: 11:31:42.089000
2 packetCount: 4 startTime: 11:31:42.089000 endTime: 11:31:42.132000
3 packetCount: 4 startTime: 11:31:42.132000 endTime: 11:31:42.212000
4 packetCount: 4 startTime: 11:31:42.212000 endTime: 11:31:42.309000
5 packetCount: 4 startTime: 11:31:42.309000 endTime: 11:31:42.450000
6 packetCount: 1 startTime: 11:31:42.450000 endTime: 11:31:42.450000
7 packetCount: 4 startTime: 11:31:52.450000 endTime: 11:31:58.335000
8 packetCount: 4 startTime: 11:32:29.474000 endTime: 11:32:29.517000
9 packetCount: 4 startTime: 11:32:40.938000 endTime: 11:32:41.025000
10 packetCount: 4 startTime: 11:32:41.025000 endTime: 11:32:41.025000
11 packetCount: 1 startTime: 11:32:41.025000 endTime: 11:32:41.025000
```

### 20 packet maximum or 10 seconds (10000msec)
Maximum of 20 packets or 10 seconds whichever is first. The large packet window size with the small data set results in several empty windows in the middle.
```
~/Network-intrusion-dataset-creator$ python3 main.py --sourcefile smtp-ssl.pcapng -wp 20 -wt 10000
1 packetCount: 20 startTime: 11:31:42.005000 endTime: 11:31:42.450000
2 packetCount: 1 startTime: 11:31:42.450000 endTime: 11:31:42.450000
3 packetCount: 4 startTime: 11:31:52.450000 endTime: 11:31:58.335000
4 packetCount: 0 startTime: 11:32:02.450000 endTime: 11:32:02.450000
5 packetCount: 0 startTime: 11:32:12.450000 endTime: 11:32:12.450000
6 packetCount: 4 startTime: 11:32:22.450000 endTime: 11:32:29.517000
7 packetCount: 9 startTime: 11:32:32.450000 endTime: 11:32:41.025000
```

# Source Code standards
The source tree is formatted with _black_ in _Visual Studio Code_ extension

