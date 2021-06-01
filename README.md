# Customizable Network intrusion dataset creator
This software enables the creation of a network intrusion dataset in CSV format. You can run it on a local server to create
your own dataset or use this to read a PCAP from another source and convert that to CSV format based on the attributes you pick.

## Theory
This program accepts a network log, _pcap_, and creates summary statistics using sliding window that moves through the log stream.
The resulting _CSV_ file contains one row of packet_dict for each time segment.

![Sliding window](https://1.bp.blogspot.com/-Lm8r_RqO_MI/YHqa7w-ywmI/AAAAAAAAEZU/5d9v4sUa4osfCQl1Z21CcTjqRQCSozgbgCLcBGAsYHQ/s696/Packet-Stream-Windowing.png)

### major components
This runs as a multi-processing application with 4 python processes plus tshark

| Stage | Python Module  | | Explanation |
| - | - | -  | - |
| Ethernet interface _or_ pcap |                     | \| | data source for packet_dict |
|                              | _tshark not Python_ | \| | converts to one line per packet json-sh format |
| subprocess pipe              |                   | \| | communication between tshark and the Python program
|                              | `PacketCapture`   | \| | reads from tshark output - massages labels |
| sharedQ                      |                   | \| | communication Queue |
|                              | `PacketAnalyze`   | \| | protocol detectors and protocol statistics |
| servicesQ                    |                   | \| | communicaton Queue  |
|                              | `ServiceIdentity` | \| | higher level TCP and UDP service counts |
| timesQ                       |                   | \| | communicaton Queue  |
|                              | `TimesAndCounts`  | \| | time windowing and file writer |
| csv file                     |                   | \| | feature file for model training |

1. `tshark` captures live data or replays data from a pcap file. It each packet as a line of text output in their ek format. I chose it because each record is on a single line so now multi-line json assembly is required. The Python processes launch it and listen to standard out.
1. `PacketCapture` is a python process that reads tshark and then transforms the data to make it more consumable.  It converts the EK to true JSON and massages some of the label styles to json standard.  The final text is pushed into a message queue
1. `PacketAnalyze` accepts the dictionary from the Queue.  It creates a node pair identifier and identifies the protocol and forwards the original data, the id and protocol to the next stage via a Queue.  PacketAnalyze also captures aggregated statistics across the run. Nothing is done with those at this time and they are lost when the program exists.
1. `ServiceIdentity` This module reads and ID, Protocol, packet data structure.  It analyzes the packet to identify the higher-level service type of the message.  Examples include DNS, SMTP, FTP, TLS, HTTP, SMB, SMB2, etc.  The service list is added to the incoming data set and sent to a topic.
1. `TimesAndCounts` manages the time windows and calculates the time bucket/window statistics and writes them to output.  it reads from the inbound topic and aggregates statistics across a set of incoming packets.  The statistics are retained for a single time window and are written to csv file, one record for each time window.

## Corner cases and issues

1. A packet can be flagged as more than one services.  Services like SSDP are implemented using HTTP. That service is currently counted as both. This means you can see a HTTP with no TCP
1. IPV6 traffic does not have a `ip.len` field.  This means that the `tcp_ip_length` value in the result set only includes ipv4 traffic.
    * This is true for TCP and UDP
1. This application has multiple concurrent threads but does not execute as parallel operations due to limitations in Python and the GIL.
1. NBNS , SMB and SMB2 service counts have not ben vetted. They may be correct or overcount. 

## Sample CSV output

| tcp_frame_length|tcp_ip_length|tcp_length|udp_frame_length|udp_ip_length|udp_length|arp_frame_length|num_tls|num_http|num_ftp|num_ssh|num_smtp|num_dhcp|num_dns|num_nbns|num_smb|num_smb2|num_pnrp|num_wsdd|num_ssdp|num_tcp|num_udp|num_arp|num_igmp|num_connection_pairs|num_ports|num_packets|window_end_time |
| -|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|--|-|-|-|-|-|- |
| 0|0|0|2006|1084|1118|210|0|2|0|0|0|0|16|4|0|0|0|0|0|0|22|5|18|8|14|46|14806 |
| 0|0|0|3479|2699|2487|0|0|5|0|0|0|0|6|15|2|0|0|0|0|0|28|0|6|4|8|34|19806 | 
| 0|0|0|16524|2781|14822|0|0|17|0|0|0|3|4|0|1|0|0|6|0|0|33|0|9|5|13|42|24806 |
| 0|0|0|9798|1810|8636|84|0|18|0|0|0|5|0|0|0|0|0|0|0|0|23|2|2|5|7|27|29806 | 
| 0|0|0|16843|5915|15239|420|0|10|0|0|0|0|12|4|0|0|0|6|0|0|36|10|20|10|14|66|34806 | 
| 0|0|0|14842|7344|12918|168|0|33|0|0|0|1|10|2|0|0|0|0|0|0|46|4|6|8|12|56|39806 | 
| 0|0|0|8476|4324|7168|0|0|22|0|0|0|0|2|8|0|0|0|0|0|0|32|0|0|4|7|32|44806 | 
| 0|0|0|5126|2956|4244|0|0|5|0|0|0|0|6|6|2|0|0|2|0|0|23|0|0|4|11|23|49806 | 
| 0|0|0|2602|1535|1924|210|0|6|0|0|0|1|2|4|4|0|0|0|0|0|17|5|0|6|10|22|54806 | 
| 0|0|0|4914|2800|4168|84|0|6|0|0|0|0|3|3|3|0|0|2|0|0|19|2|0|5|12|21|59806 | 
| 6857|6615|6111|18677|9873|16171|504|0|16|0|0|0|7|21|2|4|0|2|4|0|13|59|12|21|16|33|105|64806 |
| 6929|6747|6203|34439|17134|29359|420|0|31|0|0|0|5|23|30|2|0|15|6|0|13|120|10|24|15|36|167|69806 | 
| 29150|14857|26074|15555|8969|12973|0|0|17|0|0|0|0|13|17|4|0|5|2|0|46|63|0|4|11|24|113|74806 | 

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
You can find the original research paper on [researchgate](https://www.researchgate.net/profile/Nadun-Rajasinghe/project/A-customizable-Network-Intrusion-Detection-dataset-creating-framework/attachment/5aff08f8b53d2f63c3ccae32/AS:627686015766528@1526663416701/download/1570426776.pdf?context=ProjectUpdatesLog)

## Additions to the original project
1. Added IGMP counts
1. Added num_smb, num_smb2, num_pnrp, num_wsdd, num_ssdp
1. Added column that shows when that row ends
1. Eliminated global variables
1. Unified pcap and live tshark into single set of classes
1. Added command line options
1. Added IPv6 to one of the detectors.  Can't remember which one
1. Migrated from multi-threaded to multi-processors to make use of multiple cores.  A way to get around the GIL

## References
1. Sliding time windows for network analysis https://www.youtube.com/watch?v=b3MaxbAAdDw
    * http://joe.blog.freemansoft.com/2021/04/network-intrusion-features-via-sliding.html
1. Using Python to implement sliding time windows for network analysis https://www.youtube.com/watch?v=jKgGh5a5gFA
    * http://joe.blog.freemansoft.com/2021/04/creating-features-in-python-using.html


# Running this program 

## Prerequisites

1. Running in live capture mode may require *sudo* access.  You will be prompted for a password at execution time
    * The program is currently hard coded to run as sudo.
1. You will need Wireshark/Tshark to run this software. Installation would vary depending on your OS.
    * Ubuntu: `sudo apt install tshark`
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
    
1. The requirements.txt file has been deleted because the current code base does not seem to require any additional libraries. Create a new one if you find you need it and submit a pull request.
1. `tshark` is installed, reachable and, on the PATH.  This python program for tshar with somehting like:
    ```
    cmd = "sudo tshark -r /path/filename -V -T json"
    ```

## Command line execution
1. You can see the command line options `python3 main.py --help`
    ```
    $ python3 main.py  --help
    usage: main.py [-h] [-s SOURCEFILE] [-i INTERFACE] [-l how_long] [-o OUTFILE] [-w WINDOW]
    Create time window statistics for pcap stream or file
    optional arguments:
    -h,            --help                   show this help message and exit
    -s SOURCEFILE, --sourcefile SOURCEFILE  provide a pcap input file name instead of reading live stream
    -i INTERFACE,  --interface INTERFACE    use an interface. [eth0]
    -l HOWLONG,    --howlong HOWLONG       number of seconds to run live mode. [120]
    -o OUTFILE,    --outfile OUTFILE        change the name of the output file [dataset.csv]
    -w WINDOW,     --window WINDOW          time window in msec [5000]
    -t TSHARK,     --tshark TSHARK          tshark command [tshark]
    ```
1. The default behavior is to work off of live tshark output. You can change this by setting the `--sourcefile` on the command line.
    1. In this mode you will be running wireshark and capturing packets. These will be used to make your own dataset depending on the options you pick. 
1. The results are stored in a CSV file.  You can override with the `--outfile` command line option
1. You can set a time to capture the packet_dict with the `--howlong <time>` option. The default is stored in `set.py:how_long`. The time is seconds. 
1. In this mode you can load an existing PCAP and make a dataset in csv format. Specify the path to the input pcap with `--sourcefile <path>` The default is stored in `input_file_path` in `set.py`
1. The software allows users to define a time window for each aggregation record. Specify the time in _msec_ with the `--window <size>` offering.. TThe default is stored in  `set.py` . The time is in milliseconds. 

## Usage Notes:
* Linux users can set the execute bit on main.py and run the main.py directly without the `python3` part.
    ```
    chmod +x main.py
    ```

### Sample reading from file
reads from a pcap and writes to dataset.csv

`python3 main.py --sourcefile Razi_15012021.pcap`

    
### Capturing pcap files with tshark
Try this
```
sudo tshark  -i eth0 -a duration:120 -w /tmp/foo.pcap -F pcap
```

# Source Code
* The source tree is formatted with _black_ in _Visual Studio Code_

# performance
This progam makes use of 5 cores, 4 for python Python and one for tshark

These tests were run on a slightly slower higher core, 16 core xeon 2.2Ghz from SSD. 
Note that their performance is about the same as the 4 core run where we merged detectors and services to have fewer processes

| Sample  | sample file size | real time                      |  analyzed packets  | time windows | sample period | python | 
| ------- | ---------------- | -------------------------------|  ----------------  | ------------ | ------------- | ------ |
| Crylock |   143,446,091 B  | real:1:43 user:1:40 sys:0:15   | n/a                | n/a | 10.04 | tshark (only) |
| Crylock |   143,446,091 B  | real:1:47 user:7:14 sys:2:36   | 128778 @ 1259/sec  | 121 | 10:04 | cpython | 
| Crylock |   143,446,091 B  | real:3:07 user 11:39 sys:1:21  | 128778 @ 754/sec   | 121 | 10:04 | pypy    | 
| Maze    |   767,491,552 B  |                                | 573523 @ 1106/sec  | 111 | 09:21 | cpython |

This benchmark was for 2 queue 3 python process version **prior** to adding a back the queue between detectors and services.
Adding that topic **degraded** performance by 10% on a quad core because it added a 5th process.

| Sample  | sample file size | real time                      |  analyzed packets  | time windows | sample period | python |
| ------- | ---------------- | -------------------------------|  ----------------  | ------------ | ------------- | ------ |
| Crylock |   143,446,091 b  | real:1:47 user:6:07 sys:1:22   | 128778 @ 1201/sec  | 121 | 10:04 | cpython |
| Maze    | 1,045,083,415 b  | real:11:21 user:38:38 sys:8:33 | 770,987 @ 1131/sec | 94  | 7:59  | cpython |

1. Analysis times are linear with the number of packets processed
1. Tested with ransomware samples from unavarra.es some of which may have originated on other sites.

# Random notes
## Zombie processes
You will end up with one zombie python3 process if you `ctrl-c` the command line you ran this under.
Run some version of this:

```
pkill -f tshark
pkill -f python3
```
