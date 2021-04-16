# Customizable Network intrusion dataset creator
This software enables the creation of a network intrusion dataset in CSV format. You can run it on a local server to create
your own dataset or use this to read a PCAP from another source and convert that to CSV format based on the attributes you pick.

## Theory
This program accepts a network log, _pcap_, and creates summary statistics using sliding window that moves through the log stream.
The resulting _CSV_ file contains one row of packet_dict for each time segment.

### packet_dict Flow 
| Stage | Python Module  | | Explanation |
| - | - | -  | - |
| Ethernet interface _or_ pcap | Python Module| \| | packet_dict source |
| tshark - interface ingest    |              | \| | converts to one line per packet json-sh format |
|                              | `capture `   | \| | reads from tshark output - massages labels |
| sharedQ                      |              | \| | communication Queue |
|                              | `detectors`  | \| | protocol detectors and protocol statistics |
|                              | `services`   | \| | higher level TCP and UDP service counts |
| timesQ                       |              | \| | communicaton Queue  |
|                              | `counts`     | \| | time windowing and file writer |
| csv file                     |              | \| | feature file for model training |

## Sample CSV output

| tcp_frame_length|tcp_ip_length|tcp_length|udp_frame_length|udp_ip_length|udp_length|arp_frame_length|num_tls|num_http|num_ftp|num_ssh|num_smtp|num_dhcp|num_dns|num_nbns|num_smb|num_smb2|num_pnrp|num_wsdd|num_ssdp|num_tcp|num_udp|num_arp|num_igmp|connection_pairs|num_ports|num_packets|window_end_time |
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
1. Added column that shows when that row ends

# Running this program 

## Prerequisites

1. Running in live capture mode may require *sudo* access.  You will be prompted for a password at execution time
    * The program is currently hard coded to run as sudo.
1. You will need Wireshark/Tshark to run this software. Installation would vary depending on your OS.
    * Ubuntu: `sudo apt install tshark`
1. This software is written in python3 so you will need to install python3. Most updated linux distributes already have it installed.
    ```
    sudo apt-get update
    sudo apt-get install python3.8.5
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

### Notes:
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

## Source Code
* The source tree is formatted with _black_ in _Visual Studio Code_
* The source code is slowly migrating to the pep8 standard https://realpython.com/python-pep8/

## performance
This progam makes use of 4 cores including one for tshark

| Sample  | sample file size | real time |  analyzed packets | time windows | time span |
| ------- | ---------------- | --------- |  ---------------- | ------------ | ---------------- |
| Crylock |   143,446,091 b  | real:1:47 user:6:07 sys:1:22   | 128778 @ 1201/sec  | 121 | 10:04 
| Maze    | 1,045,083,415 b  | real:11:21 user:38:38 sys:8:33 | 770,987 @ 1131/sec | 94 | 7:59

1. Analysis times are linear with the number of packets processed
1. Tested with ransomware samples from unavarra.es some of which may have originated on other sites.

## Corner cases and concerns

1. IPV6 traffic does not have a `ip.len` field.  This means that the `tcp_ip_length` value in the result set only includes ipv4 traffic.
    * This is true for TCP and UDP
1. This application has multiple concurrent threads but does not execute as parallel operations due to limitations in Python and the GIL.
1. NBNS , SMB and SMB2 service counts have not ben vetted. They may be correct or overcount. 
