# Customizable Network intrusion dataset creator
This software enables the creation of a network intrusion dataset in CSV format. You can run it on a local server to create
your own dataset or use this to read a PCAP from another source and convert that to CSV format based on the attributes you pick.

## Theory
This program accepts a network log, _pcap_, and creates summary statistics using sliding window that moves through the log stream.
The resulting _CSV_ file contains one row of data for each time segment.

## Sample CSV output

| tcp_frame_length | tcp_ip_length | tcp_length | udp_frame_length | udp_ip_length | udp_length | arp_frame_length | src_length | dst_length | num_tls | num_http | num_ftp | num_ssh | num_smtp | num_dhcp | num_dns |  num_tcp | num_udp | num_arp | num_igmp | connection_pairs | num_ports | num_packets | window_end_time |
| - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| 0 | 0 | 0 | 1029 | 875 | 655 | 0 | 875 | 655 | 0 | 0 | 0 | 0 | 0 | 0 | 11 | 0 | 11 | 0 | 0 | 2 | 10 | 11 | 1573510808578 |
| 0 | 0 | 0 | 6049 | 5475 | 4655 | 0 | 5475 | 4655 | 0 | 0 | 0 | 0 | 0 | 0 | 39 | 0 | 41 | 0 | 0 | 7 | 19 | 41 | 1573510813698 |
| 0 | 0 | 0 | 3909 | 3629 | 3229 | 0 | 3629 | 3229 | 0 | 0 | 0 | 0 | 0 | 0 | 19 | 0 | 20 | 0 | 0 | 7 | 12 | 20 | 1573510818748 |
| 32231 | 30504 | 25544 | 7365 | 6791 | 5971 | 0 | 6791 | 5971 | 0 | 0 | 0 | 0 | 0 | 0 | 24 | 118 | 41 | 0 | 2 | 6 | 29 | 161 | 1573510824230 |
| 63847 | 61047 | 52339 | 7187 | 6669 | 5929 | 0 | 6669 | 5929 | 7 | 0 | 0 | 0 | 0 | 0 | 29 | 194 | 37 | 0 | 0 | 10 | 34 | 231 | 1573510829288 |
| 34814 | 32988 | 27128 | 1537 | 1411 | 1231 | 0 | 1411 | 1231 | 25 | 0 | 0 | 0 | 0 | 0 | 9 | 126 | 9 | 0 | 0 | 9 | 21 | 135 | 1573510834299 |
| 1120 | 976 | 576 | 4477 | 3735 | 2675 | 0 | 3735 | 2675 | 0 | 0 | 0 | 0 | 0 | 0 | 39 | 10 | 53 | 0 | 8 | 6 | 27 | 71 | 1573510839945 |
| 8435 | 7955 | 6719 | 4120 | 3448 | 2488 | 0 | 3448 | 2488 | 10 | 0 | 0 | 0 | 0 | 0 | 44 | 30 | 48 | 0 | 0 | 11 | 28 | 78 | 1573510845166 | 
| 386 | 280 | 0 | 8494 | 7304 | 5604 | 0 | 7304 | 5604 | 0 | 0 | 0 | 0 | 0 | 0 | 85 | 7 | 85 | 0 | 10 | 17 | 53 | 102 | 1573510850251 | 
| 0 | 0 | 0 | 7108 | 6086 | 4626 | 0 | 6086 | 4626 | 0 | 0 | 0 | 0 | 0 | 0 | 71 | 0 | 73 | 0 | 0 | 11 | 38 | 73 | 1573510855679 |
| 42930 | 40900 | 35484 | 2960 | 2456 | 1736 | 0 | 2456 | 1736 | 44 | 0 | 0 | 0 | 0 | 0 | 34 | 130 | 36 | 0 | 1 | 14 | 31 | 167 | 1573510860749 |

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
        accepts two modes of data input and output. One input method is to collect
        real-time data by running the software at a chosen network node and the
        other is to get Raw PCAP files from another data provider. The output can
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
    usage: main.py [-h] [-s SOURCEFILE] [-i INTERFACE] [-l HOWLONG] [-o OUTFILE] [-w WINDOW]
    Create time window statistics for pcap stream or file
    optional arguments:
    -h,            --help                   show this help message and exit
    -s SOURCEFILE, --sourcefile SOURCEFILE  provide a pcap input file name instead of reading live stream
    -i INTERFACE,  --interface INTERFACE    use an interface. [eth0]
    -l HOWLONG,    --howlong HOWLONG        number of seconds to run live mode. [120]
    -o OUTFILE,    --outfile OUTFILE        change the name of the output file [dataset.csv]
    -w WINDOW,     --window WINDOW          time window in msec [5000]
    -t TSHARK,     --tshark TSHARK          tshark command [tshark]
    ```
1. The default behavior is to work off of live tshark output. You can change this by setting the `--sourcefile` on the command line.
    1. In this mode you will be running wireshark and capturing packets. These will be used to make your own dataset depending on the options you pick. 
1. The results are stored in a CSV file.  You can override with the `--outfile` command line option
1. You can set a time to capture the data with the `--howlong <time>` option. The default is stored in `howlong` in `set.py` file. The time is seconds. 
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

## Corner cases

1. IPV6 traffic does not have a `ip.len` field.  This means that the `tcp_ip_length` value in the result set only includes ipv4 traffic.
    * This is true for TCP and UDP
1. When testing with a file, my sample froze eating one full core at 83 frames.  Ignore the number but know the app gets slower and slower probably because it keeps adding data to the globsl vars.
    * test with ransomware samples from unavarra.es which came from other sites.
