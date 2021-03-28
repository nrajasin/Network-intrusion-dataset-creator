# Customizable Network intrusion dataset creator
This software enables the creation of a network intrusion dataset in CSV format. You can run it on a local server to create
your own dataset or use this to read a PCAP from another source and convert that to CSV format based on the attributes you pick.

## Theory
This program accepts a network log, _pcap_, and creates summary statistics using sliding window that moves through the log stream.
The resulting _CSV_ file contains one row of data for each time segment.

## Sample CSV output

| tcp_frame_length | tcp_ip_length | tcp_length | udp_frame_length | udp_ip_length | udp_length | arp_frame_length | src_length | dst_length | num_tls | num_http | num_ftp | num_ssh | num_smtp | num_dhcp | num_dns | num_tcp | num_udp | num_arp | connection_pairs | num_ports | num_packets |
| - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| 1268 | 1002 | 242 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 19 | 0 | 0 | 1 | 3 | 19 |
| 1461 | 1167 | 327 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 21 | 0 | 0 | 1 | 3 | 21 |
| 15313 | 14039 | 10399 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 91 | 0 | 0 | 1 | 3 | 91 |
| 30285 | 28115 | 21851 | 1442 | 1330 | 1170 | 0 | 1330 | 1170 | 14 | 0 | 0 | 0 | 0 | 0 | 8 | 155 | 8 | 0 | 2 | 9 | 163 |
| 11836 | 11164 | 9244 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 48 | 0 | 0 | 1 | 3 | 48 |
| 11753 | 11095 | 9215 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 47 | 0 | 0 | 1 | 3 | 47 |
| 17770 | 15852 | 10372 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 137 | 0 | 0 | 1 | 3 | 137 |
| 37760 | 35688 | 29608 | 368 | 312 | 232 | 0 | 312 | 232 | 0 | 1 | 0 | 0 | 0 | 0 | 4 | 148 | 4 | 0 | 2 | 7 | 152 |
| 39743 | 37111 | 29251 | 368 | 312 | 232 | 0 | 312 | 232 | 3 | 0 | 0 | 0 | 0 | 0 | 4 | 188 | 4 | 0 | 2 | 7 | 192 |
| 11286 | 10726 | 9126 | 215 | 201 | 181 | 0 | 201 | 181 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 40 | 1 | 0 | 2 | 5 | 41 |
| 13563 | 12499 | 9459 | 645 | 603 | 543 | 0 | 603 | 543 | 0 | 3 | 0 | 0 | 0 | 0 | 0 | 76 | 3 | 0 | 2 | 5 | 79 |
| 13002 | 12092 | 9492 | 345 | 289 | 209 | 0 | 289 | 209 | 0 | 0 | 0 | 0 | 0 | 0 | 4 | 65 | 4 | 0 | 1 | 5 | 69 |
| 11314 | 10740 | 9100 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 41 | 0 | 0 | 1 | 3 | 41 |
| 11195 | 10649 | 9089 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 39 | 0 | 0 | 1 | 3 | 39 |
| 11192 | 10646 | 9086 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 39 | 0 | 0 | 1 | 3 | 39 |
| 11144 | 10612 | 9092 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 38 | 0 | 0 | 1 | 3 | 38 |
| 11422 | 10834 | 9154 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 42 | 0 | 0 | 1 | 3 | 42 |
| 37736 | 33144 | 20024 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 328 | 0 | 0 | 1 | 3 | 328 |
| 11267 | 10735 | 9215 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 38 | 0 | 0 | 1 | 3 | 38 |
| 11200 | 10654 | 9094 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 39 | 0 | 0 | 1 | 3 | 39 |
| 11197 | 10651 | 9091 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 39 | 0 | 0 | 1 | 3 | 39 |

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

# Running this program 

## Prerequisites

1. Running in live capture mode may require *sudo* access.  You will be prompted for a password at execution time
    * The program is currently hard coded to run as sudo.
1. You will need Wireshark/Tshark to run this software. Installation would vary depending on your OS.
    * Ubuntu: `sudo apt install tshark`
1. This software is written in python3 so you will need to install python3. 
    ```
    sudo apt-get update
    sudo apt-get install python3.5.2
    ```
1. The requirements.txt file has been deleted because it was a hot mess after two 3 years of bit rot. the requirements.txt file was obsolete and full of versions with CVEs. Create a new one if you find you need it and submit a pull request.
    ```
    IGNORE THIS LINE --> pip3 install -r requirements.txt
    ```
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

### Capturing pcap files
Try this
```
sudo tshark  -i eth0 -a duration:120 -w /tmp/foo.pcap -F pcap
```
