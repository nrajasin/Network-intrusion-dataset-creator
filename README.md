# Customizable Network intrusion dataset creator
This software enables the creation of a network intrusion dataset in CSV format. You can run it on a local server to create
your own dataset or use this to read a PCAP from another source and convert that to CSV format based on the attributes you pick.



If you are using this for research purposes please cite our publication listed below. The bibtex is as follows. 


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

### Requirements
You will need Wireshark/Tshark to run this software. Installation would vary depending on your OS.

This software is written in python3 so you will need to install python3. 

```
sudo apt-get update
sudo apt-get install python3.5.2
```

The requirements.txt file includes the python packages needed for the software. 

```
pip3 install -r requirements.txt
```

## Local Dataset creator mode

In this mode you will be running wireshark and capturing packets. These will be used to make your own dataset depending on the options you pick. You can run the dataset creator with default configurations by running

```
python3 main.py

```

### setting a capture time

You can set a time to capture the data. The default is set in the set.py file.

```
62 howlong=60000

```

The time is milliseconds. 

## Foreign PCAP to dataset mode

In this mode you can load an existing PCAP and make a dataset in csv format. You have to give the correct path to the dataset in main.py

```
cmd = "sudo tshark -r /path/filename -V -T json"

```
### Setting time window for each record

The software allows users to define a time window for each record. The deault is set to 5 seconds. This can be adjusted 
in the counts.py file.

```
58 time_window=5000

```
The time is in milliseconds. 

After the Dataset creation finishes, a CSV file will be created in the same folder. 
