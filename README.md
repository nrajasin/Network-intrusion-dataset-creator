# Customizable Network intrusion dataset creator
This software enables the creation of a network intrusion dataset in CSV format. You can run it on a local server to create
your own dataset or use this to read a PCAP from another source and convert that to CSV format based on the attributes you pick.

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
