# PcapEditor
The tool pro-processes network traffic (in .pcap form) for the training and testing of [MalDetect](https://github.com/IsaacLJY/MalDetect).

## Usage
Input:
```
- -h | --help : display this message.
- -l : assign the current label, this label must be in your configuration file.
- -s : specify the path of source traffic.
- -d : specify destination path for the processed traffic.
- -cp : specify the packet number.
- -cf : specify the flow number.

Tips:
If there is no printing, you should check your input.  
Three functionalities can be acheived:
- use the combination of -l, -s and -d to label the traffic flow.
- use the combination of -s, -d and -cp to partition a traffic file with a certain amount of packets.
- use the combination of -s, -d and -cf to partition a traffic file with a certain amount of flows.
```

## Config file
The label list can be set via the config file. You can find the config file in "conf" folder. The following is an example.
```
label list:  
Adw  
Drp  
Trj  
Rtk  
Susp  
Legitimate
```

## Install
Libpcap package should be installed addtionnally.
- sudo apt-get install libpcap-dev
We developed this tool with "Clion", so the configuration file is "CMakeLists.txt", in which you can find the details, such as libraries. In this project, Ubuntu 16.04 was used.
