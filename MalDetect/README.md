
# MalDetect: A Structure of Encrypted Malware Traffic Detection
This is the original implementation of the MalDetect [1]. MalDetect was programed in C++ language and here are some related instructions.

## Usage
Input:
```
- no arguements
- the training and testing traffic is required and MalDetect captures the traffic packets from network card. By the way, the traffic flows should be pre-processed by [PcapEditor](https://github.com/IsaacLJY/PcapEditor). In additon, we sugguet replaying the traffic with Tcpreplay [2].
```
Output:
```
<ip.src, port.src, ip.dst, port.dst, protocol>, flow_label
```

## Config file
All the settings of MalDetect are passed via the config file. You can find it in "conf" folder. Below are the meanings of each parameters.
Tree:
- maxDepth: maximum depth of a tree
- numRandomTests: number of random tests for each tree
- numProjectionFeatures: number of features for hyperplane tests
- counterThreshold: number of samples to be seen for an online node before splitting 
Forest:
- numTrees: number of trees in the forest
- numEpochs: number of online training epoches
- useSoftVoting: boolean flag for using hard or soft voting
Output:
- verbose: defines the verbosity level
Class:
- num: number of the concerned classes
- label{i}: the str of class i

## Install
The following packages should be firstly installed:
- libpcap: sudo apt-get install libpcap-dev
- libssl: sudo apt-get install libssl-dev
- libgmm++: sudo apt-get install libgmm++-dev

We developed this tool with "Clion", so the configuration file is "CMakeLists.txt", in which you can find the details, such as libraries. In our research, Ubuntu 16.04 was used.

## Reference
[1] 
[2]
