PRETT2
=============
PRETT2 is a framework designed to analyze HTTP/2 DoS via automated protocol reverse engineering and stateful fuzzing.  
This project has been published in the proceedings of the 29th European Symposium on Research in Computer Security (ESORICS 2024).  
The [full paper](https://link.springer.com/chapter/10.1007/978-3-031-70890-9_1) can be accessed at Springer.

<details>
  <summary>BibTeX</summary>

```bibtex
@InProceedings{10.1007/978-3-031-70890-9_1,
author="Lee, Choongin
and Jafarov, Isa
and Dietrich, Sven
and Lee, Heejo",
editor="Garcia-Alfaro, Joaquin
and Kozik, Rafa{\l}
and Chora{\'{s}}, Micha{\l}
and Katsikas, Sokratis",
title="PRETT2: Discovering HTTP/2 DoS Vulnerabilities via Protocol Reverse Engineering",
booktitle="Computer Security -- ESORICS 2024",
year="2024",
publisher="Springer Nature Switzerland",
address="Cham",
pages="3--23",
abstract="",
isbn="978-3-031-70890-9"
}
```
</details> 


## Installation (OS: Ubuntu 18.04 LTS)
### 0. Prerequisite: Python3.8
```
$ sudo apt-get install python3.8 python3.8-dev python3-pip python-tk graphviz libgraphviz-dev libjpeg-dev
$ sudo update-alternatives --install /usr/bin/python3 python /usr/bin/python3.8 1
```

### 1-1. Automated script for testbed setup
```
$ sudo sh setup.sh
```
  
### 1-2. Manual instructions for testbed setup
#### To run prett2.py
```
$ sudo pip3 install scapy 
$ sudo pip3 install transitions
$ sudo pip3 install cython (for numpy) 
$ sudo pip3 install numpy (for matplotlib) 
$ sudo pip3 install pybind11 (for matplotlib)
$ sudo pip3 install certifi (for matplotlib)
$ sudo pip3 install matplotlib 
$ sudo pip3 install pygraphviz
```

#### To run http2fuzz.py
```
$ sudo pip3 install networkx
$ sudo pip3 install tqdm
```  

## How To Run
0. Extract pcap file with a target server and a client (Use wireshark and decrypt it with SSLKEYLOGFILE).

1. Specify timeout of the server both in the server configuration and `ProtoModel` class in statemachine.py.

> [!TIP]
> If you used the tool `autoinstall.py` in `server_setting`, it automatically installs a target server with the timeout value set to 5 sec.

2. For the state machine extraction, run `prett2.py` specifying (1) a target server's IP and (2) a pcap file that is extracted between the target server and a client 
```
// Example command
$ sudo python prett2.py 192.168.107.133
```
> [!WARNING]
> It is not runnable with Python < 3.8 because it does not support keylogging properly.

3. Run `http2fuzz.py` specifying (1) a target IP, (2) a pcap file, and (3) a json file of state machine extracted in the previous step.  
```
// Example command
$ sudo python http2fuzz.py 192.168.56.109 ./pcapFile/apache_testset/ap_l_cr_l.pcapng ../output-dirs/output_ap_l_cr_l_20231002-041559/diagram/level_3\(fin\).json
```

## Troubleshoot
### setup.sh > ModuleNotFoundError: No module named *pip._internal*
- Upgrade pip.
```
$ python3 -m pip install --user --upgrade pip
```

### auto_modeling.py > cannot access to remote server?
- On the counterpart (server side), run a command.
```
$ sudo apt-get install openssl-server
```

### auto_modeling.py > sudo: no tty present and no askpass program specified
- Edit the counterpart's (server side) privilege of username.
```
$ sudo visudo
// add one line at the last (oren is username),
+ oren    ALL=(ALL) NOPASSWD: ALL
```
