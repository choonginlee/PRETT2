PRETT/2
=============

PRETT/2 is an automated protocol modeler for HTTP/2 servers.

### Installation on Ubuntu 18.04 LTS
## Python3.8 (HIGHLY recommended)
- sudo apt-get install python3.8 python3.8-dev python3-pip python-tk graphviz libgraphviz-dev libjpeg-dev
- sudo update-alternatives --install /usr/bin/python3 python /usr/bin/python3.8 1
## packages via pip3
- sudo pip3 install scapy 
- sudo pip3 install transitions
- sudo pip3 install cython (for numpy) 
- sudo pip3 install numpy (for matplotlib) 
- sudo pip3 install pybind11 (for matplotlib)
- sudo pip3 install certifi (for matplotlib)
- sudo pip3 install matplotlib 
- sudo pip3 install pygraphviz

### How To Run
- specify timeout of server both in server configuration and ProtoModel class in statemachine.py.
- run with python interpreter specifying target IP
- ex) sudo python viogram.py 192.168.107.133

## Running with python < 3.8
- It is not runnable with python < 3.8 because of keylogging.
- If you want to run in python < 3.8 anyhow, remove sslkeylog-related codes in modeller_h2.py.
# Python2
- sudo apt-get install python python-pip python-tk 
- sudo apt-get install graphviz libgraphviz-dev libjpeg-dev
# pip2
- sudo pip2 install scapy transitions matplotlib pygraphviz sslkeylog
