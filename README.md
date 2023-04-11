PRETT/2
=============

PRETT/2 is an automated protocol modeler for HTTP/2 servers.

## Prerequisite (Ubuntu 22)
### Python3
- sudo apt-get install python3-dev python3-pip python-tk graphviz libgraphviz-dev
### Python2
- sudo apt-get install python2-dev python-pip python-tk graphviz libgraphviz-dev
### Common (for python2, use pip2)
- sudo pip3 install scapy
- sudo pip3 install transitions
- sudo pip3 install matplotlib
- sudo pip3 install pygraphviz
- sudo pip3 install sslkeylog

## How To Run

- specify timeout of server both in server configuration and ProtoModel class in statemachine.py.
- run with python interpreter specifying target IP
- ex) sudo python viogram.py 192.168.107.133

