echo "== Installing all the prerequisite =="
echo "== It takes more than 5 minutes =="

echo "[1/2] Installing ubuntu packages ..."
apt-get install python3.8 python3.8-dev python3-pip python-tk graphviz libgraphviz-dev libjpeg-dev
update-alternatives --install /usr/bin/python3 python /usr/bin/python3.8 1

echo "[2/2] Installing python packages ..."
pip3 install scapy 
pip3 install transitions
pip3 install cython
pip3 install numpy
pip3 install pybind11
pip3 install certifi
pip3 install matplotlib 
pip3 install pygraphviz

echo "== All set! Run with python interpreter specifying target IP =="