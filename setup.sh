echo "== Installing all the prerequisite... It may take some minutes. =="

echo "[1/3] Installing ubuntu packages ..."
apt-get install python3.8 python3.8-dev python3-pip python-tk graphviz libgraphviz-dev libjpeg-dev
update-alternatives --install /usr/bin/python3 python /usr/bin/python3.8 1

echo "[2/3] Installing python packages for SM extraction ..."
pip3 install scapy 
pip3 install transitions
pip3 install cython
pip3 install numpy
pip3 install pybind11
pip3 install certifi
pip3 install matplotlib 
pip3 install pygraphviz

echo "[3/3] Installing python packages for SM extraction ..."
pip3 install networkx 
pip3 install tqdm

echo "== All set! Run with python interpreter specifying target IP =="