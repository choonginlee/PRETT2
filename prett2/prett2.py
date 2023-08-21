#! /usr/bin/env python
import util
import modeller_h2
import os
import sys
import logging
import subprocess
from datetime import datetime


def init():
	print("\n[STEP 1] Initializing...")

	os.system("sudo rm -r __pycache__")
	dt = datetime.now().strftime("%Y%m%d-%H%M%S")
	outdir = "output_%s" % dt
	os.system("sudo mkdir %s" % outdir)
	os.system("sudo mkdir %s/diagram" % outdir)

	# print("[INFO] If you want to capture packet via wireshark, type interface (ex. ens38).")
	# print("[INFO] You can skip capturing by typing \'n\' or \'N\'")
	# ens = input("[Q] Interface? : ")
	# if ens == 'n' or ens == 'N':
	# 	pass
	# else:
	# 	output = subprocess.Popen("sudo wireshark -k -i %s > /dev/null" % ens, shell=True)

	# Setting for logging
	logging.basicConfig(level=logging.DEBUG, filename="%s/ptmsg_log"%outdir, filemode="a+", format="%(asctime)-15s %(levelname)-8s %(message)s")
	f = open('%s/http2_PRE_logging.txt' % outdir, 'w')
	sys.stdout = util.Tee(sys.stdout, f)

	dst_ip = sys.argv[1]
	pcapfile = sys.argv[2]
	os.system("sudo cp %s %s/" % (pcapfile, outdir))

	print("  [+] Initializing done!\n    => pcap : %s, dst_ip : %s" % (pcapfile, dst_ip))
	return dst_ip, pcapfile, outdir

def info():
	print("Run this script with target IP address (python3).")
	print("sudo python3 %s [target IP] [pcap_path]" % sys.argv[0])
	print("Target IP is IP address or URL without https://")
	sys.exit()

if __name__ == "__main__":
	if len(sys.argv) != 3:
		info()

	#### general setting ###
	dst_ip, pcapfile, outdir = init()
	
	### Extract initial state machine ###
	http2_basic_messages = util.h2msg_from_pcap(pcapfile)

	### Construct reverse engineering for HTTP/2
	sm = modeller_h2.modeller_h2(http2_basic_messages, dst_ip, outdir)

else :
	print ("[-] Invalid Input... exit...\n")
	sys.exit()
