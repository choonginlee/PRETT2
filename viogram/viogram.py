#! /usr/bin/env python
import util
import modeller_h2

import os
import sys
import logging


def init():
	print("\n[STEP 1] Initializing...")

	# Delete previous log and diagram
	os.system("rm -rf ./ptmsg_log")
	# os.system("rm -rf ./diagram/*")
	if not os.path.exists('./diagram'):
		os.makedirs('./diagram')

	# Setting for logging
	logging.basicConfig(level=logging.DEBUG, filename="ptmsg_log", filemode="a+", format="%(asctime)-15s %(levelname)-8s %(message)s")
	f = open('http2_PRE_logging.txt', 'w')
	sys.stdout = util.Tee(sys.stdout, f)

	dst_ip = sys.argv[1]
	pcapfile = './pcapFile/http2_decrypted_http2Out.pcapng'

	print("  [+] Initializing done!\n    => pcap : %s, dst_ip : %s" % (pcapfile, dst_ip))
	return dst_ip, pcapfile

def info():
	print("Run this script with target IP address.")
	print("sudo python2 %s [target IP]" % sys.argv[0])
	print("Target IP is IP address or URL without https://")
	sys.exit()

if __name__ == "__main__":
	if len(sys.argv) != 2:
		info()

	#### general setting ###
	dst_ip, pcapfile = init()
	
	### Extract initial state machine ###
	http2_basic_messages = util.h2msg_from_pcap(pcapfile)

	### Construct reverse engineering for HTTP/2
	sm = modeller_h2.modeller_h2(http2_basic_messages, dst_ip)

	### Convert state machine to CFG

	### Extract violation grammar

	### Validate HTTP/2 model

else :
	print ("[-] Invalid Input... exit...\n")
	sys.exit()
