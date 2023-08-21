from states import *
import statemachine as stma
import json
import util
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.compat import raw, plain_str, hex_bytes, orb, chb, bytes_encode
import scapy.supersocket as supersocket
import scapy.contrib.http2 as h2
import time
import sys
import ssl
import socket
import os
logger = logging.getLogger(__name__)
import traceback

ssl_ctx = None

def modeller_h2(http2_basic_messages, dst_ip, outdir):
	global ssl_ctx
	
	ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
	# ssl_ctx.keylog_filename = "%s/sslkey_scapy.txt" % outdir
	ssl_ctx.keylog_filename = "./sslkey_scapy.txt"

	# Building the SSL context
	ssl_ctx.set_ciphers(':'.join([  # List from ANSSI TLS guide v.1.1 p.51
					'ECDHE-ECDSA-AES256-GCM-SHA384',
					'ECDHE-RSA-AES256-GCM-SHA384',
					'ECDHE-ECDSA-AES128-GCM-SHA256',
					'ECDHE-RSA-AES128-GCM-SHA256',
					'ECDHE-ECDSA-AES256-SHA384',
					'ECDHE-RSA-AES256-SHA384',
					'ECDHE-ECDSA-AES128-SHA256',
					'ECDHE-RSA-AES128-SHA256',
					'ECDHE-ECDSA-CAMELLIA256-SHA384',
					'ECDHE-RSA-CAMELLIA256-SHA384',
					'ECDHE-ECDSA-CAMELLIA128-SHA256',
					'ECDHE-RSA-CAMELLIA128-SHA256',
					'DHE-RSA-AES256-GCM-SHA384',
					'DHE-RSA-AES128-GCM-SHA256',
					'DHE-RSA-AES256-SHA256',
					'DHE-RSA-AES128-SHA256',
					'AES256-GCM-SHA384',
					'AES128-GCM-SHA256',
					'AES256-SHA256',
					'AES128-SHA256',
					'CAMELLIA128-SHA256'
				]))     
	ssl_ctx.set_alpn_protocols(['h2'])  # h2 is a RFC7540-hardcoded value

	g_start_time = time.time()
	print("\n[STEP 3] Modeling started at %s" % time.ctime(g_start_time))
	# pm is for modeling status, 
	# sm is for state machine data structure using Machines package 
	pm, sm = stma.generate_sm()
	pm.testmsgs = http2_basic_messages
	pm.dst_ip = dst_ip

	while True: # for each level
		print("  [+] --- Starting level %d ---" % (pm.current_level))
		logger.info("  [+] --- Starting level %d ---" % (pm.current_level))

		### Expanding ###
		print("  [+] State expansion start in level %d. (%s)" % (pm.current_level, time.ctime(time.time())))
		logger.info("  [+]  State expansion start in level %d. (%s)" % (pm.current_level, time.ctime(time.time())))
		pm.is_pruning = False
		# Retrieve valid states of previous level (unique states in prev. level so far) (for level 1, it is the initial state '0')
		leaf_states = pm.state_list.get_states_by_level(pm.current_level)
		stma.expand_sm(pm, sm, leaf_states)
		print("  [+] State expansion end in level %d. (%s)" % (pm.current_level, time.ctime(time.time())))
		logger.info("  [+] State expansion end in level %d. (%s)" % (pm.current_level, time.ctime(time.time())))

		pm.state_list.print_state_list()
		pm.candidate_state_list.print_state_list()

		### Pruning ###
		print("  [+] State minimization start in level %d. (%s)" % (pm.current_level, time.ctime(time.time())))
		logger.info("  [+] State minimization start in level %d. (%s)" % (pm.current_level, time.ctime(time.time())))
		is_pruning = True
		stma.minimize_sm(pm, sm)
		print("  [+] State minimization end in level %d. (%s)" % (pm.current_level, time.ctime(time.time())))
		logger.info("  [+] State minimization end in level %d. (%s)" % (pm.current_level, time.ctime(time.time())))

		### Finishing current level ... ###
		elapsed_time = time.time() - g_start_time
		pm.current_level = pm.current_level + 1
		pm.candidate_state_list.state_list = []  # clear candidate state list

		if len(pm.state_list.get_states_by_level(pm.current_level)) == 0: # Jobs finished
			break
		print("  [+] --- Finished level %d | " % (pm.current_level) + "Time elapsed %s ---" % elapsed_time)
		logger.info("  [+] --- Finished level %d | " % (pm.current_level) + "Time elapsed %s ---" % elapsed_time)
		

		### Graph drawing ###
		graphname = "%s/diagram/level_" % outdir + str(pm.current_level-1) + ".png"
		sm.get_graph().draw(graphname, prog='dot')
		with open(graphname.replace(".png", ".json"), "w") as jsonfile:
			json.dump(sm.markup, jsonfile, indent=2)

	elapsed_time = time.time() - g_start_time
	print ("[+] All jobs done. Total elapsed time is ", elapsed_time)
	### Graph drawing ###
	graphname = "%s/diagram/level_" % outdir + str(pm.current_level-1) + "(fin).png"
	sm.get_graph().draw(graphname, prog='dot')
	with open(graphname.replace(".png", ".json"), "w") as jsonfile:
		json.dump(sm.markup, jsonfile, indent=2)
	logger.info(pm.transition_info)
	sys.exit()


def send_receive_http2(pm, mov_msg_list, h2msg_sent, parent_elapedTime):
	
	h2msg_rcvd = []
	elapsed_time = 0.0

	########## Settings for HTTP2 secket ##########
	assert(ssl.HAS_ALPN)

	srv_max_frm_sz = 1<<14
	srv_hdr_tbl_sz = 4096
	srv_max_hdr_tbl_sz = 0
	srv_global_window = 1<<14
	srv_max_hdr_lst_sz = 0
	l = socket.getaddrinfo(pm.dst_ip, 443, socket.INADDR_ANY, socket.SOCK_STREAM, socket.IPPROTO_TCP)
	assert len(l) > 0, 'No address found :('

	s = socket.socket(l[0][0], l[0][1], l[0][2])
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	if hasattr(socket, 'SO_REUSEPORT'):
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
	ip_and_port = l[0][4]

	########## Connect SSL for HTTP2 ##########
	ssl_sock = None
	if util.ip_checker(pm.dst_ip):
		ssl_sock = ssl_ctx.wrap_socket(s)
		ssl_sock.connect(ip_and_port)
	else:
		ssl_sock = ssl_ctx.wrap_socket(s, server_hostname=pm.dst_ip)
		ssl_sock.connect((pm.dst_ip, 443))

	assert('h2' == ssl_sock.selected_alpn_protocol())
	# print("    [+] Testing.... Wait for response.")

	scapy.config.conf.debug_dissector = True
	ss = supersocket.SSLStreamSocket(ssl_sock, basecls=h2.H2Seq)

	prefaceFrame = hex_bytes('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a')
	firstSETTINGS = h2.H2Frame()/h2.H2SettingsFrame()
	max_frm_sz = (1 << 24) - 1
	max_hdr_tbl_sz = (1 << 16) - 1
	win_sz = (1 << 31) - 1
	firstSETTINGS.settings = [
		h2.H2Setting(id = h2.H2Setting.SETTINGS_ENABLE_PUSH, value=0),
		h2.H2Setting(id = h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=win_sz),
		h2.H2Setting(id = h2.H2Setting.SETTINGS_HEADER_TABLE_SIZE, value=max_hdr_tbl_sz),
		h2.H2Setting(id = h2.H2Setting.SETTINGS_MAX_FRAME_SIZE, value=max_frm_sz),
	]

	inter = 0.1
	try:
		is_quick_goaway = False
		### SENDING INITIAL MSG ###
		init_msg = h2.H2Seq()
		init_msg.frames = [prefaceFrame, firstSETTINGS]	
		ans = None
		ans, unans = ss.sr(init_msg, inter=inter, verbose=0, multi=True, timeout=0.1)
		# print("len of ans : %d" % len(ans))

		### SENDING STATE MOVING MSG ###
		for mov_msg in mov_msg_list:
			ans = None
			ans, unans = ss.sr(mov_msg, inter=0.2, verbose=0, multi=True, timeout=0.1)
			# print("len of ans : %d" % len(ans))
			if len(ans) > 0 and util.check_h2_response(ans = ans, msg = "GO"):
				# print("  [D] GOAWAY frame while state moving. Skip...")
				is_quick_goaway = True
				break

		### SENDING TARGET MSG ###
		if is_quick_goaway is False: # check for goaway in state moving
			ans = None
			ans, unans = ss.sr(h2msg_sent, inter=0.1, verbose=0, multi=True, timeout=5, retry=3)
			# print("len of ans : %d" % len(ans))
			if len(ans) > 0 and util.check_h2_response(ans = ans, msg = "GO"):
				# print("  [D] GOAWAY frame received for target msg...")
				is_quick_goaway = True
			
		
		### PROCESSING RECEIVED MSG ###
		for a in ans:
			if len(ans) > 1:
				# a[0].show()
				a[1].show()
			# a : each answered packet (a[0] : msg sent, a[1] : msg recvd)
			# print("sent:")
			# a[0].show()
			# print("recvd:")
			# a[1].show()
			r = a[1]
			if r.haslayer(h2.H2Seq):
				# # IMPORTANT :: Handling multiple SETTINGS frames received
				# # Empirically, multiple SETTINGS frames are accumulated as states go deep
				# if new_frame.type == h2.H2SettingsFrame.type_id:
				# 	if len(h2msg_rcvd.frames) > 1 and h2msg_rcvd.frames[-1].type == h2.H2SettingsFrame.type_id:
				# 	continue
				h2msg_rcvd.append(r)

		if len(ans) == 0:
			print(type(ans))
			print(ans)

		if ans is not None:
			elapsed_time = ans[0][1].time - ans[0][0].sent_time
			# print("    [ ] ElapsedTime %f" % elapsed_time)

	except Exception as e:
		print("Exception message: {}".format(e))
		print(traceback.format_exc())
		sys.exit()

	if is_quick_goaway is False:
		ss.send(h2.H2Frame()/h2.H2GoAwayFrame())

	# print("  == send_receive_http2() summary ==")
	# print("  == (Moving frame) - Test Frame / Receive Frame")
	# print("    [I] Moving => Target => Received (time)")
	print("    [R] (%s) => %s => %s (%d sec.)" % (
	util.h2msg_to_str(mov_msg_list), util.h2msg_to_str(h2msg_sent), util.h2msg_to_str(h2msg_rcvd), elapsed_time))
	# print("  ==================================")

	return h2msg_rcvd, elapsed_time