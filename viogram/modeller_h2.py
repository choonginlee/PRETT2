from states import *
import statemachine as stma
import util
from scapy.all import *
from scapy.compat import raw, plain_str, hex_bytes, orb, chb, bytes_encode
import scapy.supersocket as supersocket
import scapy.contrib.http2 as h2
import time
import sys
import ssl
import sslkeylog
import socket
import logging
import os
logger = logging.getLogger(__name__)
os.environ["SSLKEYLOGFILE"] = "sslkey_scapy.txt"
sslkeylog.set_keylog("sslkey_scapy.txt")

def modeller_h2(http2_basic_messages, dst_ip):
	g_start_time = time.time()
	print("\n[STEP 3] Modeling started at %s" % time.ctime(g_start_time))
	# pm is for modeling status, 
	# sm is for state machine data structure using Machines package 
	pm, sm = stma.generate_sm()
	pm.testmsgs = http2_basic_messages
	pm.dst_ip = dst_ip

	while True: # for each level
		if len(pm.state_list.get_states_by_level(pm.current_level)) == 0:
			break
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

		### Graph drawing ###
		graphname = "diagram/level_" + str(pm.current_level) + ".png"
		sm.get_graph().draw(graphname, prog='dot')

		### Finishing current level ... ###
		elapsed_time = time.time() - g_start_time
		pm.current_level = pm.current_level + 1
		pm.candidate_state_list.state_list = []  # clear candidate state list
		print("  [+] --- Finished level %d | " % (pm.current_level) + "Time elapsed %s ---" % elapsed_time)
		logger.info("  [+] --- Finished level %d | " % (pm.current_level) + "Time elapsed %s ---" % elapsed_time)

	elapsed_time = time.time() - g_start_time
	print ("[+] All jobs done. Total elapsed time is ", elapsed_time)
	# Program normally ends.
	# pm.model.graph.draw("diagram/prune_bfs_state_fin.png", prog='dot')
	# f.close()
	pm.get_graph().draw("diagram/prune_bfs_state_fin.png", prog='dot')
	logger.info(pm.transition_info)
	sys.exit()


def send_receive_http2(pm, move_state_h2msgs, h2msg_send, parent_elapedTime):
	H2_CLIENT_CONNECTION_PREFACE = hex_bytes('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a')
	h2msg_rcvd_short = []
	ssl_bpf = 'tcp and dst port 443'
	h2msg_rcvd = h2.H2Seq()
	elapsedTime = 0

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

	# Building the SSL context
	ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
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

	########## Send HTTP2 connection preface ##########
	ss = supersocket.SSLStreamSocket(ssl_sock, basecls=h2.H2Frame)
	ss.send(packet.Raw(H2_CLIENT_CONNECTION_PREFACE))

	########## Send HTTP2 messages ##########
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

	"""
	if int(parent_elapedTime) > 0:
		print("    [D] parent elapsedTime is %d" % int(parent_elapedTime))
		h2Seq_state_move_msg = h2.H2Seq()
		h2Seq_state_move_msg.frames.extend(move_state_h2msgs)

		h2seq_target_msg = h2.H2Seq()
		h2seq_target_msg.frames.extend(h2msg_send)
		now = time.localtime()
		print("  [+] Start at %02d:%02d:%02d ..." % (now.tm_hour, now.tm_min, now.tm_sec))
		h2Seq_state_move_msg.frames.insert(0, firstSETTINGS)
		ss.send(h2Seq_state_move_msg)
		
		compare_time = 1
		time.sleep(compare_time)
		startTime = time.time()
		for_compare_parent_time = int(parent_elapedTime) - compare_time
		ss.send(h2seq_target_msg)
	
		while True:
			try:
				new_frame = ss.sniff(timeout=600, filter = ssl_bpf, count = 1)
				endTime = time.time()
				elapsedTime = endTime - startTime
				if int(elapsedTime) >= 600:
					elapsedTime = -2
					break

				if (new_frame.type == h2.H2GoAwayFrame.type_id or new_frame.type == h2.H2ResetFrame.type_id) and int(elapsedTime) <= 0:
					print("Error code : %d" % new_frame.error)
					# new_frame.show()
					elapsedTime = 0
					break
	
				elif (new_frame.type == h2.H2GoAwayFrame.type_id or new_frame.type == h2.H2ResetFrame.type_id) and int(elapsedTime) < int(for_compare_parent_time):
					print("[+] Low TimeOut")
					print("[+] real elapsed Time %d" % int(elapsedTime))
					break

				elif (new_frame.type == h2.H2GoAwayFrame.type_id or new_frame.type == h2.H2ResetFrame.type_id) and int(elapsedTime) == int(for_compare_parent_time):
					print("[+] Same TimeOut")
					print("[+] real elapsed Time %d" % int(elapsedTime))
					elapsedTime = -1
					break
	
				elif (new_frame.type == h2.H2GoAwayFrame.type_id or new_frame.type == h2.H2ResetFrame.type_id) and int(elapsedTime) > int(for_compare_parent_time):
					print("[+] Refresh TimeOut")
					print("[+] real elapsed Time %d" % int(elapsedTime))
					break

				h2msg_rcvd_short.append(stma.frameInfoArr[new_frame.type])
				h2msg_rcvd.frames.append(new_frame)
			except:
				new_frame = None	

		now = time.localtime()
		print ("  [+] End at %02d:%02d:%02d ..." % (now.tm_hour, now.tm_min, now.tm_sec))


	else:
		print("    [D] parent elapsedTime is zero")
	"""
	h2Seq_state_move_target_msg = h2.H2Seq()
	h2Seq_state_move_msg = h2.H2Seq()
	h2Seq_state_move_msg.frames.extend(move_state_h2msgs)

	h2seq_target_msg = h2.H2Seq()
	h2seq_target_msg.frames.extend(h2msg_send)

	h2Seq_state_move_target_msg.frames.append(firstSETTINGS)
	h2Seq_state_move_target_msg.frames.append(h2Seq_state_move_msg)
	h2Seq_state_move_target_msg.frames.append(h2seq_target_msg)
	startTime = time.time()
	now = time.localtime()
	# print("    [D] Start at %02d:%02d:%02d ..." % (now.tm_hour, now.tm_min, now.tm_sec))
	# sys.exit()
	ss.send(h2Seq_state_move_target_msg)
	# print("    [D] Reaching target state and testing ...")
	 
	while True:
		try:
			sniff_frame = None
			sniff_frame = ss.sniff(timeout=600, filter=ssl_bpf, count=1)
			new_frame = sniff_frame[0]
			# new_frame.show()
			endTime = time.time()
			elapsedTime = endTime - startTime
			elapsedTime = int(elapsedTime)
			if (pm.timeout - elapsedTime) == 1:
				# print("timeout set to %d" % pm.timeout)
				elapsedTime = pm.timeout
			# h2msg_rcvd_short.append(util.frameInfoArr[new_frame.type])

			# IMPORTANT :: Handling multiple SETTINGS frames received
			# Empirically, multiple SETTINGS frames are accumulated as states go deep
			if new_frame.type == h2.H2SettingsFrame.type_id:
				if len(h2msg_rcvd.frames) > 1 and h2msg_rcvd.frames[-1].type == h2.H2SettingsFrame.type_id:
					continue
			h2msg_rcvd.frames.append(new_frame)

			if int(elapsedTime) >= 600:
				elapsedTime = -2
				break

			if new_frame.type == h2.H2GoAwayFrame.type_id or new_frame.type == h2.H2ResetFrame.type_id:
				# print("    [D] Received GoAway / Reset. (EC : %d)" % new_frame.error)
				break

		except Exception as e: 
			print(str(e))
			new_frame = None

	now = time.localtime()
	# print ("    [D] End at %02d:%02d:%02d" % (now.tm_hour, now.tm_min, now.tm_sec))

	ss.send(h2.H2Frame()/h2.H2GoAwayFrame())

	# print("  == send_receive_http2() summary ==")
	# print("  == (Moving frame) - Test Frame / Receive Frame")
	print("    => (%s) - %s / %s " % (
	util.h2msg_to_str(move_state_h2msgs), util.h2msg_to_str(h2msg_send), util.h2msg_to_str(h2msg_rcvd)))
	print("    => (%d) sec" % elapsedTime)
	# print("  ==================================")

	return h2msg_rcvd, elapsedTime