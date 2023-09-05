import os
import sys
import pickle
import logging
import time
import json
import binascii
import random
import socket
import ssl
import string
import signal
import scapy.supersocket as supersocket
import scapy.contrib.http2 as h2
import scapy.config
import scapy.packet as packet
from scapy.compat import raw, plain_str, hex_bytes, orb, chb, bytes_encode
from scapy.all import *
from collections import OrderedDict
import util
import networkx as nx
from tqdm import tqdm

jsonFileDescripter = None

def signal_handler(sig, frame):
	global jsonFileDescripter
	print('[+] Ctrl+C signal detected.')
	now = time.localtime()
	dateStrBuf = "%04d.%02d.%02d %02d:%02d:%02d" % (now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)
	print ("[+] end_time : %s" % dateStrBuf)
	try:	
		jsonFileDescripter.write('{}]\n')
		jsonFileDescripter.write('}')
		jsonFileDescripter.close()
	except Exception as e:
		print (e)
		print('[-] multiple times of Ctrl+C!')
	sys.exit(0)

class Tee(object):
	def __init__(self, *files):
	   self.files = files
	def write(self, obj):
		for f in self.files:
			f.write(obj)
			f.flush() # If you want the output to be visible immediately
	def flush(self) :
		for f in self.files:
			f.flush()

class Http2fuzz:
	def __init__(self, current_state = "init", dst_ip = 'localhost', init_time = None, pcap = None, sm_json = None):
		### General ###
		self.fuzzer_version = 'ver.2'
		self.init_time = init_time
		self.out_json = ''
		self.state_move_frame_option = "y"
		self.dst_ip = dst_ip

		### State machine reconstruction ###
		self.pcap = pcap
		self.sm_json = sm_json

		### State machine as graph ###
		self.current_state = current_state
		self.target_transition = None
		self.transition_dic = OrderedDict()
		self.graph = nx.DiGraph()

		### Connection ###
		self.ssl_ctx = None
		self.txcount = -1

		### Fuzzing configuration ###
		self.fuzzing_strategy = [0,1,2,3,4,5,6,7,8,9,10]
		self.timeOutNum = 600
		self.dosChecksocketOpenNum = 300
		self.dosCheckWaitTime = 6
		self.frame_number_dict = None

		### Server binary tokens ###
		self.token_db = None

	def ssl_setting(self):
		# Building the SSL context
		self.ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
		self.ssl_ctx.keylog_filename = "/home/oren/sslkey_scapy.txt"
		self.ssl_ctx.set_ciphers(':'.join([  # List from ANSSI TLS guide v.1.1 p.51
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
		self.ssl_ctx.set_alpn_protocols(['h2'])  # h2 is a RFC7540-hardcoded value

	def initframe_setting(self):
		H2_CLIENT_CONNECTION_PREFACE = hex_bytes('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a')
		srv_max_frm_sz = 1<<14
		srv_hdr_tbl_sz = 4096
		srv_max_hdr_tbl_sz = 0
		srv_global_window = 1<<14
		srv_max_hdr_lst_sz = 0

		prefaceFrame = packet.Raw(H2_CLIENT_CONNECTION_PREFACE)
		firstSETTINGS = h2.H2Frame()/h2.H2SettingsFrame()
		max_frm_sz = (1 << 24) - 1
		max_hdr_tbl_sz = (1 << 16) - 1
		win_sz = (1 << 31) - 1
		firstSETTINGS.settings = [
    		h2.H2Setting(id = h2.H2Setting.SETTINGS_ENABLE_PUSH, value=1),
    		h2.H2Setting(id = h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=win_sz),
    		h2.H2Setting(id = h2.H2Setting.SETTINGS_HEADER_TABLE_SIZE, value=max_hdr_tbl_sz),
    		h2.H2Setting(id = h2.H2Setting.SETTINGS_MAX_FRAME_SIZE, value=max_frm_sz),
		]

		self.past_state = '0'
		self.current_state = 'init'
		return prefaceFrame, firstSETTINGS


# 	def make_frame_array(self, frameStrBuf):
# 		global dst_ip
# 		# move_state_msg_arr: ['HE-SE-SE', DE-PE, ....]
# 		# send_frame_seq: 'HE-DE'
# 		frameDashStrArr = []
# 		if (str(type(frameStrBuf)) == "<type 'str'>"):
# 			frameDashStrArr.append(frameStrBuf)
# 		else:
# 			frameDashStrArr.extend(frameStrBuf)
	
# 		frameStrArr = []
# 		for frameEachSeq in frameDashStrArr:
# 			splitFrameEachSeq = frameEachSeq.split('-')
# 			for splitFrameEach in splitFrameEachSeq:
# 				frameStrArr.append(splitFrameEach)
	
# 		# frameArr = []
# 		srv_max_frm_sz = 1<<14
# 		srv_hdr_tbl_sz = 4096
# 		srv_max_hdr_tbl_sz = 0
# 		srv_global_window = 1<<14
# 		srv_max_hdr_lst_sz = 0
	
# 		h2seq = h2.H2Seq()
# 		# H2DataFrame
# 		# H2HeadersFrame
# 		# H2SettingsFrame
# 		# H2PushPromiseFrame
# 		# H2PingFrame
# 		# H2PriorityFrame
# 		# H2ResetFrame
# 		# H2GoAwayFrame
# 		# H2WindowUpdateFrame
# 		# H2ContinuationFrame
	
# 		for frameValue in frameStrArr:
# 			if frameValue == 'DA':
# 				dataFrameBuf = h2.H2Frame()/h2.H2DataFrame()
# 				dataFrameBuf.stream_id = 1
# 				h2seq.frames.append(dataFrameBuf)
	
# 			elif frameValue == 'HE':
# 				msg = "GET"
# 				args = "/index.html"
	
# 				headerArgs = ":method "+ msg + "\n\
# :path "+ args +"\n\
# :authority "+ dst_ip +"\n\
# :scheme https\n\
# accept-encoding: gzip, deflate\n\
# accept-language: ko-KR\n\
# accept: text/html\n\
# user-agent: Scapy HTTP/2 Module\n"

# 				tblhdr = h2.HPackHdrTable()
# 				qry_frontpage = tblhdr.parse_txt_hdrs(
# 				headerArgs,
# 				stream_id=1,
# 				max_frm_sz=srv_max_frm_sz,
# 				max_hdr_lst_sz=srv_max_hdr_lst_sz,
# 				is_sensitive=lambda hdr_name, hdr_val: hdr_name in ['cookie'],
# 				should_index=lambda x: x in [
# 						'x-requested-with', 
# 						'user-agent', 
# 						'accept-language',
# 						':authority',
# 						'accept',
# 						]
# 					)
# 				h2seq.frames.append(qry_frontpage.frames[0])
	
# 			elif frameValue == 'SE':
# 				settingFrameBuf = h2.H2Frame()/h2.H2SettingsFrame()	
# 				max_frm_sz = (1 << 24) - 1
# 				max_hdr_tbl_sz = (1 << 16) - 1
# 				win_sz = (1 << 31) - 1
# 				settingFrameBuf.settings = [
# 					h2.H2Setting(id = h2.H2Setting.SETTINGS_ENABLE_PUSH, value=0),
# 					h2.H2Setting(id = h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=win_sz),
# 					h2.H2Setting(id = h2.H2Setting.SETTINGS_HEADER_TABLE_SIZE, value=max_hdr_tbl_sz),
# 					h2.H2Setting(id = h2.H2Setting.SETTINGS_MAX_FRAME_SIZE, value=max_frm_sz),
# 				]
# 				h2seq.frames.append(settingFrameBuf)
# 			elif frameValue == 'PU':
# 				h2seq.frames.append(h2.H2Frame()/h2.H2PushPromiseFrame())
	
# 			elif frameValue == 'PI':
# 				h2seq.frames.append(h2.H2Frame()/h2.H2PingFrame())
	
# 			elif frameValue == 'PR':
# 				h2seq.frames.append(h2.H2Frame()/h2.H2PriorityFrame())
	
# 			elif frameValue == 'RS':
# 				h2seq.frames.append(h2.H2Frame()/h2.H2ResetFrame())
	
# 			elif frameValue == 'GO':
# 				h2seq.frames.append(h2.H2Frame()/h2.H2GoAwayFrame())
	
# 			elif frameValue == 'WI':
# 				h2seq.frames.append(h2.H2Frame()/h2.H2WindowUpdateFrame())
	
# 			elif frameValue == 'CO':
# 				h2seq.frames.append(h2.H2Frame()/h2.H2ContinuationFrame())
	
# 		return h2seq

	def open_socket(self, dst_ip):
		H2_CLIENT_CONNECTION_PREFACE = hex_bytes('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a')
		
		assert(ssl.HAS_ALPN)
		l = socket.getaddrinfo(dst_ip, 443, socket.INADDR_ANY, socket.SOCK_STREAM, socket.IPPROTO_TCP)
		assert len(l) > 0, 'No address found :('
	
		s = socket.socket(l[0][0], l[0][1], l[0][2])
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		if hasattr(socket, 'SO_REUSEPORT'):
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
		ssl_ip_port = l[0][4]
	
		ssl_sock = self.ssl_ctx.wrap_socket(s)
		ssl_sock.connect(ssl_ip_port)
		assert('h2' == ssl_sock.selected_alpn_protocol())
		scapy.config.conf.debug_dissector = True
		ss = supersocket.SSLStreamSocket(ssl_sock, basecls=h2.H2Seq)

		return ss

	def get_next_transition(self, td):
		# Get next transition. If target transition is none, get the first transition
		return td.popitem(last=False)

	def get_moving_frame(self, t_transition):
		# Get moving frames to reach the source of target trasition
		sd = t_transition.split("->")
		source = sd[0]
		dest = sd[1]

		mov_msg_list = []

		states_to_source = nx.shortest_path(self.graph, source='init', target=source)
		# get transition messages following states_to_source
		for i in range(0, len(states_to_source)-1):
			sub_src = states_to_source[i]
			sub_dst = states_to_source[i+1]
			sub_trs = sub_src+"->"+sub_dst
			sub_msg = self.transition_dic[sub_trs][0]
			if len(sub_msg.frames) == 0:
				continue
			mov_msg_list.append(sub_msg)
		return mov_msg_list


	def make_fuzzing_frame_seq(self, frameStrBuf):
		# Below codes used for binary token used
		httpSchemes = self.token_db
		httpMethods = self.token_db
		httpPaths = self.token_db
		httpImageTypes = self.token_db
		dstIPArr = self.token_db

		frameStrArr = []
		frameStrArr = frameStrBuf.split('-')
		# print("[DEBUG] frameStrBuf :", frameStrBuf)
		# print("[DEBUG] frameStrArr :", frameStrArr)
	
		h2seq = h2.H2Seq()
	
		for frameValue in frameStrArr:
			# For removing frame length (from DA (1e) to DA)
			frameValue = frameValue.split("(")[0].rstrip(" ")

			if frameValue == 'DA':
				dataFrameBuf = h2.H2Frame()/h2.H2DataFrame()
				# while True:
				# 	stream_id_buf = random.randrange(1, (1<<31)) - 1
				# 	if (stream_id_buf % 2) != 0:
				# 		break 
				dataFrameBuf.stream_id = self.makeRandomValue()
				dataFrameBuf.flags = random.randint(0,255)

				data_len = random.randint(0, 10000)
				string_pool = string.ascii_letters + string.digits + string.punctuation
				data_buf = ''
				for i in range(data_len):
					data_buf += random.choice(string_pool)
				dataFrameBuf.data = data_buf
				# print("??2")
				h2seq.frames.append(dataFrameBuf)
				# print("??3")

			elif frameValue == 'HE':
				qry_frontpage = self.make_header_random_args()

				qry_frontpage.frames[0].stream_id = self.makeRandomValue()
				qry_frontpage.frames[0].flags = random.randint(0,255)

				# qry_frontpage.frames[0].show()
				h2seq.frames.append(qry_frontpage.frames[0])
	
			elif frameValue == 'SE':
				settingFrameBuf = h2.H2Frame()/h2.H2SettingsFrame()	

				frame_size_buf = self.makeRandomValue()
				frame_header_table_size_buf = self.makeRandomValue()
				window_size_buf = self.makeRandomValue()
				max_stream_buf = self.makeRandomValue()
				max_header_list_size_buf = self.makeRandomValue()
				settings_enable_push = self.makeRandomValue()
				settingFrameBuf.settings = [
					h2.H2Setting(id = h2.H2Setting.SETTINGS_MAX_CONCURRENT_STREAMS, value=max_stream_buf),
					h2.H2Setting(id = h2.H2Setting.SETTINGS_MAX_HEADER_LIST_SIZE, value = max_header_list_size_buf),
					h2.H2Setting(id = h2.H2Setting.SETTINGS_ENABLE_PUSH, value=settings_enable_push),
					h2.H2Setting(id = h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=frame_size_buf),
					h2.H2Setting(id = h2.H2Setting.SETTINGS_HEADER_TABLE_SIZE, value=frame_header_table_size_buf),
					h2.H2Setting(id = h2.H2Setting.SETTINGS_MAX_FRAME_SIZE, value=window_size_buf),
				]
				# TODO: you need to consider ACK settings
				# h2.H2Frame(flags={'A'})/h2.H2SettingsFrame()
				settingFrameBuf.stream_id = self.makeRandomValue()
				# settingFrameBuf.len = settingFrameBuf.__len__()

				h2seq.frames.append(settingFrameBuf)
			elif frameValue == 'PU':
				pushPromiseFrameBuf = h2.H2Frame()/h2.H2PushPromiseFrame()

				max_promise_stream_id = self.makeRandomValue()
				# pushPromiseFrameBuf.PromiseStreamID = random.randint(0, max_promise_stream_id)
				# print(pushPromiseFrameBuf['HTTP/2 Push Promise Frame'].reserved)
				pushPromiseFrameBuf['HTTP/2 Push Promise Frame'].stream_id = self.makeRandomValue()

				qry_frontpage = self.make_header_random_args()
				headerFrameBuf = qry_frontpage.frames[0]
				
				pushPromiseFrameBuf['HTTP/2 Push Promise Frame'].hdrs = headerFrameBuf['HTTP/2 Headers Frame'].hdrs

				pushPromiseFrameBuf.stream_id = self.makeRandomValue()
				pushPromiseFrameBuf.flags = random.randint(0,255)

				# pushPromiseFrameBuf.show()

				h2seq.frames.append(pushPromiseFrameBuf)
	
			elif frameValue == 'PI':
				pingFrameBuf = h2.H2Frame()/h2.H2PingFrame()
				pingFrameBuf.flags = random.randint(0,255)
				# pingFrameBuf.stream_id = random.randint(1, ((1 << 31) - 1))
				pingFrameBuf.stream_id = self.makeRandomValue()
				# TODO: add opaque data
				# 8byte array needed each array include random.randint(0, 256)

				# data_len = random.randint(0, 10000)
				# string_pool = string.ascii_lowercase
				# data_buf = ''
				# for i in range(data_len):
				# 	data_buf += random.choice(string_pool)

				# pingFrameBuf.__init__(100000000000)
				# dataFrameBuf.data = data_buf

				# pingFrameBuf.len = pingFrameBuf.__len__()
				h2seq.frames.append(pingFrameBuf)
	
			elif frameValue == 'PR':
				priorityFrameBuf = h2.H2Frame()/h2.H2PriorityFrame()
				priorityFrameBuf['HTTP/2 Priority Frame'].exclusive = self.makeRandomValue()
				priorityFrameBuf['HTTP/2 Priority Frame'].stream_dependency = self.makeRandomValue()
				# weight occur error when value out of range(0 <= number <= 255)
				priorityFrameBuf['HTTP/2 Priority Frame'].weight = random.randint(0,255)

				priorityFrameBuf.stream_id = self.makeRandomValue()
				h2seq.frames.append(priorityFrameBuf)
	
			elif frameValue == 'RS':
				h2seq.frames.append(h2.H2Frame()/h2.H2ResetFrame())
	
			elif frameValue == 'GO':
				h2seq.frames.append(h2.H2Frame()/h2.H2GoAwayFrame())
	
			elif frameValue == 'WI':
				windowUpdateFrameBuf = h2.H2Frame()/h2.H2WindowUpdateFrame()
				windowUpdateFrameBuf.stream_id = self.makeRandomValue()
				windowUpdateFrameBuf['HTTP/2 Window Update Frame'].win_size_incr = self.makeRandomValue()

				# windowUpdateFrameBuf.len = windowUpdateFrameBuf.__len__()
				h2seq.frames.append(windowUpdateFrameBuf)
	
			elif frameValue == 'CO':
				continuationFrameBuf = h2.H2Frame()/h2.H2ContinuationFrame()

				continuationFrameBuf.stream_id = self.makeRandomValue()
				continuationFrameBuf.flags = random.randint(0,255)
	
				qry_frontpage = self.make_header_random_args()
				headerFrameBuf = qry_frontpage.frames[0]

				continuationFrameBuf['HTTP/2 Continuation Frame'].hdrs = headerFrameBuf['HTTP/2 Headers Frame'].hdrs

				# continuationFrameBuf.len = continuationFrameBuf.__len__()
				# continuationFrameBuf.show()

				h2seq.frames.append(continuationFrameBuf)

			elif frameValue == 'RA':
				hex_string_pool = 'abcdef0123456789'
				while True:
					data_len = random.randint(0, 10000)
					if (data_len % 2) == 0:
						break 
				data_buf = ''
				for i in range(data_len):
					data_buf += random.choice(hex_string_pool)

				rawHexBytes = hex_bytes(data_buf)
				rawFrame = packet.Raw(rawHexBytes)
				h2seq.frames.append(rawFrame)
	
		return h2seq


	"""
	def make_fuzzing_packet(self, strategy):
		frameShortInfoArr_forFuzz = ['DA','HE','PR','SE','PU','PI','WI','CO','RA']
		# 0,1,2,3,4,5,6,7 -> frameShortInfoArr each frame sent

		fuzzing_frame_seq = None
		# strategy: 0 make frame field mutation
		self.txcount += 1
		print("[DEBUG] make_fuzzing_packet(): txcount = %d" % int(self.txcount))
		if strategy < 9:
			frameStr = frameShortInfoArr_forFuzz[strategy]
			print("[+] Single frame to be sent : %s" % frameStr)
			fuzzing_frame_seq = self.make_fuzzing_frame_seq(frameStr)
			# fuzzing_frame_seq.show()

		else:
			frameStr = ''
			# 0 to end of List
			for i in range(0, (len(frameShortInfoArr_forFuzz))):
				frameStr += (frameShortInfoArr_forFuzz[i]+'-')
			frameStr = frameStr[:-1]
			print("[+] All frames to be sent : %s" % frameStr)
			fuzzing_frame_seq = self.make_fuzzing_frame_seq(frameStr)
			# fuzzing_frame_seq.show()

		# elif strategy == 10:
		# 	frameNum = self.txcount
		# 	frameStr = ''
		# 	for i in range(0, frameNum):
		# 		frameIndex = random.randint(0, len(frameShortInfoArr_forFuzz) - 1)
		# 		frameStr += (frameShortInfoArr_forFuzz[frameIndex]+'-')
		# 	frameStr = frameStr[:-1]
		# 	print("[+] Random frames to be sent : %d frames" % len(frameStr))
		# 	fuzzing_frame_seq = self.make_fuzzing_frame_seq(frameStr)

		# To check crash added ping frame
		# fuzzing_frame_seq.frames.append(h2.H2Frame()/h2.H2PingFrame())
		# fuzzing_frame_seq.frames.append(h2.H2Frame()/h2.H2PingFrame())
		return fuzzing_frame_seq
	"""

	def make_fuzzing_message(self, t_msg):
		"""
		# @Isa we need to generate test cases here.
		# Currently I generate a template in the format of frameStr (i.e. HE-DA) 
		# using t_msg as seed and make_fuzzing_frame_seq() to fill randomized value 
		# in each frame.
		# - t_msg is the message we stored in state machine reconstruction
		"""
		frameStr = ''
		for msg in t_msg: # for each frame in t_msg
			msg_short_str = util.h2msg_to_str(msg)
			frameStr += msg_short_str+'-'
		frameStr = frameStr[:-1]
		fuzzing_frame_seq = self.make_fuzzing_frame_seq(frameStr)
		return fuzzing_frame_seq

	def make_header_random_args(self):
		srv_max_frm_sz = 1<<14
		srv_max_hdr_lst_sz = 0

		method_buf = random.choice(self.token_db)
		path_buf = random.choice(self.token_db)
		scheme_buf = random.choice(self.token_db)
		accept_buf = random.choice(self.token_db)
		dst_ip = random.choice(self.token_db)
		accept_encodeing_var = random.choice(self.token_db)
		accept_language_var = random.choice(self.token_db)
		user_agent_var = random.choice(self.token_db)

		headerArgsList = []
		headerArgsRanValList = []
		# over 200 takes too long time
		randomCount = random.randint(1, 100)

		headerArgs = ":method "+ method_buf + "\n\
:path "+ path_buf +"\n\
:authority "+ dst_ip +"\n\
:scheme "+ scheme_buf+"\n\
accept-encoding: " + accept_encodeing_var + "\n\
accept-language: " + accept_language_var + "\n\
accept: "+ accept_buf +"\n\
user-agent:" + user_agent_var + "\n"

		shouldIndexArgsList = ['x-requested-with', 
		'user-agent', 
		'accept-language', 
		':authority', 
		'accept']

		for i in range(0, randomCount):
			headerArgsRan = random.choice(self.token_db)
			headerArgsRanVal = random.choice(self.token_db)
			headerArgsList.append(headerArgsRan)
			headerArgsRanValList.append(headerArgsRanVal)
			headerArgs = headerArgs + (headerArgsRan+": "+str(headerArgsRanVal)+"\n")
			shouldIndexArgsList.append(headerArgsRan)

		tblhdr = h2.HPackHdrTable()
		qry_frontpage = tblhdr.parse_txt_hdrs(
			str.encode(headerArgs),
			stream_id=1,
			max_frm_sz=srv_max_frm_sz,
			max_hdr_lst_sz=srv_max_hdr_lst_sz,
			is_sensitive=lambda hdr_name, hdr_val: hdr_name in ['cookie'],
			should_index=lambda x: x in shouldIndexArgsList
		)
		# headerFrameBuf = qry_frontpage.frames[0]

		return qry_frontpage

	def make_frame_array_to_str(self, frameArrBuf):
		global frameInfoArr, frameShortInfoArr
		# move_state_msg_arr: ['HE-SE-SE', DE-PE, ....]
		# send_frame_seq: 'HE-DE'
		# frameStrArr = []
		frameStr = ''
		# print("[!] Testing!!")
		# frameArrBuf.show()
		# print("[!] Testing End!!")
		for frameValue in frameArrBuf.frames:
			try:
				frameStr+=(frameShortInfoArr[frameValue.type]+'-')
			except:
				frameStr+=('RA-')
				continue
	
		frameStr = frameStr[:-1]
	
		return frameStr

	def write_binary_file(self, state_move_frame, send_frame, now, crash_type):
		global jsonFileDescripter
		total_write_frame_binary_array = []
		# if self.txcount == 0:
		# 	jsonFileDescripter.write('\t{')
		# else:
		# 	jsonFileDescripter.write('\t,{')
		jsonFileDescripter.write('\t{')
		jsonFileDescripter.write("\"no\" : {0},\n".format(self.txcount))
		# print("[+] Dos on multiple connection checking Start %02d:%02d:%02d" % (now.tm_hour, now.tm_min, now.tm_sec))
		dateStrBuf = "%04d.%02d.%02d %02d:%02d:%02d" % (now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)
		jsonFileDescripter.write("\t\"time\" : \"{0}\",\n".format(dateStrBuf))
		jsonFileDescripter.write("\t\"crash_type\" : \"{0}\",\n".format(crash_type))

		jsonFileDescripter.write("\t\"state_move_frames\" : [\n")
		frame_no = 0
		for msg in state_move_frame:
			frame_no += 1
			try:
				jsonFileDescripter.write("\t\t{")
				jsonFileDescripter.write("\"frame_no\" : {0}, ".format(str(frame_no)))
				jsonFileDescripter.write("\"frame_data\" : \"{0}\"".format(util.h2msg_to_str(msg)))
				if frame_no == len(state_move_frame)-1:
					jsonFileDescripter.write("\n\t\t}\n")
					break
				jsonFileDescripter.write("\n\t\t},\n")
			except Exception as e:
				print ("  [E] write_binary_file():", e)
				continue
		jsonFileDescripter.write("\t],\n")

		jsonFileDescripter.write("\t\"fuzzing_frames\" : [\n")
		frame_no = 0
		for msg in send_frame:
			frame_no += 1
			try:
				jsonFileDescripter.write("\t\t{")
				jsonFileDescripter.write("\"frame_no\" : {0}, ".format(str(frame_no)))
				jsonFileDescripter.write("\"frame_data\" : \"{0}\"".format(util.h2msg_to_str(msg)))
				if frame_no == len(state_move_frame)-1:
					jsonFileDescripter.write("\n\t\t}\n")
					break
				jsonFileDescripter.write("\n\t\t},\n")
			except Exception as e:
				print ("  [E] write_binary_file():", e)
				continue
		jsonFileDescripter.write("\t],\n")

		# frameID = '00'
		# jsonFileDescripter.write("\t\"state_move_frames\" : [\n")
		# for index, frame in enumerate(state_move_frame.frames):
		# 	frame_str = binascii.hexlify(raw(frame))
		# 	try:
		# 		jsonFileDescripter.write("\t\t{")
		# 		jsonFileDescripter.write("\"frame_index\" : {0}, ".format(str(index)))
		# 		jsonFileDescripter.write("\"frame_data\" : \"0x{0}\"".format(frame_str))
		# 		if index == (len(state_move_frame.frames)-1):
		# 			jsonFileDescripter.write("\n\t\t}\n")
		# 			break
		# 		jsonFileDescripter.write("\n\t\t},\n")
		# 	except Exception as e:
		# 		print (e)
		# 		print ("error! 1")
		# 		continue
		# jsonFileDescripter.write("\t],\n")

		# frameID = '01'
		# # jsonFileDescripter.write('[+]Send Frames:\n')
		# jsonFileDescripter.write("\t\"send_frames\" : [\n")
		# for index, frame in enumerate(send_frame.frames):
		# 	frame_str = binascii.hexlify(raw(frame))
		# 	try:
		# 		jsonFileDescripter.write("\t\t{")
		# 		jsonFileDescripter.write("\"frame_index\" : {0},".format(str(index)))
		# 		jsonFileDescripter.write("\"frame_data\" : \"0x{0}\"".format(frame_str))
		# 		if index == (len(send_frame.frames)-1):
		# 			jsonFileDescripter.write("\n\t\t}\n")
		# 			break
		# 		jsonFileDescripter.write("\n\t\t},\n")
		# 	except:
		# 		print ("error! 2")
		# 		continue
		# jsonFileDescripter.write("\t]\n")

		# frameID = '02'
		# jsonFileDescripter.write('[+]Receive Frames:\n')
		# jsonFileDescripter.write("\t\"receive_frames\" : [\n")
		# for index, frame in enumerate(receive_frame.frames):
		# 	frame_str = binascii.hexlify(raw(frame))
		# 	try:
		# 		jsonFileDescripter.write("\t\t{")
		# 		jsonFileDescripter.write("\"frame_index\" : {0},".format(str(index)))
		# 		jsonFileDescripter.write("\"frame_data\" : \"0x{0}\"".format(frame_str))
		# 		if index == (len(receive_frame.frames)-1):
		# 			jsonFileDescripter.write("\n\t\t}\n")
		# 			break
		# 		jsonFileDescripter.write("\n\t\t},\n")
		# 	except:
		# 		print ("error! 3")
		# 		continue

		# jsonFileDescripter.write("\t]\n")
		jsonFileDescripter.write('\t},\n')
		jsonFileDescripter.flush()

	def count_frames(self, frame_seq, crash_check = 0):
		if crash_check == 1:
			# settings is 4
			self.frame_number_dict[4] = (self.frame_number_dict[4] + 1)
			return

		for frame in frame_seq.frames:
			try:
				self.frame_number_dict[frame.type] = (self.frame_number_dict[frame.type] + 1)
			except:
				self.frame_number_dict[10] = (self.frame_number_dict[10] + 1)

	def print_count_frames(self):
		global frameShortInfoArr

		print("[+] frame total send number:")
		for index, frameStr in enumerate(frameShortInfoArr):
			print ("[%s] : %d" % (frameStr, self.frame_number_dict[index]))

	def set_strategy(self):
	 	# strategy 10 is making 1 to 1000 frames sequence, it makes error in Nginx and H2O
		self.fuzzing_strategy = [0,1,2,3,4,5,6,7,8,9,10]
		self.dosChecksocketOpenNum = 300
	# 	if self.target_binary == 'Apache2.4.29':
	# 		self.fuzzing_strategy = [0,1,2,3,4,5,6,7,8,9,10]
	# 		self.dosChecksocketOpenNum = 300
	# 	elif self.target_binary == 'Nginx1.14.0':
	# 		self.fuzzing_strategy = [0,1,2,3,4,5,6,7,8,9]
	# 		self.dosChecksocketOpenNum = 1200
	# 	elif self.target_binary == 'H2O2.2.4':
	# 		self.fuzzing_strategy = [0,1,2,3,4,5,6,7,8,9]
	# 		self.dosChecksocketOpenNum = 1200
	# 	elif self.target_binary == 'NodeJS12.18.4':
	# 		self.fuzzing_strategy = [0,1,2,3,4,5,6,7,8,9]
	# 		self.dosChecksocketOpenNum = 2030
	# 	elif self.target_binary == 'OpenLiteSpeed1.6.21':
	# 		self.fuzzing_strategy = [0,1,2,3,4,5,6,7,8,9]
	# 		self.dosChecksocketOpenNum = 300



	def fuzzing_run(self):
		self.frame_number_dict = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
		self.ssl_setting()
		self.start_write_json_logging()
		self.get_token_dict()
		self.set_strategy()

		prefaceFrame, firstSETTINGS = self.initframe_setting()
		init_msg = h2.H2Seq()
		init_msg.frames = [prefaceFrame, firstSETTINGS]		

		print("[STEP 4] Start Fuzzing...")

		td_traverse = OrderedDict()
		t_index = 0
		while True:
			if len(td_traverse) == 0:
				if t_index == len(self.transition_dic):
					print("  [+] Finished all %d transitions!" % len(self.transition_dic))
					# sys.exit()
				td_traverse = self.transition_dic.copy()
				t_index = 0
			t_index += 1
			t_key, t_msg_info = self.get_next_transition(td_traverse)
			t_msg = t_msg_info[0]
			t_msg_rtime = t_msg_info[1]

			mov_msg_list = self.get_moving_frame(t_key)

			self.fuzzing_strategy = [1]

			for strategy in self.fuzzing_strategy:
				# fuzz_msg = self.make_fuzzing_packet(strategy) # prev. version (~2021)
				fuzz_msg = self.make_fuzzing_message(t_msg)
				totalelapsedTime = 0
				timeOutElapsedTime = 0
				socketArr = []
				dosChecker = False
				errorOutChecker = False

				startTime = time.time()
				now = time.localtime()
				moving_msg_short = "" # for debugging
				for mov_msg in mov_msg_list:
					moving_msg_short += util.h2msg_to_str(mov_msg) + "|"
				if len(moving_msg_short) > 0 and moving_msg_short[-1] == "|":
					moving_msg_short = moving_msg_short[:-1]
				print("  [STATUS] Transition [%d/%d]: Init-M(%s)-T(%s)" % (t_index, len(self.transition_dic), moving_msg_short, t_key))
				print("  [STATUS] Strategy   [%d/%d]: F(%s)" % (int(strategy), len(self.fuzzing_strategy), util.h2msg_to_str(fuzz_msg)))
				dosCheckStartTime = now
				# Trying multiple sockets
				self.dosChecksocketOpenNum = 10
				inter = 0
				for index in tqdm(range(self.dosChecksocketOpenNum)):
					# if int(elapsedMiliSec) > dosCheckWaitTime:
					# 	dosChecker = True
					# 	break
					interConnectionStartTime = time.time()

					try:
						sockBuf = None
						sockBuf = self.open_socket(dst_ip=self.dst_ip)
						socketArr.append(sockBuf)

						### SENDING INITIAL MSG ###
						ans = None
						ans, unans = sockBuf.sr(init_msg, inter=inter, verbose=0)


						### SENDING STATE MOVING MSG ###
						for mov_msg in mov_msg_list:
							ans = None
							ans, unans = sockBuf.sr(mov_msg, inter=inter, verbose=0)
						if util.check_h2_response(ans, "GO"):
							print("  [D] GOAWAY frame while state moving. Skip...")
							break

						### SENDING FUZZING MSG ###
						if util.h2msg_to_str(t_msg) == "GO":
							# print(" GOAWAY msg sent.")
							# When sending GOAWAY, we do not expect any response.
							sockBuf.send(fuzz_msg)					
						else:
							ans = None
							ans, unans = sockBuf.sr(fuzz_msg, inter=inter, timeout=self.dosCheckWaitTime, verbose=0)

					except Exception as e:
						now = time.localtime()
						# print("[!] Error occured on fuzzing multiple connection %02d:%02d:%02d" % (now.tm_hour, now.tm_min, now.tm_sec))
						print("Exception message: {}".format(e))

						if str(e) == '[Errno 0] Error':
							# print ('Errno Zero')
							print("[!] "+str(e))
						elif str(e) == '[Errno 104] Connection reset by peer':
							# print ('Errno One hundred four')
							print("[!] "+str(e))
						elif str(e) == '[Errno 111] Connection refused':
							# print ('Errno One hundred eleven')
							print("[!] "+str(e)+" fuzzer shutdown!")
							# time.sleep(1)
							self.write_binary_file(mov_msg_list, fuzz_msg, dosCheckStartTime, "Shutdown")
							self.fuzzer_shutdown_error_no111()
						# print (e)
						errorOutChecker = True

					if errorOutChecker == True:
						self.write_binary_file(mov_msg_list, fuzz_msg, dosCheckStartTime, "Error")
						break

					timestamp = 0.0

					if ans is not None:
						timestamp = ans[0][1].time - ans[0][0].sent_time
						# print("    [ ] ElapsedTime %f" % timestamp)

					# interConnectionEndTime = time.time()
					# endTime = time.time()

					# elapsedMiliSec = endTime - startTime
					# # print("[+] Connection Number : %d, timeElapse %f" % (index, elapsedMiliSec))

					if timestamp > self.dosCheckWaitTime:
						dosChecker = True
						break
			
				if dosChecker == True:
					self.write_binary_file(mov_msg_list, fuzz_msg, dosCheckStartTime, "DoS")
					print("    [+] DoS : yes *********************************************")
					time.time(10)
				else:
					# print("    [ ] DoS : no")
					pass

				# now = time.localtime()
				# print("[+] Dos on multiple connection checking End %02d:%02d:%02d" % (now.tm_hour, now.tm_min, now.tm_sec))

				# print ("[+] Socket reset start")
				for index, sockValue in enumerate(socketArr):
					try:
						sockValue.send(h2.H2Frame()/h2.H2GoAwayFrame())
						# print("    [+] Reset Successful")
					except Exception as e:
						print ("[!] Error occured in connection %d while reset via GOAWAY" % index)
						continue

				# print("[-] packet number : %d End\n" % int(self.txcount))
				# time.sleep(1)
				# break

				
	def makeRandomValue(self):
		returnValue = None

		percentValueArray = ['%c','%s','%d','%f']
		# TODO: percent Value array can occur error in scapy library
		randIndexArray = [0, 1]
		# 0: minus value
		# 1: very big int
		# 2: %c %d ...
		randIndex = random.choice(randIndexArray)

		if randIndex == 0:
			# negative
			returnValue = random.randint(0x80000000, 0xFFFFFFFF)

		elif randIndex == 1:
			# positive
			# returnValue = random.randint(10000, 1000000)
			returnValue = random.randint(0x00000000, 0x7FFFFFFF)
			# 0x7FFF pos
			# 8000~ 0xFFFF... neg

		elif randIndex == 2:
			returnValue = random.choice(percentValueArray)

		return returnValue


	def recover_sm(self, messages):
		global frameInfoArr, frameShortInfoArr
		print("[STEP 3] Reconstructing state machine from json file...")

		# Nodes are stored in networkx Digraph. 
		with open(self.sm_json) as json_file:
			data = json.load(json_file)
			self.current_state = data["initial"]
			for s_info in data["states"]:
				state = s_info["name"]
				self.graph.add_node(state)
			
			for t_info in data["transitions"]:
				edge = (t_info["source"], t_info["dest"])
				self.graph.add_edge(t_info["source"], t_info["dest"])
				trigger = t_info["trigger"]
				### Prev. version trigger
				# msg_sent = trigger.split("/")[0].replace(" ", "")
				# msg_rtime = trigger.split("/")[-1].replace("\n", "").replace(" ", "")
				### New version trigger
				msg_sent = trigger.split(" => ")[0].replace(" ", "")
				msg_rtime = trigger.split(" => ")[-1].replace("\n", "").replace(" ", "")
				for h2msg_sent in messages:
					if msg_sent == util.h2msg_to_str(h2msg_sent):
						msg_sent = h2msg_sent
						break
				if type(msg_sent) == type(""):
					print("[Error] recover_sm(): not maching msg error")

				# Transition infomration are stored in transition_dic.
				# Each key is source state -> dest state, where its corresponding value is
				# a tuple of (1) message sent for the transition and (2) response with time.
				# The tuple is used for making fuzzing test cases and monitoring later 
				# (t_msg as seed, msg_rtime as monitoring).
				self.transition_dic[t_info["source"]+"->"+t_info["dest"]] = [msg_sent, msg_rtime]


		if len(self.graph.nodes) > 0:
			print("  [+] Reconstruction done!")
			print("  [+] No. of states : %d, No. of transitions : %d" % (len(self.graph.nodes), len(self.graph.edges)))

	def get_token_dict(self):
		with open("./tokenDict/total_tokens.data", "rb") as f:
			self.token_db = pickle.load(f)

	def start_write_json_logging(self):
		global jsonFileDescripter
		self.out_json = './log/'+self.init_time+'_logging.json'
		fuzzer_version_buf = ("\"fuzzer_version\" : \"%s\",\n" % self.fuzzer_version)
		start_date_buf = ("\"starting_time\" : \"%s\",\n" % self.init_time)
		# target_binary_buf = ("\"target_binary\" : \"%s\",\n" % self.target_binary)
		state_move_use_buf = ("\"state_move_frame_use\" : \"%s\",\n" % self.state_move_frame_option)

		jsonFileDescripter = open(self.out_json, 'w')
		jsonFileDescripter.write("{\n")
		jsonFileDescripter.write(fuzzer_version_buf)
		jsonFileDescripter.write(start_date_buf)
		# jsonFileDescripter.write(target_binary_buf)
		jsonFileDescripter.write(state_move_use_buf)
		jsonFileDescripter.write("\"packet\" : [\n")
		jsonFileDescripter.flush()

	def fuzzer_shutdown_error_no111(self):
		global jsonFileDescripter
		jsonFileDescripter.write('{}]\n')
		jsonFileDescripter.write('}')
		jsonFileDescripter.close()
		sys.exit()

def info():
	print("[USAGE]")
	print("- $ sudo python3 %s [target_ip] [input_pcap] [sm_json]" % sys.argv[0])
	print("- [target_ip] string; IP address or URL without https://")
	print("- [input_pcap] file path; pcap file used for state machine construction")
	print("- [sm_json] file path; json file output from state machine construction")
	print("[NOTICE]")
	print("- Run this script with target IP address (python3).")
	sys.exit()

def main():
	if len(sys.argv) < 4:
		info()

	print("[STEP 1] Initializing...")
	#### general setting ###
	dst_ip = sys.argv[1]
	pcap_path = sys.argv[2]
	json_path = sys.argv[3]
	state_move_frame_option = "y"
	now = time.localtime()
	dt = "%04d%02d%02d-%02d%02d%02d" % (now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)
	pcapname = pcap_path.split("/")[-1]
	# f = open('./log/'+pcapname+"_"+dt+'.txt', 'w')
	# original = sys.stdout
	# sys.stdout = Tee(sys.stdout, f)
	signal.signal(signal.SIGINT, signal_handler)
	http2fuzz_obj = Http2fuzz(dst_ip = dst_ip, init_time=dt,
		pcap = pcap_path,
		sm_json = json_path,
		)

	print ("- Starting Time : %s" % dt)
	print ("- Pcap Input : %s" % pcap_path)
	print ("- Json Input : %s" % json_path)

	### Extract contructed state machine ###
	http2_basic_messages = util.h2msg_from_pcap(pcap_path)
	http2fuzz_obj.recover_sm(http2_basic_messages)
	http2fuzz_obj.fuzzing_run()


	# print(len(fuzzFrameSeq.frames))
	# fuzzFrameSeq.show()
	# elapsedTimeTest = 6
	# receiveFrameArr, elapsedTime = send_receive_http2_time_maketimeout(move_state_frame, frame_db, elapsedTimeTest)

if __name__ == "__main__":
	main()