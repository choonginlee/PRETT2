import os
import sys
import pickle
import logging
import time
import re
import json
import binascii
import random
# import matplotlib.pyplot as plt
# import matplotlib.image as mplotimg
import socket
import ssl
import string
import signal
import scapy.supersocket as supersocket
import scapy.contrib.http2 as h2
import scapy.config
import scapy.packet as packet
from scapy.compat import raw, plain_str, hex_bytes, orb, chb, bytes_encode
# from transitions.extensions import GraphMachine as Machine
# from transitions.extensions import GraphMachine
from scapy.all import *
from collections import OrderedDict
import util
import networkx as nx

dst_ip = '127.0.0.1'
# target_binary = 'Apache 2.4.29'
frameInfoArr = ['DATA','HEADERS','PRIORITY','RST_STREAM','SETTINGS','PUSHPROMISE','PING','GO_AWAY','WINDOW_UPDATE','CONTINUATION','RAW']
frameShortInfoArr = ['DA','HE','PR','RS','SE','PU','PI','GO','WI','CO','RA']

sniff_frame = None
jsonFileDescripter = None

def http2_sniff_parser(packet):
	global sniff_frame
	# sniff_frame = h2.H2Seq()
	sniff_frame = h2.H2Frame(packet)
	# sniff_frame.frames.append(sniff_frameBuf)

def signal_handler(sig, frame):
	global jsonFileDescripter
	print('You pressed Ctrl+C!')
	now = time.localtime()
	dateStrBuf = "%04d.%02d.%02d %02d:%02d:%02d" % (now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)
	print ("[+] end_time : %s" % dateStrBuf)
	try:	
		jsonFileDescripter.write('{}]\n')
		jsonFileDescripter.write('}')
		jsonFileDescripter.close()
	except Exception as e:
		print (e)
		print('You pressed Ctrl+C too much!')
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
	def __init__(self, current_state = "init", init_time = None, pcap = None, sm_json = None):
		self.fuzzer_version = 'fuzz_prett2_v1'
		self.current_state = current_state
		self.past_state = '0'
		self.state_array = []
		self.state_dic = OrderedDict()
		self.transition_dic = OrderedDict()
		self.fuzzing_strategy = [0,1,2,3,4,5,6,7,8,9,10]
		self.timeOutNum = 600
		self.init_time = init_time
		self.pcap = pcap
		self.sm_json = sm_json
		self.graph = nx.DiGraph()

		#  below variable would be used for server binary dict(list type)
		self.token_db = None
		self.txcount = -1
		self.out_json = ''
		self.frame_number_dict = None
		# self.target_binary = targetBinary
		self.state_move_frame_option = "y"
		self.dosChecksocketOpenNum = 300
		self.dosCheckWaitTime = 5


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

	def open_socket(self):
		global dst_ip, sniff_frame,frameInfoArr,frameShortInfoArr

		H2_CLIENT_CONNECTION_PREFACE = hex_bytes('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a')
		
		assert(ssl.HAS_ALPN)
		l = socket.getaddrinfo(dst_ip, 443, socket.INADDR_ANY, socket.SOCK_STREAM, socket.IPPROTO_TCP)
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
		ssl_sock = ssl_ctx.wrap_socket(s)
	
		# something wrong when nginx pruning 25
		ssl_sock.connect(ip_and_port)
		# print ("Fine!")
		assert('h2' == ssl_sock.selected_alpn_protocol())
		scapy.config.conf.debug_dissector = True
		ss = supersocket.SSLStreamSocket(ssl_sock, basecls=h2.H2Frame)

		# prefaceFrame = packet.Raw(H2_CLIENT_CONNECTION_PREFACE)
		# ss.send(prefaceFrame)
		return ss

	def state_move(self):
		# state_array = ['0', '1', '2', '3', '9', '10', '15']
		# state_dic = OrderedDict()
		# state_dic['0'] = []
		# state_dic['1'] = ['HE']
		# state_dic['2'] = ['SE-SE-WI']
		# state_dic['3'] = ['SE']
		# state_dic['9'] = ['HE-WE-SE-SE']
		# state_dic['10'] = ['HE-SE']
		# state_dic['15'] = ['SE-SE-WI-HE']
		# state_dic['0'] = {'1':'SE', '2':'SE', '3':'WI'}	
		# state_dic['1'] = {'9':'WI-SE-SE', '10':'SE'}	
		# state_dic['2'] = {'15':'HE'}

		state_len = len(self.state_array)
		array_index = 0

		for index, value in enumerate(self.state_array):
			if self.current_state == value:
				array_index = index

		self.past_state = self.current_state
		# return_state_move_msg = self.make_frame_array(self.state_dic[self.current_state])
		return_state_move_msg = self.state_dic[self.current_state]
		print("[+] Current_state: %s" % self.current_state)
		print("[+] Current_state msg: "),
		self.state_dic[self.current_state].show()

		array_index = (array_index + 1) % state_len
		self.current_state = self.state_array[array_index]

		# print()

		# return_state_move_msg = self.make_frame_array(state_dic[self.current_state])
		return return_state_move_msg

	def make_fuzzing_frame_seq(self, frameStrBuf):
		# global dst_ip

		# httpSchemes = ["http", "https", "ftp", "mailto", "aim", "file", "dns",
		# "fax", "imap", "ldap", "ldaps", "smb", "pop", "rtsp", "snmp",
		# "telnet", "xmpp", "chrome", "feed", "irc", "mms", "ssh",
		# "sftp", "sms", "url", "about", "sip", "h323", "tel"]

		# httpMethods = ["OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "FOOBAR"]

		# httpPaths = ["/index.html", "/index.php", "/", "index"]

		# httpImageTypes = [
		# "image/bmp", "image/cmu-raster", "image/fif", "image/florian", "image/g3fax",
		# "image/gif", "image/ief", "image/jpeg", "image/jutvision", "image/naplps", "image/pict", "image/pjpeg", "image/png",
		# "image/tiff", "image/vasa", "image/vnd.dwg", "image/vnd.fpx", "image/vnd.net-fpx", "image/vnd.rn-realflash",
		# "image/vnd.rn-realpix", "image/vnd.wap.wbmp", "image/vnd.xiff", "image/xbm", "image/xpm", "message/rfc822", "model/iges",
		# "model/vnd.dwf", "model/vrml", "music/crescendo", "text/asp", "text/css", "text/html", "text/mcf", "text/pascal",
		# "text/plain", "text/richtext", "text/scriplet", "text/sgml", "text/tab-separated-values", "text/uri-list", "text/vnd.abc",
		# "text/vnd.fmi.flexstor", "text/vnd.rn-realtext", "text/vnd.wap.wml", "text/vnd.wap.wmlscript", "text/webviewhtml",
		# "text/xml", "windows/metafile", "www/mime", "xgl/drawing", "xgl/movie",
		# ]

		# Below codes used for binary token used
		httpSchemes = self.token_db
		httpMethods = self.token_db
		httpPaths = self.token_db
		httpImageTypes = self.token_db
		dstIPArr = self.token_db


		# move_state_msg_arr: ['HE-SE-SE', DE-PE, ....]
		# send_frame_seq: 'HE-DE'
		frameDashStrArr = []
		if (str(type(frameStrBuf)) == "<type 'str'>"):
			frameDashStrArr.append(frameStrBuf)
		else:
			frameDashStrArr.extend(frameStrBuf)
	
		frameStrArr = []
		for frameEachSeq in frameDashStrArr:
			splitFrameEachSeq = frameEachSeq.split('-')
			for splitFrameEach in splitFrameEachSeq:
				frameStrArr.append(splitFrameEach)

		srv_max_frm_sz = 1<<14
		srv_hdr_tbl_sz = 4096
		srv_max_hdr_tbl_sz = 0
		srv_global_window = 1<<14
		srv_max_hdr_lst_sz = 0
	
		h2seq = h2.H2Seq()
	
		for frameValue in frameStrArr:

			if frameValue == 'DA':
				# print("??1")
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
				# max_frm_sz = (1 << 24) - 1
				# max_hdr_tbl_sz = (1 << 16) - 1
				# win_sz = (1 << 31) - 1
				# max_hdr_list_sz = (1 << 31) - 1 

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

	def make_fuzzing_packet(self, strategy):
		global dst_ip
		frameShortInfoArr_forFuzz = ['DA','HE','PR','SE','PU','PI','WI','CO','RA']
		# 0,1,2,3,4,5,6,7 -> frameShortInfoArr each frame sent

		fuzzing_frame_seq = None
		# strategy: 0 make frame field mutation
		self.txcount += 1
		print("[+] packet number : %d" % int(self.txcount))
		if strategy >= 0 and strategy <= 8:
			frameStr = frameShortInfoArr_forFuzz[strategy]
			print("[+] Single frame sent : %s" % frameStr)
			fuzzing_frame_seq = self.make_fuzzing_frame_seq(frameStr)
			# fuzzing_frame_seq.show()

		elif strategy == 9:
			frameStr = ''
			# 0 to end of List
			for i in range(0, (len(frameShortInfoArr_forFuzz))):
				frameStr += (frameShortInfoArr_forFuzz[i]+'-')
			frameStr = frameStr[:-1]
			print("[+] All frames sent : %s" % frameStr)
			fuzzing_frame_seq = self.make_fuzzing_frame_seq(frameStr)
			# fuzzing_frame_seq.show()

		elif strategy == 10:
			frameNum = random.randint(1, 1000)
			frameStr = ''
			for i in range(0, frameNum):
				frameIndex = random.randint(0, len(frameShortInfoArr_forFuzz) - 1)
				frameStr += (frameShortInfoArr_forFuzz[frameIndex]+'-')
			frameStr = frameStr[:-1]
			print("[+] Random frames sent : %s" % frameStr)
			fuzzing_frame_seq = self.make_fuzzing_frame_seq(frameStr)

		# To check crash added ping frame
		# fuzzing_frame_seq.frames.append(h2.H2Frame()/h2.H2PingFrame())
		# fuzzing_frame_seq.frames.append(h2.H2Frame()/h2.H2PingFrame())
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
			headerArgs,
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

		frameID = '00'
		jsonFileDescripter.write("\t\"state_move_frames\" : [\n")
		for index, frame in enumerate(state_move_frame.frames):
			frame_str = binascii.hexlify(raw(frame))
			try:
				jsonFileDescripter.write("\t\t{")
				jsonFileDescripter.write("\"frame_index\" : {0}, ".format(str(index)))
				jsonFileDescripter.write("\"frame_data\" : \"0x{0}\"".format(frame_str))
				if index == (len(state_move_frame.frames)-1):
					jsonFileDescripter.write("\n\t\t}\n")
					break
				jsonFileDescripter.write("\n\t\t},\n")
			except Exception as e:
				print (e)
				print ("error! 1")
				continue
		jsonFileDescripter.write("\t],\n")

		frameID = '01'
		# jsonFileDescripter.write('[+]Send Frames:\n')
		jsonFileDescripter.write("\t\"send_frames\" : [\n")
		for index, frame in enumerate(send_frame.frames):
			frame_str = binascii.hexlify(raw(frame))
			try:
				jsonFileDescripter.write("\t\t{")
				jsonFileDescripter.write("\"frame_index\" : {0},".format(str(index)))
				jsonFileDescripter.write("\"frame_data\" : \"0x{0}\"".format(frame_str))
				if index == (len(send_frame.frames)-1):
					jsonFileDescripter.write("\n\t\t}\n")
					break
				jsonFileDescripter.write("\n\t\t},\n")
			except:
				print ("error! 2")
				continue
		jsonFileDescripter.write("\t]\n")

		frameID = '02'
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
		global dst_ip, sniff_frame,frameInfoArr,frameShortInfoArr
		self.frame_number_dict = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
		self.start_write_json_logging()
		self.get_token_dict()
		self.set_strategy()

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
		self.current_state = '0'


		while True:
			state_move_frame_seq = self.state_move()
			# self.count_frames(state_move_frame_seq)

			# state_move_frame_seq_str = self.make_frame_array_to_str(state_move_frame_seq)

			for strategy in self.fuzzing_strategy:
				# total_send_frame.frames.extend(state_move_frame_seq.frames)
				fuzzing_frame_seq = self.make_fuzzing_packet(strategy)
				# total_send_frame.frames.extend(fuzzing_frame_seq.frames)
				# self.count_frames(fuzzing_frame_seq)

				# total_send_frame.show()
				# decision = input('Do you want to send it?')
				# print (decision)
				# open socket

				
				totalelapsedTime = 0
				timeOutElapsedTime = 0

				# send state_move_frame_seq and fuzzing_msg
				total_send_frame = h2.H2Seq()
				total_send_frame.frames = [
					prefaceFrame,
					firstSETTINGS,
					state_move_frame_seq,
					fuzzing_frame_seq
				]
				# total_send_frame.frames.extend(state_move_frame_seq.frames)
				# total_send_frame.frames.extend(fuzzing_frame_seq.frames)

				# emptyReceiveFrames = h2.H2Seq()
			
				# TODO: if you use in other server binary you should change below variable
				# self.dosChecksocketOpenNum = 300
				self.dosCheckWaitTime = 20
				socketArr = []
				dosChecker = False
				errorOutChecker = False

				startTime = time.time()
				now = time.localtime()
				print("[+] Dos on multiple connection checking Start %02d.%02d %02d:%02d:%02d" % (now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec))
				dosCheckStartTime = now
				for index in range(self.dosChecksocketOpenNum):
					# if int(elapsedMiliSec) > dosCheckWaitTime:
					# 	dosChecker = True
					# 	break
					interConnectionStartTime = time.time()
					try:
						sockBuf = None
						# sockOpened = open_socket()
						sockBuf = self.open_socket()
						socketArr.append(sockBuf)
						sockBuf.send(total_send_frame)
					except Exception as e:
						now = time.localtime()
						print("[!] Error occured on fuzzing multiple connection %02d:%02d:%02d" % (now.tm_hour, now.tm_min, now.tm_sec))
						# print (type(e))
						# print("Exception: {}".format(type(e).__name__))
						# print("Exception message: {}".format(e))

						if str(e) == '[Errno 0] Error':
							# print ('Errno Zero')
							print("[!] "+str(e))
						elif str(e) == '[Errno 104] Connection reset by peer':
							# print ('Errno One hundred four')
							print("[!] "+str(e))
						elif str(e) == '[Errno 111] Connection refused':
							# print ('Errno One hundred eleven')
							print("[!] "+str(e)+" fuzzer shutdown!")
							self.write_binary_file(state_move_frame_seq, fuzzing_frame_seq, dosCheckStartTime, "Shutdown")
							self.fuzzer_shutdown_error_no111()
						# print (e)
						errorOutChecker = True

					if errorOutChecker == True:
						self.write_binary_file(state_move_frame_seq, fuzzing_frame_seq, dosCheckStartTime, "Error")
						break

					interConnectionEndTime = time.time()
					endTime = time.time()

					elapsedMiliSec = endTime - startTime
					print("[+] Connection Number : %d, timeElapse %f" % (index, elapsedMiliSec))

					if int(interConnectionEndTime - interConnectionStartTime) > self.dosCheckWaitTime:
						dosChecker = True
						break
			
				if dosChecker == True:
					self.write_binary_file(state_move_frame_seq, fuzzing_frame_seq, dosCheckStartTime, "DoS")
					print("[+] DoS : yes")
				else:
					print("[+] DoS : no")

				now = time.localtime()
				print("[+] Dos on multiple connection checking End %02d:%02d:%02d" % (now.tm_hour, now.tm_min, now.tm_sec))

				print ("[+] Socket reset start")
				for index, sockValue in enumerate(socketArr):
					try:
						sockValue.send(h2.H2Frame()/h2.H2GoAwayFrame())
					except Exception as e:
						print ("[!] Error occured in %d connection" % index)
						continue

				print("[-] packet number : %d End\n" % int(self.txcount))
				time.sleep(5)

				
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

		# nodes are stored in networkx Digraph. 
		# transitions are stored in transition_dic
		with open(self.sm_json) as json_file:
			data = json.load(json_file)
			self.current_state = data["initial"]
			for s_info in data["states"]:
				state = s_info["name"]
				self.graph.add_node(state)
			
			for t_info in data["transitions"]:
				# edge = (t_info["source"], t_info["dest"])
				self.graph.add_edge(t_info["source"], t_info["dest"])
				trigger = t_info["trigger"]
				msg_sent = trigger.split("/")[0].replace(" ", "")
				msg_rtime = trigger.split("/")[-1].replace("\n", "").replace(" ", "")
				for h2msg_sent in messages:
					if msg_sent == util.h2msg_to_str(h2msg_sent):
						msg_sent = h2msg_sent
						break
				if type(msg_sent) == type(""):
					print("not maching msg error")

				self.transition_dic[t_info["source"]+"->"+t_info["dest"]] = [msg_sent, msg_rtime]

	def get_token_dict(self):
		with open("./tokenDict/total_tokens.data") as f:
			self.token_db = pickle.load(f)

	def start_write_json_logging(self):
		global jsonFileDescripter
		self.out_json = './log/'+self.init_time+'_logging.json'
		state_move_use_buf = ("\"fuzzer_version\" : \"%s\",\n" % self.fuzzer_version)
		start_date_buf = ("\"starting_time\" : \"%s\",\n" % self.init_time)
		# target_binary_buf = ("\"target_binary\" : \"%s\",\n" % self.target_binary)
		state_move_use_buf = ("\"state_move_frame_use\" : \"%s\",\n" % self.state_move_frame_option)

		jsonFileDescripter = open(self.out_json, 'w')
		jsonFileDescripter.write("{\n")
		jsonFileDescripter.write(start_date_buf)
		jsonFileDescripter.write(target_binary_buf)
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
	global dst_ip
	if len(sys.argv) < 3:
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
	http2fuzz_obj = Http2fuzz(init_time=dt,
		pcap = pcap_path,
		sm_json = json_path,
		)

	print ("- Starting Time : %s" % dt)
	print ("- Pcap Input : %s" % pcap_path)

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