import scapy.contrib.http2 as h2


def abnormal_checker(pm, self_state, vs_payload, parent_state_no):
	isAbnormal = ""
	vs_payload_arr = vs_payload.split('/')
	sent_frame_seq = vs_payload_arr[0]
	parent_state = pm.state_list.get_state_by_num(parent_state_no)
	# based on RFC 7541 response code index     
		  # | 8     | :status                     | 200           |
	   #    | 9     | :status                     | 204           |
	   #    | 10    | :status                     | 206           |
	   #    | 11    | :status                     | 304           |
	   #    | 12    | :status                     | 400           |
	   #    | 13    | :status                     | 404           |
	   #    | 14    | :status                     | 500    	    |
	# responseCodeArr = ['index     = 8', 'index     = 9', 'index     = 10', 'index     = 11', 
	# 'index     = 12', 'index     = 13', 'index     = 14']
	responseCodeArr = [':status 200', ':status 204', ':status 206', ':status 304', 
	':status 400', ':status 404', ':status 500']

	max_hdr_tbl_sz = (1 << 16) - 1
	srv_tblhdr = h2.HPackHdrTable(dynamic_table_max_size=max_hdr_tbl_sz, dynamic_table_cap_size=max_hdr_tbl_sz)

	print("[+] abnormal check in state : %s, payload : %s" % (self_state, sent_frame_seq))
	
	# if parent is abnormal, son == abnormal
	if parent_state.get_is_abnormal() == True:
		self_state.set_abnormal()
		isAbnormal = " parent ab"
		print("[+] abnormal reason : %s" % isAbnormal)
		return isAbnormal
	
	# Rule 1
	if sent_frame_seq.count("PU") > 1:
		self_state.set_abnormal()
		isAbnormal = " PU ab"
		print("[+] abnormal reason : %s" % isAbnormal)
		return isAbnormal

	# Rule 2
	elif sent_frame_seq.count("SE") > 0 or sent_frame_seq.count("WI") > 1 or sent_frame_seq.count("PR") > 1:
		self_state.set_abnormal()
		isAbnormal = " setup ab"
		print("[+] abnormal reason : %s" % isAbnormal)
		return isAbnormal

	# Rule 3
	elif sent_frame_seq.count("HE") > 0:

		stream_txt = {}
		stream_data = {}

		for frame in self_state.h2msg_sent.frames:
			if frame.type == h2.H2HeadersFrame.type_id:
				stream_txt[frame.stream_id] = srv_tblhdr.gen_txt_repr(frame)

		if len(stream_txt) < 1:
			return isAbnormal

		send_h2_frame_info_buf = stream_txt[1]
		send_h2_frame_info_arr = send_h2_frame_info_buf.splitlines()

		for send_h2_frame_info_line in send_h2_frame_info_arr:
			for responseIndexValue in responseCodeArr:
				if responseIndexValue in send_h2_frame_info_line:
					self_state.set_abnormal()
					isAbnormal = " HE ab"
					return isAbnormal

	return isAbnormal