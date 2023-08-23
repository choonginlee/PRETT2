# -*- coding: UTF-8 -*-
# import dpkt
import re

import scapy.contrib.http2 as h2
from scapy.layers.inet import IP
# import scapy.layers.inet4 as inet4
from scapy.utils import rdpcap

frameInfoArr = ['DATA', 'HEADERS', 'PRIORITY', 'RST_STREAM', 'SETTINGS', 'PUSHPROMISE', 'PING', 'GO_AWAY',
                'WINDOW_UPDATE', 'CONTINUATION', 'RAW']
frameShortInfoArr = ['DA', 'HE', 'PR', 'RS', 'SE', 'PU', 'PI', 'GO', 'WI', 'CO', 'RA']
TIMEOUT = 5


############# GENERAL #############
class Tee(object):
    def __init__(self, *files):
        self.files = files

    def write(self, obj):
        for f in self.files:
            f.write(obj)
            f.flush()  # If you want the output to be visible immediately

    def flush(self):
        for f in self.files:
            f.flush()


def cmp(a, b):
    return (a > b) - (a < b)


def compare_ordered_dict(dict1, dict2):
    for i, j in zip(dict1.items(), dict2.items()):
        if cmp(i, j) != 0:
            return False
    # print("compare_ordered_dict(): Two dict is same")
    # print(dict1)
    # print("---")
    # print(dict2)
    return True


def ip_checker(string):
    # ex) https://www.geeksforgeeks.org/python-check-url-string/
    # determines if string is ip address
    regex = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    # regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex, string)
    if len(url) == 0:
        return False  # non-ip address
    else:
        return True  # ip adress


############# HTTP2 #############
# def prn_http2(packet):
# 	global sniff_frame
# 	sniff_frame = h2.H2Frame(str(packet))

def h2msg_from_pcap(f):
    # Extract all http2 messages from pcapfile and return an array of http2 messages in scapy form
    print("\n[STEP 2] Parsing http2 messages from pcapfile %s ..." % f)
    # Get ip to gather client message 
    client_ip = None
    with open(f, 'rb') as f_pre:
        pcapng = rdpcap(f_pre)
        for buf in pcapng:
            http2raw = buf.load[64:]
            # Got client's message
            if http2raw[:24] == b'\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a':
                client_ip = buf.load[16:20]
                break

    h2msg_arr = []
    with open(f, 'rb') as f:
        pcapng = rdpcap(f)
        frameid = 1
        for buf in pcapng:  # for each http2 message
            if buf.load[16:20] != client_ip:
                continue

            http2raw = buf.load[64:]
            # handle magic
            if http2raw[:24] == b'\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a':
                http2raw = http2raw[24:] 
            tmpseq = h2.H2Seq(http2raw)
            h2msg_arr.append(tmpseq)
            frameid += 1
    print("  [+] Parsing done! (Total %s messages.)" % len(h2msg_arr))

    msgid = 1
    # Debugging http2 messages frame by frame
    # print("  [DBG] messages (shortened)")
    for h2msg in h2msg_arr:
        h2msg_str = h2msg_to_str(h2msg)
        print("    - h2msg %d: %s" % (msgid, h2msg_str))
        msgid += 1

    # [NOTE] An HTTP2 message is a sequence of frames.
    return h2msg_arr


def h2frame_from_sniff(packet):
    sniff_frame = h2.H2Frame(str(packet))
    return sniff_frame


def framestr_to_h2seq(frameStrBuf):
    global dst_ip
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

    # frameArr = []
    srv_max_frm_sz = 1 << 14
    srv_hdr_tbl_sz = 4096
    srv_max_hdr_tbl_sz = 0
    srv_global_window = 1 << 14
    srv_max_hdr_lst_sz = 0

    h2seq = h2.H2Seq()
    # H2DataFrame
    # H2HeadersFrame
    # H2SettingsFrame
    # H2PushPromiseFrame
    # H2PingFrame
    # H2PriorityFrame
    # H2ResetFrame
    # H2GoAwayFrame
    # H2WindowUpdateFrame
    # H2ContinuationFrame

    for frameValue in frameStrArr:
        if frameValue == 'DA':
            dataFrameBuf = h2.H2Frame() / h2.H2DataFrame()
            dataFrameBuf.stream_id = 1
            h2seq.frames.append(dataFrameBuf)

        elif frameValue == 'HE':
            msg = "GET"
            args = "/index.html"

            headerArgs = ":method " + msg + "\n\
			:path " + args + "\n\
			:authority " + dst_ip + "\n\
			:scheme https\n\
			accept-encoding: gzip, deflate\n\
			accept-language: ko-KR\n\
			accept: text/html\n\
			user-agent: Scapy HTTP/2 Module\n"

            tblhdr = h2.HPackHdrTable()
            qry_frontpage = tblhdr.parse_txt_hdrs(
                headerArgs,
                stream_id=1,
                max_frm_sz=srv_max_frm_sz,
                max_hdr_lst_sz=srv_max_hdr_lst_sz,
                is_sensitive=lambda hdr_name, hdr_val: hdr_name in ['cookie'],
                should_index=lambda x: x in [
                    'x-requested-with',
                    'user-agent',
                    'accept-language',
                    ':authority',
                    'accept',
                ]
            )
            h2seq.frames.append(qry_frontpage.frames[0])

        elif frameValue == 'SE':
            settingFrameBuf = h2.H2Frame() / h2.H2SettingsFrame()
            max_frm_sz = (1 << 24) - 1
            max_hdr_tbl_sz = (1 << 16) - 1
            win_sz = (1 << 31) - 1
            settingFrameBuf.settings = [
                h2.H2Setting(id=h2.H2Setting.SETTINGS_ENABLE_PUSH, value=0),
                h2.H2Setting(id=h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=win_sz),
                h2.H2Setting(id=h2.H2Setting.SETTINGS_HEADER_TABLE_SIZE, value=max_hdr_tbl_sz),
                h2.H2Setting(id=h2.H2Setting.SETTINGS_MAX_FRAME_SIZE, value=max_frm_sz),
            ]
            h2seq.frames.append(settingFrameBuf)
        elif frameValue == 'PU':
            h2seq.frames.append(h2.H2Frame() / h2.H2PushPromiseFrame())

        elif frameValue == 'PI':
            h2seq.frames.append(h2.H2Frame() / h2.H2PingFrame())

        elif frameValue == 'PR':
            h2seq.frames.append(h2.H2Frame() / h2.H2PriorityFrame())

        elif frameValue == 'RS':
            h2seq.frames.append(h2.H2Frame() / h2.H2ResetFrame())

        elif frameValue == 'GO':
            h2seq.frames.append(h2.H2Frame() / h2.H2GoAwayFrame())

        elif frameValue == 'WI':
            h2seq.frames.append(h2.H2Frame() / h2.H2WindowUpdateFrame())

        elif frameValue == 'CO':
            h2seq.frames.append(h2.H2Frame() / h2.H2ContinuationFrame())

    return h2seq


def h2msg_to_str(h2msg):
    frameStr = ''
    # h2msg.show()
    # Case 1: h2msg is list of HTTP/2 Frame Sequence in Scapy (multiplexed message sequence)
    if type(h2msg) is type([]):
        for h2msg_in_list in h2msg:
            for h2frame in h2msg_in_list.frames:
                if hasattr(h2frame, 'type') and hasattr(h2frame, 'len'):
                    frameStr += (frameShortInfoArr[h2frame.type] + '(%x)' % h2frame.len + '-')
            frameStr = frameStr[:-1]
            frameStr += ' | '
        frameStr = frameStr[:-3]
    # Case 2: h2msg is HTTP/2 Frame Sequence in Scapy
    else:
        for h2frame in h2msg.frames:
            # h2frame.show()
            if hasattr(h2frame, 'type'):
                frameStr += (frameShortInfoArr[h2frame.type] + '(%x)' % h2frame.len + '-')
        frameStr = frameStr[:-1]
    return frameStr

def check_h2_response(ans, msg=None):
    # Check if h2 message received from sr.

    # Detailed information about ans
    # ans is a list of QueryAnswer tuple
    # therefore, a Queryanswer is (Query (s), Answer (r))
    check = False
    # print(ans)
    # FUNCTION 1: checking h2 message presence
    if msg is None:
        for a in ans:
            # print("-----")
            # print(a)
            # print("-----")
            r = a[1] # received packet
            if r.haslayer(h2.H2Seq):
                check = True
    # FUNCTION 2 : checking specific message
    else:           
        for a in ans:
            # print("-----")
            # print(a)
            # print("-----")
            r = a[1] # received packet
            if msg in h2msg_to_str(r):
                check = True
    return check