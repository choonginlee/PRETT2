# Read pcaps
import os, sys
import glob
import scapy.contrib.http2 as h2
from scapy.utils import rdpcap
from fastDamerauLevenshtein import damerauLevenshtein

frameInfoArr = ['DATA', 'HEADERS', 'PRIORITY', 'RST_STREAM', 'SETTINGS', 'PUSHPROMISE', 'PING', 'GO_AWAY',
                'WINDOW_UPDATE', 'CONTINUATION']
frameShortInfoArr = ['D', 'H', 'T', 'R', 'S', 'P', 'I', 'G', 'W', 'C']

def h2msg_to_str(h2msg):
    frameStr = ''
    # h2msg.show()
    for h2frame in h2msg.frames:
        # h2frame.show()
        if hasattr(h2frame, 'type'):
            frameStr += (frameShortInfoArr[h2frame.type])
    return frameStr


def h2msg_from_pcap(f):
    # Extract all http2 messages from pcapfile and return an array of http2 messages in scapy form
    h2msg_arr = []
    with open(f, 'rb') as f:
        pcapng = rdpcap(f)
        frameid = 1
        for buf in pcapng:  # for each http2 message
            # tmpbuf = h2.H2Seq(buf)
            # print(type(tmpbuf))
            # tmpbuf.show()

            http2raw = buf.load[64:]
            # handle magic
            if http2raw[:24] == b'\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a':
                http2raw = http2raw[24:] 
            tmpseq = h2.H2Seq(http2raw)
            h2msg_arr.append(tmpseq)
            frameid += 1
    # print("  [+] Parsing done! (Total %s messages.)" % len(h2msg_arr))

    msgid = 1
    msg_str = ""
    # Debugging http2 messages frame by frame
    # print("  [DBG] messages (shortened)")
    for h2msg in h2msg_arr:
        h2msg_str = h2msg_to_str(h2msg)
        # print("    [ ] h2msg %d: %s " % (msgid, h2msg_str))
        msgid += 1
        msg_str += h2msg_str

    # [NOTE] An HTTP2 message is a sequence of frames.
    return h2msg_arr, msg_str



if __name__ == "__main__":
	h2msg_dict = {}
	group_dict = {}
	for f in glob.glob(sys.argv[1]+"*/*.pcapng"):
		h2msg_arr, h2msg_str = h2msg_from_pcap(os.path.abspath(f))
		pcap = f.split("/")[-1]
		h2msg_dict[pcap] = h2msg_str
	for k1 in h2msg_dict.keys():
		for k2 in h2msg_dict.keys():
			if k1 == k2:
				continue
			else:
				sim = damerauLevenshtein(h2msg_dict[k1], h2msg_dict[k2], similarity=True)
				if sim > 0.8:
					if (k1.find("ff") > 0 and k2.find("ff") < 0) or (k1.find("ff") < 0 and k2.find("ff") > 0):
						print("firefox and non-firefox!")
					print(k1, k2, sim)

