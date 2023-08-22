# Script for modeling given traffic testset
import sys
import os
import subprocess
import paramiko

# Server type: apache
#   - Version: httpd-2.4.29
#   - Version: httpd-2.4.33
#   - Version: httpd-2.4.56
# Server type: nginx
#   - Version: nginx-1.14.0
#   - Version: nginx-1.21.6
#   - Version: nginx-1.23.4
# Server type: h2o
#   - Version: h2o-2.2.4
#   - Version: h2o-2.3.0-beta1
#   - Version: h2o-2.3.0-beta2
server_dict = {
	'apache': ["httpd-2.4.29", "httpd-2.4.33", "httpd-2.4.56"],
	'nginx' : ["nginx-1.14.0", "nginx-1.21.6", "nginx-1.23.4"],
	'h2o'   : ["h2o-2.2.4", "h2o-2.3.0-beta1", "h2o-2.3.0-beta2"]
	}

path_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
pcap_path = ""

def install_target_server(target_ip, ts, ts_v):
	s = ""
	v = -1

	if ts == "ap":
		s = "apache"
	elif ts == 'ng':
		s = "nginx"
	elif ts == 'h2':
		s = "h2o"

	if ts_v == "o":
		v = 0
	elif ts_v == 'm':
		v = 1
	elif ts_v == 'l':
		v = 2

	if v < 0 or s == "":
		print("[-] Invalid target server [%s] with version [%s]" % (ts, ts_v))
		sys.exit()

	servername = server_dict[s][v]

	cli = paramiko.SSHClient()
	cli.set_missing_host_key_policy(paramiko.AutoAddPolicy)
	cli.connect(target_ip, port=22, username="oren", password="1")
	cmd_server_install = "python2 /home/oren/PRETT2/server_setting/autoinstall.py %s %s" % (s, servername)
	print("  >[+] Install: %s ..." % cmd_server_install)
	stdin, stdout, stderr = cli.exec_command(cmd_server_install)
	lines = stderr.readlines()
	# if len(lines) > 0: 
	# 	print("  [-] Error occured!")
	# 	print(''.join(lines))

	cmd_server_run = "python2 /home/oren/PRETT2/server_setting/autostart.py %s" % (s)
	print("  >[+] Run: %s ..." % cmd_server_run)
	stdin, stdout, stderr = cli.exec_command(cmd_server_run)
	lines = stdout.readlines()
	if lines[-1].find("successfully started.") > 0:
		print("  >[+] Success.")
	else:
		lines = stderr.readlines() 
		print("  >[-] -----------------------------------")
		print("  >[-] [DEBUG] Output from remote server")
		print(''.join(lines))
		print('  >[-] -----------------------------------')
	cli.close()

def test_target_server(target_ip, traffic):
	prett2_path = path_root+"/prett2/prett2.py"
	proc = subprocess.Popen(
		['python3', prett2_path, target_ip, traffic],
		stdout=subprocess.PIPE, stderr = subprocess.PIPE)

	while True:
		output = str(proc.stdout.readline(), 'utf-8')
		if output == '' and proc.poll() is not None:
			break
		if output != '':
			print("\t", output.strip())

	while True:
		output = str(proc.stderr.readline(), 'utf-8')
		if output == '' and proc.poll() is not None:
			break
		if output != '':
			print("\t[E]", output.strip())

	rc = proc.poll()
	return rc


def get_target_traffic(target_server):
	global pcap_path
	pcap_list = []
	pcap_path = path_root+"/prett2/pcapFile/%s_testset/" % target_server
	for dirpath, _, filenames in os.walk(pcap_path):
		for f in filenames:
			pcap_list.append(os.path.abspath(os.path.join(dirpath, f)))
	return pcap_list

def info():
	print("[USAGE]")
	print("- $ sudo python3 %s [target_ip] [target_server]" % sys.argv[0])
	print("- [target_ip] string; IP address or URL without https://")
	print("- [target_server] server type to test in pcapFile/ dataset")
	print("-      ex) apache, h2o, nginx")
	sys.exit()

if __name__ == "__main__":
	if len(sys.argv) != 3:
		info()

	target_ip = sys.argv[1]
	target_server = sys.argv[2]

	traffics = get_target_traffic(target_server)
	if len(traffics) == 0:
		print("[-] No pcap found in path: \n - %s" % pcap_path)
	else:
		print("[+] %d pcap files found in path: \n - %s" % (len(traffics), pcap_path))
	
	testidx = 1
	for traffic in traffics:
		traffic_name = traffic.split("/")[-1]
		print("  [%d/%d] Testing [...]/%s ..." % (testidx, len(traffics), traffic_name))

		# Get target server / client information (ex: ap_l_op_l)
		traffic_spt = traffic_name.replace(".pcapng", "").split("_")
		ts = traffic_spt[0]
		ts_v = traffic_spt[1]
		tc = traffic_spt[2]
		tc_v = traffic_spt[3]

		install_target_server(target_ip, ts, ts_v)
		rc = test_target_server(target_ip, traffic)
		print(rc)

		testidx += 1

