import os
import sys
import subprocess
import autostop
import re

available_servers = ["apache", "nginx", "h2o"]
path_root = os.path.dirname(os.path.abspath(__file__))

def usage():
	print("[+] This script is for automatic startup for a server.")
	print("[+] Usage: python2 %s <server_type>" % (sys.argv[0]))
	print("[+] Usage: python3 %s <server_type>" % (sys.argv[0]))
	sys.exit()

if __name__ == "__main__":
	if len(sys.argv) != 2:
		usage()

	server = sys.argv[1]
	if server not in available_servers:
		print("[-] invalid server name!")
		sys.exit()

	autostop.stop_all()
	output = ""

	if server == "apache":
		output = subprocess.check_output("sudo /usr/local/httpd2/bin/httpd", shell=True)
		output = subprocess.check_output("sudo curl -k -I https://localhost", shell=True)
		output = output.decode()
		p = re.compile('server: Apache/\d+\.\d+\.\d+')
		res = p.findall(output)[0]
		server = res[8:]
	elif server == "nginx":
		output = subprocess.check_output("sudo /usr/local/nginx/nginx", shell=True)
		output = subprocess.check_output("sudo curl -k -I https://localhost", shell=True)
		output = output.decode()
		p = re.compile('server: nginx/\d+\.\d+\.\d+')
		res = p.findall(output)[0]
		server = res[8:]
	elif server == "h2o":
		print("[***INFO***] H2O runs as an worker process. Please check the running status in this shell.")
		print("[***INFO***] To kill the server, just press Ctrl + C.")
		os.system("sudo /usr/local/bin/h2o -v")
		output = subprocess.check_output("sudo /usr/local/bin/h2o -c /etc/h2oconf.conf", shell=True)

	if output.find("HTTP/2") == 0:
		print("[+] Server %s successfully started." % server)
	else:
		print("[-] Server startup failed.")


	