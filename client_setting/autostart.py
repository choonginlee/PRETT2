import os
import sys
import subprocess

available_clients = ["chromium", "firefox", "opera"]
firefox_versions = ["56", "60", "111"]
path_root = os.path.dirname(os.path.abspath(__file__))

def usage():
	print("[+] This script is for automatic startup for a client.")
	print("[+] It automatically runs wireshark capture via interface ens38.")
	print("[+] For firefox, please specify version. (56, 60, 111)")
	print("[+] Usage: python %s <client_type> [firefox_version]" % (sys.argv[0]))
	print("[!] Do not use sudo!")
	sys.exit()

if __name__ == "__main__":
	if os.geteuid() == 0:
		print("[-] Do not run with sudo.")
		sys.exit()

	if len(sys.argv) < 2:
		usage()

	client = sys.argv[1]
	version = ""
	if client not in available_clients:
		print("[-] Invalid client name!")
		sys.exit()

	if client == "firefox":
		if len(sys.argv) != 3:
			print("[-] Please specify firefox version.")
			print(" - %s" % firefox_versions)
			sys.exit()
		if sys.argv[2] not in firefox_versions:
			print("[-] Invalid firefox version!")
			print(" - %s" % firefox_versions)
			sys.exit()
		version = sys.argv[2]

	output = ""

	output = subprocess.Popen("sudo wireshark -k -i ens38", shell=True)

	os.system("export SSLKEYLOGFILE=$HOME/browser_sslkey.log")
	if client == "chromium":
		os.system("chromium-browser --version")
		os.system("chromium-browser --incognito")
	elif client == "firefox":
		os.chdir("%s/" % path_root)
		if version == firefox_versions[-1]:
			os.system("firefox --version")
			os.system("firefox --private-window")
		else:
			os.system("./firefox%s/firefox --version" % version)
			os.system("./firefox%s/firefox --private-window" % version)
	elif client == "opera":
		os.system("opera --version")
		os.system("opera --incognito")
	


	