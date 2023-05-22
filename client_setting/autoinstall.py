# Script for client setting
import os
import sys

available_clients = {}
available_clients["chromium"] = ["61", "67", "111"]
available_clients["firefox"] = ["56", "60", "111"]
available_clients["opera"] = ["48", "53", "97"]
path_root = os.path.dirname(os.path.abspath(__file__))
cwd = os.getcwd()

def usage():
	print("[+] This script is for automatic setup for a client.")
	print("[+] Usage: python %s <client_type> <version>" % (sys.argv[0]))
	print("[+] Example: python %s chromium 61" % (sys.argv[0]))
	print("Available clients:")
	for client in available_clients.keys():
		print("Client type: %s" % client)
		for version in available_clients[client]:
			print("  - Version: %s" % version)
	print("[INFO] firefox is not required to be installed!")
	sys.exit()

def install_chromium(version):
	print("Installing chromium [%s] ..." % version)
	print("Removing previous versions ...")
	os.chdir("%s/" % path_root)
	os.system("sudo apt-get remove -y --purge chromium-browser chromium-codecs-ffmpeg-extra > /dev/null")
	print("Installing ...")
	if version == available_clients["chromium"][-1]:
		os.system("sudo apt-get install -y chromium-browser > /dev/null")
	else:
		os.system("sudo dpkg -i chromium-codecs-ffmpeg-extra_%s*.deb > /dev/null" % version)
		os.system("sudo dpkg -i chromium-codecs-ffmpeg_%s*.deb > /dev/null" % version)
		os.system("sudo dpkg -i chromium-browser_%s*.deb > /dev/null" % version)

	# print("Extracting code ...")
	# os.chdir("%s/apache/" % path_root)
	# os.system("sudo rm -r %s" % version)
	# os.system("sudo tar -xzf %s.tar.gz" % version)
	# print("Configuring ...")
	# os.chdir("%s/apache/%s" % (path_root, version))
	# os.system("sudo ./configure --prefix=/usr/local/httpd2 --enable-so --enable-ssl --enable-http2 > /dev/null")
	# print("Installing ...")
	# os.system("sudo make -j > /dev/null")
	# os.system("sudo make install > /dev/null")
	# os.system("sudo cp %s/apache/httpd.conf /usr/local/httpd2/conf/httpd.conf" % path_root)
	# os.system("sudo cp %s/apache/httpd-ssl.conf /usr/local/httpd2/conf/extra/httpd-ssl.conf" % path_root)
	# os.system("sudo mkdir /usr/share/nginx")
	# os.system("sudo mkdir /usr/share/nginx/html/")
	# os.system("sudo cp %s/html/* /usr/share/nginx/html/" % path_root)

def install_firefox(version):
	print("[INFO] just run firefox in the directory.")

def install_opera(version):
	print("Installing opera [%s] ..." % version)
	print("Removing previous versions ...")
	os.chdir("%s/" % path_root)
	os.system("sudo apt-get remove -y --purge opera-stable > /dev/null")
	os.system("sudo snap remove opera > /dev/null")
	print("Installing ... (Type [ENTER])")
	if version == available_clients["opera"][-1]:
		os.system("sudo snap install opera")
	else:
		os.system("sudo dpkg -i opera-stable_%s.0*_amd64.deb > /dev/null" % version)

if __name__ == "__main__":
	if len(sys.argv) != 3:
		usage()

	client = sys.argv[1]
	version = sys.argv[2]

	if client not in available_clients.keys():
		print("[-] invalid client name!")
		sys.exit()
	if version not in available_clients[client]:
		print("[-] invalid version name for %s!" % client)
		sys.exit()

	print("[+] We got the client name and version ... Looks good!")
	if client == "chromium":
		install_chromium(version)
	elif client == "firefox":
		install_firefox(version)
	elif client == "opera":
		install_opera(version)

	print("[+] All jobs done.")


# os.system("sudo apt-get update")