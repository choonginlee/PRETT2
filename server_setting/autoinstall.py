# Script for server setting
import os
import sys

available_servers = {}
available_servers["apache"] = ["httpd-2.4.29", "httpd-2.4.33", "httpd-2.4.56"]
available_servers["nginx"] = ["nginx-1.14.0", "nginx-1.21.6", "nginx-1.23.4"]
available_servers["h2o"] = ["h2o-2.2.4", "h2o-2.3.0-beta1", "h2o-2.3.0-beta2"]
path_root = os.path.dirname(os.path.abspath(__file__))
cwd = os.getcwd()

def usage():
	print("[+] This script is for automatic setup for a server.")
	print("[+] Usage: python %s <server_type> <version>" % (sys.argv[0]))
	print("[+] Example: python %s apache httpd-2.4.29" % (sys.argv[0]))
	print("Available servers:")
	for server in available_servers.keys():
		print("Server type: %s" % server)
		for version in available_servers[server]:
			print("  - Version: %s" % version)

	sys.exit()

def install_apache(version):
	print("Installing apache [%s] ..." % version)
	print("Installing prerequisite ...")
	os.system("sudo apt-get update > /dev/null")
	os.system("sudo apt-get -y install build-essential curl libpcre3-dev zlib1g-dev libssl1.0-dev libnghttp2-dev libapr1-dev libaprutil1-dev > /dev/null")
	print("Extracting code ...")
	os.chdir("%s/apache/" % path_root)
	os.system("sudo rm -r %s" % version)
	os.system("sudo tar -xzf %s.tar.gz" % version)
	print("Configuring ...")
	os.chdir("%s/apache/%s" % (path_root, version))
	os.system("sudo ./configure --prefix=/usr/local/httpd2 --enable-so --enable-ssl --enable-http2 > /dev/null")
	print("Installing ...")
	os.system("sudo make -j > /dev/null")
	os.system("sudo make install > /dev/null")
	os.system("sudo cp %s/apache/httpd.conf /usr/local/httpd2/conf/httpd.conf" % path_root)
	os.system("sudo cp %s/apache/httpd-ssl.conf /usr/local/httpd2/conf/extra/httpd-ssl.conf" % path_root)
	os.system("sudo mkdir /usr/share/nginx")
	os.system("sudo mkdir /usr/share/nginx/html/")
	os.system("sudo cp %s/html/* /usr/share/nginx/html/" % path_root)

def install_nginx(version):
	print("Start installing nginx [%s] ..." % version)
	print("Installing prerequisite ...")
	os.system("sudo apt-get update > /dev/null")
	os.system("sudo apt-get -y install build-essential curl libpcre3-dev zlib1g-dev libssl1.0-dev > /dev/null")
	print("Extracting code ...")
	os.chdir("%s/nginx" % path_root)
	os.system("sudo rm -r %s" % version)
	os.system("sudo tar -xzf %s.tar.gz" % version)
	print("Configuring ...")
	os.chdir("%s/nginx/%s" % (path_root, version))
	os.system("sudo ./configure --sbin-path=/usr/local/nginx/nginx --conf-path=/usr/local/nginx/nginx.conf --pid-path=/usr/local/nginx/nginx.pid --with-http_ssl_module --with-stream --with-mail=dynamic --with-cc-opt=\"-g\" --with-debug --with-http_v2_module > /dev/null")
	print("Installing ...")
	os.system("sudo make > /dev/null")
	os.system("sudo make install > /dev/null")
	os.system("sudo cp %s/nginx/nginx.conf /usr/local/nginx/nginx.conf" % path_root)
	os.system("sudo cp %s/html/* /usr/local/nginx/html/" % path_root)

def install_h2o(version):
	tarversion = version.replace("h2o-", "v")
	print("Installing h2o [%s] ..." % version)
	print("Installing prerequisite ...")
	os.system("sudo apt-get update > /dev/null")
	os.system("sudo apt-get -y install cmake > /dev/null")
	print("Extracting code ...")
	os.chdir("%s/h2o" % path_root)
	os.system("sudo rm -r %s" % version)
	os.system("sudo tar -xzf %s.tar.gz" % tarversion)
	print("Configuring ...")
	os.chdir("%s/h2o/%s" % (path_root, version))
	os.system("sudo mkdir build")
	os.chdir("%s/h2o/%s/build" % (path_root, version))
	os.system("sudo cmake .. > /dev/null")
	print("Installing ...")
	os.system("sudo make > /dev/null")
	os.system("sudo make install > /dev/null")
	os.system("sudo cp %s/h2o/h2oconf.conf /etc/h2oconf.conf" % path_root)
	os.system("sudo mkdir /usr/share/nginx")
	os.system("sudo mkdir /usr/share/nginx/html/")
	os.system("sudo cp %s/html/* /usr/share/nginx/html/" % path_root)

if __name__ == "__main__":
	if len(sys.argv) != 3:
		usage()

	server = sys.argv[1]
	version = sys.argv[2]

	if server not in available_servers.keys():
		print("[-] invalid server name!")
		sys.exit()
	if version not in available_servers[server]:
		print("[-] invalid version name for %s!" % server)
		sys.exit()

	print("[+] We got the server name and version ... Looks good!")
	if server == "apache":
		install_apache(version)
	elif server == "nginx":
		install_nginx(version)
	elif server == "h2o":
		install_h2o(version)

	print("[+] All jobs done.")


# os.system("sudo apt-get update")