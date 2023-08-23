import os

def stop_all():
	os.system("sudo /usr/local/httpd2/bin/httpd -k stop > /dev/null")
	os.system("sudo /usr/local/nginx/nginx -s stop > /dev/null")
	os.system("sudo killall -9 perl")
	os.system("sudo killall -9 h2o")

	print("[+] All servers are stopped.")

if __name__ == "__main__":
	stop_all()
