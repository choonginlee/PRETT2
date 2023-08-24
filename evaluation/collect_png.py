import os
import sys

path_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
path_output = path_root+"/output_pngonly"

def collect_finpng_from_outputs(target_path):
	path = path_root+"/"+target_path
	output_dir_list = []
	png_list = []
	for (root, dirs, files) in os.walk(path):
		# print("# root : " + root)
		if len(dirs) > 0:
			for dir_name in dirs:
				if dir_name.find("output_") == 0:
					sv = dir_name.split("_")[1]
					if sv == "ap" or sv == "ng" or sv == "h2":
						output_dir_list.append(os.path.abspath(os.path.join(root, dir_name)))
						# output_dir_list.append(root+dir_name)
					else:
						continue

	for path in output_dir_list:
		for dirpath, _, filenames in os.walk(path):
			for f in filenames:
				if f.find("(fin).png") < 0:
					continue
				png_list.append(os.path.abspath(os.path.join(dirpath, f)))


	for path in png_list:
		dirname = path.split("/")[-3]
		filename = path.split("/")[-1]
		sv = dirname.split("_")[1]
		sv_v = dirname.split("_")[2]
		cl = dirname.split("_")[3]
		cl_v = dirname.split("_")[4]
		lv = filename.split("(fin)")[0]
		target_name = "%s_%s_%s_%s_%s" % (sv, sv_v, cl, cl_v, lv)
		path = path.replace("(", "\\(").replace(")", "\\)")
		os.system("cp %s %s/%s" % (path, path_output, target_name))

	print("done.")

def info():
	print("[USAGE]")
	print("- $ sudo python3 %s [dirpath]" % sys.argv[0])
	print("- [dirpath] path : path of root directory that contain more than one output directories")
	sys.exit()

if __name__ == "__main__":
	if len(sys.argv) != 2:
		info()

	os.system("mkdir %s" % path_output)
	dirpath = sys.argv[1]
	collect_finpng_from_outputs(dirpath)