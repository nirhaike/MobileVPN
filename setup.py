import time
import zipfile
import os
import sys

class InstallBar(object):

	def __init__(self, name, jobs):
		self.name = name
		self.jobs = jobs
		self.curr_jobs = 0
		self.done = False
		self.start_message()

	def progress(self, new_jobs):
		if self.done:
			return
		self.curr_jobs += new_jobs
		if self.curr_jobs > self.jobs:
			self.curr_jobs = self.jobs
		full = int((self.curr_jobs * 1.0 / self.jobs) * 50)
		blank = 50 - full
		st_percent = str(int(self.curr_jobs * 100 / self.jobs))
		st = "\rProgress: [{}%] [" + "#" * full + "." * blank + "]"
		st = st.format("".ljust(3-len(st_percent)) + st_percent)
		print st,
		if self.curr_jobs >= self.jobs:
			self.finish()
			self.done = True

	def finish(self):
		message = self.end_message()
		print message + " " * (70 - len(message)) + "\n"

	def start_message(self):
		print "{0}...".format(self.name)

	def end_message(self):
		return "\r[Done {0}]".format(self.name)


def printWelcome():
	print """
	     __  __       _     _ _   __      _______  _   _ 
	    |  \/  |     | |   (_) |  \ \    / /  __ \| \ | |
	    | \  / | ___ | |__  _| | __\ \  / /| |__) |  \| |
	    | |\/| |/ _ \| '_ \| | |/ _ \ \/ / |  ___/| . ` |
	    | |  | | (_) | |_) | | |  __/\  /  | |    | |\  |
	    |_|  |_|\___/|_.__/|_|_|\___| \/   |_|    |_| \_|\n"""
	print "2017 Copyright (C) Nir Haike\n"

def start():
	# start message
	printWelcome()
	# python version check
	if not sys.version_info[0] == 2 or not sys.version_info[1] == 7:
		print "[Error] You are running Python %d.%d, please run the script with Python 2.7."\
			 % (sys.version_info[0], sys.version_info[1])
		close_installer()
	# make sure we have all the dependencies
	check_dependencies()
	# extract server files
	if os.path.isdir("src/"):
		print "Extracting Server files...\nServer files already exists.\n"
	else:
		extract_files()
	# configuration
	try:
		from src import config
	except:
		print "[Error] Invalid server files..."
		close_installer()
	cfg = config.Config("properties.cfg")
	cfg.read()
	# get username from the user
	print "Please enter your username for the web user interface:"
	username = raw_input(">>> ")
	if len(username) == 0:
		username == "admin"
	# get password from the user
	print "Please enter your password:"
	password = raw_input(">>> ")
	if len(password) == 0:
		password == "@mobileVPN"
	print "Please enter your encryption key (leave empty for the default key):"
	key = raw_input(">>> ")
	if len(key) == 0:
		key = "qNX2tvW06TbkkXNb"
	print ""
	# progress bar
	i = InstallBar("Writing configuration file", 5)
	# update the configuration
	cfg["username"] = username
	i.progress(1)
	time.sleep(0.1)
	cfg["password"] = password
	i.progress(1)
	time.sleep(0.05)
	if len(key) > 0:
		cfg["key"] = key
		time.sleep(0.05)
	i.progress(1)
	cfg.pack()
	i.progress(1)
	cfg.write({})
	i.progress(1)
	# done setup
	print "[Info] Setup done successfully."
	print "Server usage: 'python main.py'"
	close_installer()

def check_dependencies():
	try:
		import scapy
		print "[Dependency] Scapy was found on your computer."
	except:
		print "[Error] Dependency 'scapy' is missing, please install it first."
		close_installer()
	try:
		import Crypto
		print "[Dependency] pycrypto was found on your computer."
	except:
		print "[Error] Dependency 'pycrypto' is missing, please install it first."
		close_installer()
	print ""

def extract_files():
	try:
		archive = zipfile.ZipFile("MobileVPN.zip", "r")
	except:
		print "[Error] Cannot find the Server files. Please redownload MobileVPN."
		close_installer()
	files = archive.namelist()
	i = InstallBar("Extracting Server files", len(files))
	for f in files:
		archive.extract(f, "")
		i.progress(1)

def close_installer():
	try:
		input = raw_input
	except NameError:
		pass
	print "\nPress any key to continue..."
	raw_input()
	sys.exit()

if __name__ == "__main__":
	start()
