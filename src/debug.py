###################################################################
#
#                      Python Network Tunnel
#                        Log and Debugging
#
# Author: Nir Haike
#
###################################################################

import datetime
import threading

MUTEX = threading.Lock()

VERBOSE = 0
WARNING = 1
ERROR = 2

messages = []

def get_timestamp(time):
	return datetime.datetime.fromtimestamp(time).strftime("%d/%m/%y %H:%M:%S ")

def get_current_timestamp():
	return datetime.datetime.now().strftime("%d/%m/%y %H:%M:%S ")

def debug(msg="", level=VERBOSE):
	MUTEX.acquire()
	# add the timestamp to the message
	line = get_current_timestamp() + msg
	# print the line
	print(line)
	# add the message to the log list
	messages.append((line, level))
	MUTEX.release()

def generate_html_log(max=100, newline="<br>"):
	log = ""
	for message in messages[-max:]:
		if message[1] == ERROR:
			log += "<font color=\"#aa2020\">%s</font>%s" % (escape_string(message[0]), newline)
		elif message[1] == WARNING:
			log += "<font color=\"#d88c2f\">%s</font>%s" % (escape_string(message[0]), newline)
		else:
			log += "<font color=\"#202020\">%s</font>%s" % (escape_string(message[0]), newline)
	return log

def generate_plain_log():
	return "\r\n".join([msg[0] for msg in messages])

def escape_string(st):
	return st.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")