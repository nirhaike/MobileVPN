###################################################################
#
#                      Python Network Tunnel
#                      Configuration Handler
#
# Author: Nir Haike
#
###################################################################

import traceback
import random
import hashlib
import urllib
import socket
import string
import debug
import sys
import os

from service import ServiceThread


class Config(object):
	"""
		Contains the server's configuration properties.
	"""

	USERNAME = ""
	PASSWORD = ""

	KEY = "qNX2tvW06TbkkXNb"

	SERVER_PORT = 1234

	MAX_CLIENTS = 10

	MAX_LOG = 50
	
	DISCONNECT_CLIENT_TIME = 300
	DISCONNECT_SESSION_TIME = 30

	PCAP_FILE_SIZE = 1000000

	PCAP_TRAFFIC = True
	ALLOW_UNSECURE_CONNECTION = True

	APPLICATIONS_LIST = True

	SECURE_CONNECTIONS = False

	BLOCKED_IPS = []

	def __init__(self, fn):
		self.fn = fn
		self.data = {}

	def read(self):
		"""
			This function reads the configuration from the properties file.
		"""
		try:
			f = open(self.fn, "r")
			lines = f.read().split("\n")
			f.close()
			self.BLOCKED_IPS = []
			for line in lines:
				if len(line) > 0 and line[0] != "!" and "=" in line:
					arg, val = line.split("=")
					arg = arg.strip(' \t\n\r')
					val = val.strip(' \t\n\r')
					self.data[arg] = val
					if arg == "blocks" and len(val) > 0:
						self.BLOCKED_IPS = val.split(",")
							
		except:
			debug.debug("[Error] Can't parse the config file.", level=debug.ERROR)
			debug.debug(traceback.format_exc(), level=debug.ERROR)


	def update(self):
		"""
			This function updates this config object's properties
		"""
		try:
			for key, val in self.data.items():
				if key == "port":
					self.SERVER_PORT = val
				elif key == "key":
					self.KEY = val
				elif key == "max_conn":
					self.MAX_CLIENTS = int(val)
				elif key == "close_conn":
					self.DISCONNECT_CLIENT_TIME = int(val)
				elif key == "close_port":
					self.DISCONNECT_SESSION_TIME = int(val)
				elif key == "pcap":
					self.PCAP_TRAFFIC = to_bool(val)
				elif key == "unsecure":
					self.ALLOW_UNSECURE_CONNECTION = to_bool(val)
				elif key == "max_log":
					self.MAX_LOG = int(val)
				elif key == "username":
					self.USERNAME = val
				elif key == "password":
					self.PASSWORD = val
		except:
			debug.debug("[Error] Bad config file format.", level=debug.ERROR)

	def pack(self):
		"""
			Packs the properties to be written to the properties file.
		"""
		self.data["port"] = self.SERVER_PORT
		self.data["key"] = self.KEY
		self.data["max_conn"] = self.MAX_CLIENTS
		self.data["close_conn"] = self.DISCONNECT_CLIENT_TIME
		self.data["close_port"] = self.DISCONNECT_SESSION_TIME
		self.data["pcap"] = self.PCAP_TRAFFIC
		self.data["unsecure"] = self.ALLOW_UNSECURE_CONNECTION
		self.data["max_log"] = self.MAX_LOG
		self.data["username"] = self.USERNAME
		self.data["password"] = self.PASSWORD

	def write(self, new_data):
		"""
			Writes the configuration to the properties file.
		"""
		for key, value in new_data.items():
			self.data[key] = str(value)
		f = open(self.fn, "w")
		f.write("! ----------------------------------------------\n")
		f.write("!  MobileVPN Properties File\n")
		f.write("! ----------------------------------------------\n")
		for key, value in self.data.items():
			if key != "blocks":
				f.write(key + "=" + str(value) + "\n")
		# write the blocked ip addresses
		f.write("blocks=" + (",".join(self.BLOCKED_IPS)) + "\n")
		# close the file
		f.close()

	def __getitem__(self, prop):
		prop = prop.upper()
		if prop == "USERNAME":
			return self.USERNAME
		if prop == "PASSWORD":
			return self.PASSWORD
		if prop == "SERVER_PORT":
			return self.SERVER_PORT
		if prop == "MAX_CLIENTS":
			return self.MAX_CLIENTS
		if prop == "MAX_LOG":
			return self.MAX_LOG
		if prop == "DISCONNECT_CLIENT_TIME":
			return self.DISCONNECT_CLIENT_TIME
		if prop == "DISCONNECT_SESSION_TIME":
			return self.DISCONNECT_SESSION_TIME
		if prop == "PCAP_FILE_SIZE":
			return self.PCAP_FILE_SIZE
		if prop == "PCAP_TRAFFIC":
			return self.PCAP_TRAFFIC
		if prop == "ALLOW_UNSECURE_CONNECTION":
			return self.ALLOW_UNSECURE_CONNECTION
		if prop == "KEY":
			return self.KEY
		return None

	def __setitem__(self, prop, data):
		prop = prop.upper()
		if prop == "USERNAME":
			self.USERNAME = data
		if prop == "PASSWORD":
			self.PASSWORD = hashlib.sha256(data).hexdigest()
		if prop == "SERVER_PORT":
			self.SERVER_PORT = data
		if prop == "MAX_CLIENTS":
			self.MAX_CLIENTS = data
		if prop == "MAX_LOG":
			self.MAX_LOG = data
		if prop == "DISCONNECT_CLIENT_TIME":
			self.DISCONNECT_CLIENT_TIME = data
		if prop == "DISCONNECT_SESSION_TIME":
			self.DISCONNECT_SESSION_TIME = data
		if prop == "PCAP_FILE_SIZE":
			self.PCAP_FILE_SIZE = data
		if prop == "PCAP_TRAFFIC":
			self.PCAP_TRAFFIC = data
		if prop == "ALLOW_UNSECURE_CONNECTION":
			self.ALLOW_UNSECURE_CONNECTION = data
		if prop == "KEY":
			self.KEY = data


def to_bool(st):
	return st.lower() == "true"


class ConfigHandler(ServiceThread):
	"""
		A Web Server for configuration.
	"""
	def __init__(self, tunnel, port=8080):
		"""
			Initializes the config server.
			@param tunnel The VPN tunnel.
			@param port The Website port.
		"""
		super(ConfigHandler, self).__init__()

		self.tunnel = tunnel
		self.ip = "0.0.0.0"
		self.port = port

		self.config = Config("properties.cfg")
		self.config.read()
		self.config.update()

		self.web_sessions = set()

		self.TIME_STARTUP = debug.get_current_timestamp()
		self.THREAD_CRASHED = "<font color=\"#f00000\">(probably crashed)</font>"

	def start(self):
		"""
			Starts the configuration web server.
		"""
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.bind((self.ip, self.port))
		self.sock.listen(5)
		debug.debug("[Config] Server is listening on " + self.ip + ":" + str(self.port))
		while True:
			try:
				client, addr = self.sock.accept()
				self.update()
				client.settimeout(20)
				self.handle_request(client, addr)
				client.close()
			except socket.timeout:
				pass
			except socket.error:
				pass
			except:
				debug.debug("[Config] Error in website request handling", level=debug.ERROR)
				debug.debug(traceback.format_exc(), level=debug.ERROR)


	def login(self, username, password, client, ip):
		"""
			Handles user login.
			@param username the user's name
			@param password the user's password
			@param client the client socket
			@param ip the client's ip address
		"""
		# get the username/password
		username = urllib.unquote(username)
		password = hashlib.sha256(urllib.unquote(password)).hexdigest()
		# check them with our properties
		if self.config.USERNAME == username and self.config.PASSWORD == password:
			session_name = ip + "_" + generate_token(5)
			self.web_sessions.add(session_name)
			debug.debug("[Config] %s has logged in." % (ip,))
			# login successfully
			fdata, params = self.load_main()
			return self.send_code(client, 302, fdata, params="\r\nLocation: /\r\nSet-Cookie: session=%s" % (session_name,))
		# load the login screen if authentication failed
		fdata = self.load_file("login.html")
		fdata = fdata.replace("<helpbar>", "<span style=\"color:#fa3030\">Authentication failed.</span>")
		return self.send_code(client, 200, fdata)


	def handle_request(self, client, addr):
		"""
			Handles a single web request.
			@param client the client's socket
			@param addr the client's address (ip, port)
		"""
		request = client.recv(1024)
		header = request.replace("\r", "").split("\n")[0].split(" ")
		if len(header) != 3:
			return self.send_code(client, 404)
		if header[0] == "POST":
			if header[1] == "/login":
				data = [pair.replace("\n", "").replace("\r", "").split("=") for pair in request.split("\r\n\r\n")[1].split("&")]
				username = ""
				password = ""
				try:
					for key, val in data:
						if key == "username":
							username = val
						elif key == "password":
							password = val
				except:
					# errors can happen on form re-sends
					pass
				return self.login(username, password, client, addr[0])
			else:
				return self.send_code(client, 404)
		elif header[0] != "GET" or not header[2].startswith("HTTP/"):
			return self.send_code(client, 404)
		if ".." in header[1]:
			return self.send_code(client, 404)
		# favicon
		if header[1] == "/favicon.ico":
			fdata = self.load_file("favicon.png")
			return self.send_code(client, 200, fdata)
		# login screen css
		if header[1] == "/window.css":
			fdata = self.load_file("window.css")
			return self.send_code(client, 200, fdata)
		# get the session's cookie (if any)
		cookie = self.get_cookie(request, "session")
		# need authentication
		if not cookie or cookie not in self.web_sessions:
			fdata = self.load_file("login.html")
			return self.send_code(client, 200, fdata)
		elif header[1] == "/logout":
			# disconnect the client
			debug.debug("[Config] %s has logged out." % (addr[0],))
			self.web_sessions.remove(cookie)
			# load the login page
			fdata = self.load_file("login.html")
			return self.send_code(client, 200, fdata)
		# main page
		if header[1] in ["/", "main.html", "index", "/login"]:
			try:
				fdata, params = self.load_main()
				return self.send_code(client, 200, fdata)
			except:
				debug.debug("[Config] Error in creating main page", level=debug.ERROR)
				debug.debug(traceback.format_exc(), level=debug.ERROR)
		if header[1] == "/partial-log.txt":
			return self.send_code(client, 200, debug.generate_html_log(max=self.config.MAX_LOG, newline="<br>"))
		if header[1] == "/log.txt":
			return self.send_code(client, 200, debug.generate_plain_log())
		if header[1].startswith("/config"):
			return self.send_code(client, 200, self.update_config(header[1]))
		if header[1].startswith("/device/"):
			return self.send_code(client, 200, self.get_device_info(header[1][8:]))
		if header[1].startswith("/stream/"):
			return self.send_code(client, 200, self.get_html_stream(header[1][8:]))
		if header[1].startswith("/rmdev/"):
			return self.send_code(client, 302, self.remove_device(header[1][7:]), params="\r\nLocation: /")
		if header[1].startswith("/block/"):
			return self.send_code(client, 302, self.block_ip(header[1][7:]), params="\r\nLocation: /")
		if header[1].startswith("/unblock/"):
			return self.send_code(client, 302, self.unblock_ip(header[1][9:]), params="\r\nLocation: /")
		if header[1].startswith("/restart"):
			self.restart_vpn()
			return self.send_code(client, 200, self.load_message("Restart Failed", "This functionality is not implemented yet.<br>Please try again later."))#302, "Restarted, this might take a while..", params="\r\nLocation: /")
		if header[1].endswith(".webp"):
			return self.send_code(client, 200, self.load_file(header[1][1:]), params="\r\nContent-Type: image/webp")
		if header[1].startswith("/?"):
			try:
				fdata, params = self.load_main(args=header[1][2:])
				return self.send_code(client, 200, fdata, params=params)
			except:
				pass
		# load the file and send the code
		try:
			fdata = self.load_file(header[1][1:])
			return self.send_code(client, 200, fdata)
		except:
			pass
		return self.send_code(client, 404)

	def send_code(self, client, code, data="", params=""):
		"""
			Sends a response to the client.
		"""
		if code == 404:
			client.send("HTTP/1.1 404 Page Not Found\r\n\r\n<b>Page Not found</b><br>The page doesn't exist.")
		elif code == 500:
			client.send("HTTP/1.1 500 Internal Server Error\r\n\r\n<b>Internal Server Error</b><br>A successful response could not be generated.")
		elif code == 200:
			client.send("HTTP/1.1 200 OK" + params + "\r\nConnection: close\r\n\r\n" + data) 
		elif code == 302:
			client.send("HTTP/1.1 302 Found" + params + "\r\nConnection: close\r\n\r\n" + data) 

	def load_file(self, fn):
		try:
			path = os.getcwd() + "/www/" + fn
			f = open(path, "rb")
			data = f.read()
			f.close()
		except:
			path = os.getcwd() + "/www/res/" + fn
			f = open(path, "rb")
			data = f.read()
			f.close()
		return data

	def load_main(self, args=""):
		if args.startswith("zip="):
			try:
				num = int(args[4:])
			except:
				num = 0
			conn = self.tunnel.get_connection_by_id(num)
			if conn is not None: # if conn is none, return the regular homepage (resets the connections list)
				data = conn.create_pcap_zip()
				return data, "\r\nContent-Disposition: attachment; filename=\"%s\"" % (conn.get_name() + ".zip",)

		data = self.load_file("main.html")
		# TODO optimize using replacement dictionary
		# update timestamps
		data = data.replace("{TIME_STARTUP}", self.TIME_STARTUP)
		data = data.replace("{TIME_TUNNEL}", debug.get_timestamp(self.tunnel.get_last_update_time()))
		data = data.replace("{TIME_ROUTER}", debug.get_timestamp(self.tunnel.router.get_last_update_time()))
		data = data.replace("{TIME_SESSIONS}", debug.get_timestamp(self.tunnel.router.nat.sessions.get_last_update_time()))
		data = data.replace("{TIME_CONNECTIONS}", debug.get_timestamp(self.tunnel.conns_handler.get_last_update_time()))
		data = data.replace("{TIME_CONFIG}", debug.get_timestamp(self.get_last_update_time()))
		# update log
		data = data.replace("{LOG}", debug.generate_html_log(max=self.config.MAX_LOG))
		data = data.replace("{MAX_LOG}", str(self.config.MAX_LOG))
		data = data.replace("{DEVICE_TABLE}", self.generate_devices_table())
		data = data.replace("{DEVICE_DATA}", self.generate_devices_data())
		# configurations
		# checked="checked"
		data = data.replace("{SERVER_PORT}", str(self.config.SERVER_PORT))
		data = data.replace("{MAX_CONN}", str(self.config.MAX_CLIENTS))
		data = data.replace("{CLOSE_CONN_TIME}", str(self.config.DISCONNECT_CLIENT_TIME/60) + " mins")
		data = data.replace("{CLOSE_PORT_TIME}", str(self.config.DISCONNECT_SESSION_TIME) + " secs")
		if self.config.PCAP_TRAFFIC:
			data = data.replace("{PCAP_TRAFFIC}", "checked")
		else:
			data = data.replace("{PCAP_TRAFFIC}", "")
		if self.config.ALLOW_UNSECURE_CONNECTION:
			data = data.replace("{UNSECURE_CONNECTIONS}", "checked")
		else:
			data = data.replace("{UNSECURE_CONNECTIONS}", "")
		# blocked ips
		data = data.replace("{BLOCKS}", self.generate_block_table())
			
		return data, "\r\nContent-type: text/html; charset=utf-8"


	def generate_block_table(self):
		"""
			Generates a HTML table of blocked IP addresses.
		"""
		st = ""
		i = 0
		for item in self.config.BLOCKED_IPS:
			st += "<tr><td>%s</td><td><a href=\"/unblock/%d\">Remove</a></td></tr>" % (item, i)
			i += 1
		return st


	def generate_devices_table(self):
		template = "<td><span class=\"device\"><a href=\"javascript:void(0)\" onclick=\"showDevice(%d)\
\"><img src=\"client_unsecure.png\"></a><br>Name: %s<br>Token: %s<br></span></td>"
		data = "<tr>"
		i = 0
		for client_data in self.tunnel.get_clients_data():
			data += template % (i, client_data[0], client_data[2].encode("base64").replace("\n", ""))
			i += 1
		if i == 0:
			data += "<td><font color=\"#707070\">No connected devices.</font></td>"
		data += "</tr>"
		return data


	def generate_devices_data(self):
		data = "["
		i = 0
		for client_data in self.tunnel.get_clients_data():
			if i > 0:
				data += ","
			data += "[\"" + client_data[0] + "\", \"" + client_data[2].encode("base64").replace("\n", "") + "\", \"" + str(client_data[3]) + "\", " + str(client_data[4]) + ", \"" + str(client_data[1]) + "\"]"
			i += 1
		data += "]"
		return data


	def block_ip(self, url):
		if not is_valid_ip_address(url):
			return "Argument Error!"
		self.config.BLOCKED_IPS.append(url)
		self.config.write({})
		return ""

	def unblock_ip(self, url):
		try:
			index = int(url)
		except:
			return "Argument Error!"
		try:
			self.config.BLOCKED_IPS.pop(index)
			self.config.write({})
		except:
			return "Index Error!"
		return ""

	def remove_device(self, url):
		try:
			deviceId = int(url)
		except:
			return "Argument Error!"
		connection = self.tunnel.get_connection_by_id(deviceId)
		connection.disconnect()
		return ""


	def get_device_info(self, url):
		try:
			deviceId = int(url)
		except:
			return "Device Disconnected"
		# init the data
		data = "<table><th><td>Package Name</td><td>Port Sessions</td></th>"
		# get the connections and apps data
		connection = self.tunnel.get_connection_by_id(deviceId)
		if connection == None:
			return "Device Disconnected"
		apps = connection.get_applications()
		# go through all apps
		for app in apps.keys():
			data += "<tr>"
			data += "<td><img src=\"" + apps[app].get_image() + "\" type=\"image/webp\" width=\"32\" height=\"32\"></td>"
			data += "<td>" + apps[app].get_name() + "</td>"
			data += "<td>"
			i = 0
			for conn in apps[app].get_connections():
				if i > 0:
					data += ", "
				if self.tunnel.router.nat.contains_port(int(conn[0])):
					span_start = "<a href=\"javascript:void(0)\" onclick=\"getStream(%d)\"><span title=\"%s\" class=\"stream_port\">" \
						% (int(conn[0]), "Protocol: " + conn[1])
					span_end = "</span></a>"
				else:
					span_start = "<font color=\"#808080\"><span title=\"%s\">" % ("Protocol: " + conn[1])
					span_end = "</span></font>"
				data += span_start + str(conn[0]) + span_end
				i += 1
			# if there are no connections
			if i == 0:
				data += "<font color=\"#808080\"><span title=\"This application most likely had active sessions in the past.\">No active sessions.</span></font>"
			data += "</td>"
			data += "</tr>"
		data += "</tr></table>"
		return data


	def get_html_stream(self, url):
		try:
			data = url.split("/")
			deviceId = int(data[0])
			port = int(data[1])
		except:
			return "Error Creating Stream"
		return self.tunnel.router.nat.get_html_stream(port)


	def get_cookie(self, request, name):
		for line in request.replace("\r", "").split("\n"):
			if line.startswith("Cookie: %s=" % (name,)):
				return line[line.find("=")+1:]
		return None

	def load_message(self, title, text):
		msg = self.load_file("message.html")
		return msg.replace("<vpnmsg-title>", title).replace("<vpnmsg-text>", text)

	def update_config(self, url):
		args = self.parse_config(url)
		if args == None:
			return self.load_message("Update Configuration Failed...",\
				"Check out the console log for more information.") 
		# save the configuration
		self.config.write(args)
		self.config.update()
		# return
		return self.load_message("Configuration Update",\
				"Saved the new configuration.") 


	def parse_config(self, url):
		#/config?port=1234&max_conn=10&close_conn=300&close_port=30&pcap=on&unsecure=on
		try:
			args = [[pair[:pair.find("=")], pair[pair.find("=")+1:]] for pair in url[url.find("?")+1:].split("&")]
			# add arguments to a dictionary
			d = {}
			d["pcap"] = False
			d["unsecure"] = False
			# run over the arguments
			for arg in args:
				if arg[0] == "port":
					arg[1] = int(arg[1])
					if arg[1] < 1024 or arg[1] > 65534:
						return None
					d[arg[0]] = arg[1]				
				elif arg[0] == "max_conn":
					arg[1] = int(arg[1])
					if arg[1] > 100 or arg[1] < 1:
						return None
					d[arg[0]] = arg[1]
				elif arg[0] == "close_conn":
					arg[1] = int(arg[1])
					if arg[1] > 1800 or arg[1] < 60:
						return None
					d[arg[0]] = arg[1]
				elif arg[0] == "close_port":
					arg[1] = int(arg[1])
					if arg[1] > 180 or arg[1] < 15:
						return None
					d[arg[0]] = arg[1]
				elif arg[0] == "pcap" and arg[1] == "on":
					arg[1] = True
					d[arg[0]] = arg[1]
				elif arg[0] == "unsecure" and arg[1] == "on":
					arg[1] = True
					d[arg[0]] = arg[1]
			return d
		except:
			debug.debug(traceback.format_exc(), level=debug.ERROR)
			return None
	def restart_vpn(self):
		"""
			Restarts The MobileVPN server.
		"""
		# close all sockets
		###self.sock.close()
		###self.tunnel.sock.close()
		# restart the program
		###sys.exit()

def is_valid_ip_address(addr):
	try:
		socket.inet_aton(addr)
		return addr.count(".") == 3
	except socket.error:
		return False

def generate_token(size):
	return ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(size))