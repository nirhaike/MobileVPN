###################################################################
#
#                      Python Network Tunnel
#                      Configuration Handler
#
# Author: Nir Haike
#
###################################################################

import traceback
import socket
import urllib
import debug
import os

from service import ServiceThread


class Config(object):

	USERNAME = "admin"
	PASSWORD = "@mobileVPN"

	SERVER_PORT = 1234

	MAX_CLIENTS = 10

	MAX_LOG = 50
	
	DISCONNECT_CLIENT_TIME = 300
	DISCONNECT_SESSION_TIME = 30

	PCAP_FILE_SIZE = 1000000

	PCAP_TRAFFIC = True
	ALLOW_UNSECURE_CONNECTION = False

	BLOCKED_IPS = []

	def __init__(self, fn):
		self.fn = fn
		self.data = {}

	def read(self):
		try:
			f = open(self.fn, "r")
			lines = f.read().split("\n")
			f.close()
			for line in lines:
				if len(line) > 0 and line[0] != "!" and "=" in line:
					arg, val = line.split("=")
					arg = arg.strip(' \t\n\r')
					val = val.strip(' \t\n\r')
					self.data[arg] = val
		except:
			debug.debug("[Error] Can't parse the config file.", level=debug.ERROR)

	def update(self):
		try:
			for key, val in self.data.items():
				if key == "port":
					self.SERVER_PORT = val
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

	def write(self, new_data):
		for key, value in new_data.items():
			self.data[key] = str(value)
		f = open(self.fn, "w")
		f.write("! ----------------------------------------------\n")
		f.write("!  MobileVPN Properties File\n")
		f.write("! ----------------------------------------------\n")
		for key, value in self.data.items():
			f.write(key + "=" + value + "\n")
		f.close()


def to_bool(st):
	return st.lower() == "true"


class ConfigHandler(ServiceThread):

	def __init__(self, tunnel, port=8080):
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
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.bind((self.ip, self.port))
		self.sock.listen(5)
		debug.debug("[Config] Server is listening on " + self.ip + ":" + str(self.port))
		while True:
			try:
				client, addr = self.sock.accept()
				self.update()
				client.settimeout(20)
				self.handle_client(client, addr)
				client.close()
			except socket.timeout:
				pass
			except:
				debug.debug("[Config] Error in website request handling", level=debug.ERROR)
				debug.debug(traceback.format_exc(), level=debug.ERROR)


	def login(self, username, password, client, ip):
		username = urllib.unquote(username)
		password = urllib.unquote(password)
		if self.config.USERNAME == username and self.config.PASSWORD == password:
			self.web_sessions.add(ip)
			debug.debug("[Config] %s has logged in." % (ip,))
			# login successfully
			fdata, params = self.load_main()
			return self.send_code(client, 200, fdata)
		# load the login screen if authentication failed
		fdata = self.load_file("login.html")
		fdata = fdata.replace("<helpbar>", "<span style=\"color:#fa3030\">Authentication failed.</span>")
		return self.send_code(client, 200, fdata)


	def handle_client(self, client, addr):
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
		# need authentication
		if addr[0] not in self.web_sessions:
			fdata = self.load_file("login.html")
			return self.send_code(client, 200, fdata)
		elif header[1] == "/logout":
			# disconnect the client
			debug.debug("[Config] %s has logged out." % (addr[0],))
			self.web_sessions.remove(addr[0])
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
		if code == 404:
			client.send("HTTP/1.1 404 Page Not Found\r\n\r\n<b>Page Not found</b><br>The page doesn't exist.")
		elif code == 500:
			client.send("HTTP/1.1 500 Internal Server Error\r\n\r\n<b>Internal Server Error</b><br>A successful response could not be generated.")
		elif code == 200:
			client.send("HTTP/1.1 200 OK" + params + "\r\nConnection: close\r\n\r\n" + data) 

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
			

		# do some manipulations here..
		return data, "\r\nContent-type: text/html; charset=utf-8"


	def generate_devices_table(self):
		template = "<td><span class=\"device\"><a href=\"javascript:void(0)\" onclick=\"showDevice(%d)\
\"><img src=\"client_unsecure.png\"></a><br>Name: %s<br>Token: %s==<br></span></td>"
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


	def get_device_info(self, url):
		try:
			deviceId = int(url)
		except:
			return "Device Disconnected"
		# init the data
		data = "<table><th><td>Package Name</td><td>Ports</td></th>"
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


	def update_config(self, url):
		args = self.parse_config(url)
		if args == None:
			return "<html><body<h1>Update Configuration</h1><br>Failed...<br>Check out the console log for more information.</body></html>"
		# save the configuration
		self.config.write(args)
		self.config.update()
		# return
		return "<html><body<h1>Update Configuration</h1>Saved the new configuration!</body></html>"


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
