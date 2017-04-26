###################################################################
#
#                      Python Network Tunnel
#                         Session Handler
#
# Author: Nir Haike
#
###################################################################

import threading
import socket
import string
import time
import debug
import net

from service import ServiceThread


class PortSession(object):

	def __init__(self, port, key, callback):
		"""
			PortSession Constructor
			@param port the session's port
			@param key the remote session's key (address, port)
			@param callback the function that is called when
				   the socket is closed. 
		"""
		self.MAX_UNUSED_TIME = 30
		
		self.COLOR_ME = "#3060c0"
		self.COLOR_OTHER = "#c03930"

		self.port = port
		self.key = key
		self.callback = callback
		self.stream = [] # in/out data

		#self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,\
		#	socket.IPPROTO_RAW)
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.last_refresh = time.time()

	def connect(self):
		self.sock.bind(('0.0.0.0', self.port))
		#self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
		#debug.debug("[Session] Port %d is bound" % (self.port,))

	def get_port(self):
		return self.port

	def refresh(self):
		self.last_refresh = time.time()

	def update(self):
		"""
			This function updates the socket.
			The socket is closed if it's unused.
			Returns: False if closed, True otherwise
		"""
		if time.time() - self.last_refresh > self.MAX_UNUSED_TIME:
			self.close()
			return False
		return True

	def send(self, packet, dest):
		#f = open("C:\port" + str(self.port) + ".bin", "a+b")
		#f.write(data + "======")
		#f.close()
		###result = self.sock.sendto(data, dest)
		net.send_packet(net.get_packet_raw_data(packet))
		self.handle_send(packet)
		#debug.debug("[Session] 1 packet was sent to " + dest[0] + ":" + str(dest[1]))

	def handle_send(self, packet):
		"""
			Adds the packet to the stream.
			Called when sending data through the session.
		"""
		self.stream.append((0, packet.get_raw_data()))

	def handle_receive(self, packet):
		""" 
			Adds the packet to the stream.
			Called when receiving data from the sniffer.
		"""
		self.stream.append((1, packet.get_raw_data()))

	def get_html_stream(self):
		#stream = ""
		textual = ""
		for peer, data in self.stream:
			if peer == 0:
				#stream += "<span class=\"streamdata\" title=\"Sent by your device\" style=\"color:%s\"" % (self.COLOR_ME) + ">"
				textual += "<span class=\"streamdata\" title=\"Sent by your device\" style=\"color:%s\"" % (self.COLOR_ME) + ">"
			else:
				#stream += "<span class=\"streamdata\" title=\"Sent to your device\" style=\"color:%s\"" % (self.COLOR_OTHER) + ">"
				textual += "<span class=\"streamdata\" title=\"Sent to your device\" style=\"color:%s\"" % (self.COLOR_OTHER) + ">"
			#stream += " ".join("{:02x}".format(ord(c)) for c in data)
			# only printable characters
			textual += debug.escape_string(filter(lambda x: x in string.printable, data))
			#stream += "</span> "
			textual += "</span> "
		#return "<span id=\"stream0\">" + stream + "</span><br><span id=\"stream1\">" + textual + "</span>"
		return "<span id=\"stream1\">" + textual + "</span>"

	def close(self):
		""" Closes the socket. """
		# call the callback (update the router)
		self.callback(self.key)
		# close the socket
		self.sock.close()


class SessionsHandler(ServiceThread):

	def __init__(self):
		super(SessionsHandler, self).__init__()
		self.sessions = []
		self.mutex = threading.Lock()

	def create_session(self, session):
		self.mutex.acquire()
		self.sessions.append(session)
		self.mutex.release()

	def handle_receive(self, port, packet):
		self.mutex.acquire()
		for session in self.sessions:
			if session.get_port() == port:
				session.handle_receive(packet)
		self.mutex.release()

	def get_html_stream(self, port):
		result = ""
		self.mutex.acquire()
		for session in self.sessions:
			if session.get_port() == port:
				result = session.get_html_stream()
		self.mutex.release()
		return result

	def refresh(self, port):
		self.mutex.acquire()
		for session in self.sessions:
			if session.get_port() == port:
				session.refresh()
		self.mutex.release()

	def send(self, packet, dest, port):
		self.mutex.acquire()
		for session in self.sessions:
			if session.get_port() == port:
				session.send(packet, dest)
		self.mutex.release()

	def run(self):
		try:
			while True:
				# update the statistics that this thread actually runs
				self.update()
				# update the sessions list (remove unused ones)
				self.mutex.acquire()
				length = len(self.sessions)
				self.sessions = [s for s in self.sessions if s.update()]
				if len(self.sessions) < length:
					debug.debug("[Session] Cleared unused sessions...")
				self.mutex.release()
				#"""
				# sleep for 15 seconds
				time.sleep(15)
		except KeyboardInterrupt:
			return
