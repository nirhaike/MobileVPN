###################################################################
#
#                      Python Network Tunnel
#                      Network Addres Table.
#
# Author: Nir Haike
#
###################################################################


import debug
import net
import socket
import session
import threading


class NetworkAddressTable(object):
	"""
		This class handles the IP/port translation of packets
	"""
	def __init__(self, vpn, router):
		self.vpn = vpn
		self.router = router
		self.packet_handler = router.packet_handler
		self.sessions = session.SessionsHandler()
		self.table = {}
		self.reversed_table = {}
		self.client_port = 52289
		self.max_port = 53200
		# for thread safety
		self.mutex = threading.Lock()
		# start the sessions handler
		t = threading.Thread(target=self.sessions.run)
		t.daemon = True
		t.start()

	def handle_outgoing_packet(self, packet, conn):
		"""
			@param packet the packet (as class, not data string)
			@param conn the client's connection object
			Does port forwarding to the packet.
			* This function does NOT send the packet *
			Returns: True if the operation succeeded.
		"""
		source_ip = net.get_packet_source_ip(packet)
		source_port = net.get_packet_source_port(packet)
		key = (conn, source_port)
		# add the key if it doesn't exist
		if key not in self.table:
			self.mutex.acquire()
			# create the tables keys
			self.table[key] = self.generate_next_port()
			self.reversed_table[self.table[key]] = (conn, (source_ip, source_port))
			# create a new session
			s = session.PortSession(self.table[key], key, self.remove_table_key)
			s.connect()
			self.router.add_port(self.table[key])
			self.mutex.release()
			self.sessions.create_session(s)
		real_port = self.table[key]
		# assign our ip (automatically) and port (argument) to the packet
		self.packet_handler.set_source_data(packet, real_port)
		# refresh the session (to make it active)
		self.refresh_session(real_port)
		# return that we succeeded translating the packet
		return True

	def handle_ingoing_packet(self, packet):
		"""
			@param packet the packet
			@param client_ip the vpn client's ip address
			Changes the packet's destination ip & port.
			* This function does NOT send the packet to it's
			destination *
			Returns: The client's address (as tuple), or None
					 if the packet is not valid.
		"""
		dest_port = net.get_packet_destination_port(packet)
		self.mutex.acquire()
		if dest_port not in self.reversed_table:
			# the packet is not valid
			debug.debug("[Router] Invalid packet detected (NAT.handle_ingoing_packet)")
			self.mutex.release()
			return None
		# change the ip headers to the client's ip and port
		conn, addr = self.reversed_table[dest_port]
		real_ip, real_port = addr
		self.mutex.release()
		self.packet_handler.set_destination_data(packet, real_ip, real_port)
		# refresh the session (to make it active)
		self.refresh_session(dest_port)
		# return the client's address
		return (conn, addr)

	def generate_next_port(self):
		while self.client_port < self.max_port:#65536:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			result = sock.connect_ex(('127.0.0.1', self.client_port))
			self.client_port += 1
			# if the port is closed we can use it
			if result == 10061:
				return self.client_port - 1
	
	def get_forwarded_port(self, port):
		for key in self.table.keys():
			if port == key[1]:
				return self.table[key]
		return None

	def contains_port(self, port):
		for key in self.table.keys():
			if port == key[1]:
				return True
		return False

	def contains_forwarded_port(self, port):
		for key in self.table.keys():
			if port == self.table[key]:
				return True
		return False

	def get_html_stream(self, port):
		return self.sessions.get_html_stream(self.get_forwarded_port(port))

	def handle_receive(self, port, packet):
		return self.sessions.handle_receive(self.get_forwarded_port(port), packet)

	def refresh_session(self, port):
		self.sessions.refresh(port)

	def send(self, packet, dest, port):
		self.sessions.send(packet, dest, port)

	def remove_table_key(self, key):
		self.mutex.acquire()
		rev_key = self.table[key]
		self.router.remove_port(rev_key)
		del self.reversed_table[rev_key]
		del self.table[key]
		self.mutex.release()

