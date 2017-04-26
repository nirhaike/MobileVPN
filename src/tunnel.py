###################################################################
#
#                      Python Network Tunnel
#                      Tunnel Implementation
#
# Author: Nir Haike
#
###################################################################
#
# Handling outgoing packets:
# 1. Receive the packet from the device
# 2. Change the source ip
# 3. (Add action here)
# 4. Update the checksum
# 5. Send the packet (which port should we use?)
#
# Handling ingoing packets:
# 1. Receive the packet (how?)
# 2. Change the destination ip
# 3. Update the checksum
# 4. Send the packet to the tunnel
#
###################################################################
#
# The device's VPN Service:
#
# We use an input stream to read outgoing packets, then we
# write them to the tunnel.
#
#                Device -> Tunnel -> Internet
#
# We read the ingoing packets from the tunnel and write them
# to the output stream.
#
#                Internet -> Tunnel -> Device
#
# Questions:
# 1. What does the addRoute and addAddress functions do?
# https://developer.android.com/reference/android/net/
# VpnService.Builder.html
#
#
#
###################################################################
# Imports
###################################################################
# log that we started loading
import debug
debug.debug("[Tunnel] Setting up...")
import time
import socket
import threading
import net
import config
import session
import connection
import traceback

from service import ServiceThread

###################################################################
# Classes
###################################################################

class VpnListener(ServiceThread):
	"""
		This class listens to all the packets that clients send
		and handles them.
	"""
	def __init__(self, port=1234):
		super(VpnListener, self).__init__()
		# the vpn server's port
		self.port = port
		# the current connection objects
		self.connections = []
		# make sure we won't access a shared resources from
		# different threads...
		self.mutex = threading.Lock()
		# set up the virtual router
		self.router = Router(self)
		# set up the config handler
		self.config = config.ConfigHandler(self)
		# set up the connections manager
		self.conns_handler = connection.ConnectionsHandler(self, self.config.config)

	def start(self):
		# run the router
		router_thread = threading.Thread(target=self.router.start)
		router_thread.daemon = True
		router_thread.start()
		# run the config server
		config_thread = threading.Thread(target=self.config.start)
		config_thread.daemon = True
		config_thread.start()
		# run the connections handler
		conns_thread = threading.Thread(target=self.conns_handler.start)
		conns_thread.daemon = True
		conns_thread.start()
		# start listening
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.bind(("0.0.0.0", self.port))
		self.sock.settimeout(1.0) # allows keyboard interrupt
		debug.debug("[Tunnel] Started listening on port %d..." % (self.port,))
		try:
			while True:
				try:
					self.update()
					data, address = self.sock.recvfrom(655350)
					self.route_packet(data, address)
				except socket.timeout:
					pass # do nothing...
		except KeyboardInterrupt:
			debug.debug("[Tunnel] ^C received, shutting down service...")

	def route_packet(self, data, address):
		# make sure that no one change the connections list
		self.mutex.acquire()
		for conn in self.connections:
			# if the packet is from this client
			if conn.is_remote_address(address):
				result = conn.handle_outgoing_packet(data)
				self.mutex.release()
				if result == None:
					self.end_connection(conn)
				return
		# if no connection exists, create a new one
		if len(self.connections) < self.config.config.MAX_CLIENTS:
			conn = connection.Connection(self, address, self.config.config)
			conn.handle_outgoing_packet(data)
			self.connections.append(conn)
			# release the mutex
			self.mutex.release()
			conn.handshake()

	def get_router(self):
		return self.router

	def send_packet(self, data, address):
		self.sock.sendto(data, address)

	def end_connection(self, conn):
		"""
			Removes the connection object from the connections
			list.
			Returns: None
		"""
		self.mutex.acquire()
		try:
			self.connections.remove(conn)
		except ValueError:
			pass # the connection doesn't exist
		self.mutex.release()

	def filter_connections(self, time):
		self.mutex.acquire()
		size = len(self.connections)
		self.connections = [conn for conn in self.connections if conn.is_alive(time)]
		if len(self.connections) < size:
			debug.debug("[Connection] Cleared unused connections...")
		self.mutex.release()

	def get_client_by_address(self, address):
		self.mutex.acquire()
		for conn in self.connections:
			# if the packet is from this client
			if conn.is_remote_address(address):
				self.mutex.release()
				return conn
		self.mutex.release()
		return None

	def get_clients_data(self):
		"""
			Returns: A list of lists that contains data about
			every connection.
		"""
		data = []
		self.mutex.acquire()
		for conn in self.connections:
			if conn.is_initialized():
				data.append(conn.get_data())
		self.mutex.release()
		return data

	def get_connection_by_id(self, num):
		try:
			return self.connections[num]
		except:
			return None

###################################################################

class Router(ServiceThread):

	def __init__(self, vpn):
		super(Router, self).__init__()
		self.vpn = vpn
		# create the packet handler
		self.packet_handler = net.PacketHandler()
		# create the address table
		self.nat = NetworkAddressTable(vpn, self)
		self.sniffer = None

	def start(self):
		""" 
			Start running the router (get packets from the internet
			and deliver them to the clients).
		"""
		# create a new sniffer
		self.sniffer = net.Sniffer(self.route_packet)
		# start sniffing with route_packet as callback..
		self.sniffer.start_sniffing()

	def route_packet(self, packet):
		# update that we received a packet
		self.update()
		try:
			# change the destination port and get the regular ip
			conn, dest_address = self.nat.handle_ingoing_packet(packet)
			if dest_address is not None:
				# get the raw ip data
				raw_data = net.fix_packet(net.get_packet_raw_data(packet))
				# deliver the packet to the destination client
				conn.handle_incoming_packet(raw_data)
				# call the session's receive for saving the stream
				try:
					self.nat.handle_receive(packet.get_dport(), packet)
				except:
					debug.debug("[Router] Received a packet in an unassigned port (%d)."
						% (packet.get_dport()), level=debug.ERROR)
					debug.debug(traceback.format_exc(), level=debug.ERROR)
		except:
			debug.debug("[Router] Error in route_packet", level=debug.ERROR)
		return None

	def send_packet(self, data, conn):
		"""
			@param data the packet's IP layer data
			@address the *client's* ip address
			Sends the packet to it's destination address 
		"""
		packet = self.packet_handler.create_packet(data)
		if self.nat.handle_outgoing_packet(packet, conn):
			self.nat.send(packet, net.get_packet_destination(packet),\
				net.get_packet_source_port(packet))
		else:
			debug.debug("[Router] Error in send_packet", level=debug.ERROR)

	def get_packet_handler(self):
		return self.packet_handler

	def add_port(self, port):
		self.sniffer.update_port_set({port})

	def remove_port(self, port):
		self.sniffer.port_set_remove(port)


###################################################################

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



###################################################################
