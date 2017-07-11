###################################################################
#
#                      Python Network Tunnel
#                      Tunnel Implementation
#
# Author: Nir Haike
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
###################################################################
# Imports
###################################################################
# log that we started loading
import debug
debug.debug("[Tunnel] Setting up...")
import net
import nat
import time
import socket
import threading
import config
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
		except socket.error:
			debug.debug("[Tunnel] Closed.")

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
		self.nat = nat.NetworkAddressTable(vpn, self)
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
			debug.debug(traceback.format_exc(), level=debug.ERROR)
		return None

	def create_packet(self, data):
		return self.packet_handler.create_packet(data)

	def send_packet(self, packet, conn):
		"""
			@param data the packet's IP layer data
			@address the *client's* ip address
			Sends the packet to it's destination address 
		"""
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
