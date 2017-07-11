###################################################################
#
#                      Python Network Tunnel
#                        Connection Handler
#
# Author: Nir Haike
#
###################################################################

import pcap_writer
import threading
import random
import debug
import time
import net
import aes

import zlib
#import cStringIO as StringIO
import binary_reader
import traceback

from service import ServiceThread


TOKEN_SIZE = 4


class Connection(object):
	"""
		This class handles the connection with a single vpn client.
	"""

	def __init__(self, vpn, address, config):
		self.vpn_service = vpn
		self.address = address
		self.name = None
		self.token = None
		self.encryption = None
		self.pcap = None
		self.zip_traffic = True # compress by default
		self.options = 0x00 # client options

		self.config = config

		# client resources
		self.resources = {}
		self.applications = {}

		# make this class thread-safe
		self.mutex = threading.Lock()
		# saving the packets for handling them in another thread
		self.save_packets = True # handle packets differently for the initial handshake
		self.packets = []
		self.last_refresh = time.time()

	def get_name(self):
		return self.name

	def refresh(self):
		self.last_refresh = time.time()

	def handle_incoming_packet(self, data):
		"""
			This function handles a single incoming packet from
			the internet to the vpn client.
		"""
		self.refresh()
		# write to the pcap file
		if self.pcap is not None:
			self.pcap.write_packet(data)
		# encrypt the packet
		data = self.encrypt_packet(data)
		# add the token to the packet
		data = self.add_token(data)
		# send the packet
		self.send_client(data)

	def handle_outgoing_packet(self, data):
		"""
			This function handles a single incoming packet from
			the vpn client.
			Returns: True if the packet was fully handled,
					 False if the packet was saved for future use.
		"""
		self.refresh()
		# save the packet for another thread if required to do so
		if self.save_packets:
			self.mutex.acquire()
			self.packets.append(data)
			self.mutex.release()
			return False
		# check if this is a disconnection message
		if data.startswith("\x00\x00\x00\x00BYE!"):
			self.close()
			debug.debug("[Connection] Ended a connection.")
			# none means that the connection should be closed
			return None
		# applications update message
		elif data.startswith("\x00\x00\x00\x00" + self.token + "APPS"):
			try:
				self.read_applications_ports(data[12:])
			except:
				debug.debug(traceback.format_exc(), level=debug.ERROR)
				debug.debug("[Error] cant read apps.", level=debug.ERROR)
			return False
		elif data.startswith("\x00\x00\x00\x00" + self.token + "RES"):
			try:
				self.read_resource_part(data[11:])
			except:
				#debug.debug(traceback.format_exc(), level=debug.ERROR)
				#debug.debug("[Error] cant read resource.", level=debug.ERROR)
				pass
			return False
		# check if the packet is valid
		if len(data) < TOKEN_SIZE or data[:TOKEN_SIZE] != self.token:
			# invalid packet
			debug.debug("[Connection] Invalid packet/token received..")
			return False
		# decrypt the packet
		packet_data = self.decrypt_packet(data[TOKEN_SIZE:])
		# write to the pcap file
		if self.pcap is not None:
			self.pcap.write_packet(packet_data)
		# create the packet
		packet = self.vpn_service.get_router().create_packet(packet_data)
		# check if the destination is blocked
		if packet.get_dest_ip() in self.config.BLOCKED_IPS:
			return True
		# handle the packet
		self.vpn_service.get_router().send_packet(packet, self)
		return True

	def send_client(self, data):
		self.vpn_service.send_packet(data, self.address)

	def decrypt_packet(self, data):
		"""
			Decrypts and Decompresses the packet data
		"""
		if self.zip_traffic:
			# decompress the data
			data = zlib.decompress(data)
		if self.encryption:
			# decrypt the data
			data = self.encryption.decrypt(data)
		return data

	def getintofbytes(self, data):
		st = ""
		for d in data:
			st += str(ord(d)) + " "
		return st

	def encrypt_packet(self, data):
		"""
			Encrypts and Compresses the packet data
		"""
		if self.encryption:
			# encrypt using a random IV (base64 output)
			data = self.encryption.encrypt(data)
		if self.zip_traffic:
			# compress the data
			return zlib.compress(data)
		return data

	def add_token(self, data):
		return self.token + data

	def next_packet(self, timeout=-1):
		"""
			Returns the next packet from the connection, or
			None if timeout exceeded.

			@param timeout maximum wait time. Use (-1) for no timeout.
		"""
		curr_time  = 0
		delta_time = 0.1

		while True:
			self.mutex.acquire()
			if len(self.packets) > 0:
				packet = self.packets.pop(0)
				self.mutex.release()
				return packet
			self.mutex.release()
			# check if timeout exceeded
			if curr_time >= timeout and timeout != -1:
				return None
			# if there's no packet yet, sleep for a short time
			time.sleep(delta_time)
			curr_time += delta_time



	def is_in_addresses_table(self, packet):
		remote_addr = net.get_packet_addresses(packet)
		# TODO this...
		#return 

	def generate_token(self):
		"""
			Generate a connection token.
			The token cannot contain "null" (0) bytes.
		"""
		return "".join([chr(random.randint(1,255)) for i in range(4)])

	def handshake(self):
		"""
			This function processes the handshake with a new client.
		"""
		data = self.next_packet()
		# check if the packet is valid
		if len(data) < 10 or data[:8] != "\x01\x02\x03\x04HELO":
			#debug.debug("[Connection] Bad handshake received.")
			self.vpn_service.end_connection(self)
			return
		# get the options
		self.options = ord(data[8])
		# generate the token
		self.token = self.generate_token()
		# set the device's name if available
		self.name = "Device"
		try:
			if ord(data[9]) > 0:
				self.name = data[10:10+ord(data[9])]
		except:
			pass
		# connection options byte
		options = 0
		# applications list option
		if self.config.APPLICATIONS_LIST:
			options += 0x01
		# compression option
		if self.zip_traffic:
			options += 0x02
		# encryption option
		if self.config.SECURE_CONNECTIONS:
			try:
				self.encryption = aes.AESSession(self.config.KEY)
				options += 0x04
			except:
				debug.debug("[Connection] Could not initialize the sessions encrypter.", level=debug.WARNING)
		# send and receive ack
		# byte #9 : options (0x01 - get applications list, 0x02 - zip traffic, 0x04 - encryption)
		self.send_client("\x02\x02\x03\x04HELO" + chr(options) + chr(len(self.token)) + self.token)
		self.save_packets = False
		# create the pcap writer only if requested in the properties file
		if self.config.PCAP_TRAFFIC:
			self.pcap = pcap_writer.PcapWriter(self.name, self.config)
		debug.debug("[Connection] A new client has been connected.")

	def send_acknowledged(self, packet, expected_header):
		"""
			Sends the packet and receives a response.
			@param packet the data to send
			@param expected_header the response's first byte
			@returns the connection's response
		"""
		while True:
			# resend until there's a valid response
			self.send_client(packet)
			ack = self.next_packet(timeout=1)
			if ack is not None and len(ack) > 0 and ack[0] == expected_header:
				return ack

	def is_remote_address(self, address):
		"""
			Returns whether the address is this connection's remote
			address.
		"""
		return address == self.address

	def get_address(self):
		return self.address

	def get_ip_address(self):
		return self.address[0]

	def get_data(self):
		"""
			Returns a list that represents the connection object.
			The list contains: the name, address, token and encryption type.
		"""
		# encryption text
		encryption = "None"
		if self.options > 0:
			encryption = "AES (256 bit)"
		# packet capture option
		if self.pcap:
			return [self.name, self.address[0], self.token, encryption, self.pcap.get_packets_count()]
		return [self.name, self.address[0], self.token, encryption, 0]

	def is_initialized(self):
		return not self.save_packets

	def disconnect(self, end_conn=True):
		"""
			Ends the session with the vpn client and closes the connection.
			@param end_conn Whether to call end_connection in the vpn listener.
		"""
		self.send_client("\x00\x00\x00\x00EXIT")
		self.close()
		if end_conn:
			self.vpn_service.end_connection(self)

	def close(self):
		"""
			This function is called after closing the vpn connection.
		"""
		# close the pcap file
		if self.pcap is not None:
			self.pcap.close()

	def is_alive(self, max_time):
		"""
			Returns whether the connection was updated in the last "max_time" seconds.
			@param max_time the maximum idle time for a connection.
		"""
		if time.time() - self.last_refresh > max_time:
			# prepare to be closed
			self.disconnect(end_conn=False)
			return False
		return True

	def create_pcap_zip(self):
		return self.pcap.create_zip()

	def read_applications_ports(self, zdata):
		#zip_data = StringIO.StringIO(zdata)
		#zf = zipfile.ZipFile(zip_data, "r")
		#data = zf.read("appdata.bin")
		# zf.close()
		data = zlib.decompress(zdata)
		# start reading the data
		reader = binary_reader.BinaryReader(data)
		# read the data filename (appdata.bin, we don't really need it)
		name = reader.read_string()
		# the amount of listed packages
		size = reader.read_int()
		# clear all current packages
		for package in self.applications:
			self.applications[package].clear_connections()
		# start gathering the data
		for i in xrange(size):
			# get the package name
			package = reader.read_string()
			if len(package) > 0 and package != "null":
				num_ports = reader.read_int()
				ports = {}
				if package not in self.applications:
					self.applications[package] = AppData(package)
				for i in xrange(num_ports):
					port = reader.read_int()
					protocol = reader.read_string()
					ports[port] = protocol
				self.applications[package].update_connections(ports)
		return False

	def read_resource_part(self, data):
		res_type = ord(data[0])
		# start reading the data
		reader = binary_reader.BinaryReader(data[1:])
		# read the name
		resource_name = reader.read_string()
		# read the fragment (parts) data
		curr_fragment = reader.read_int()
		total_fragments = reader.read_int()
		debug.debug("Reading resource %s %d/%d" % (resource_name, curr_fragment+1, total_fragments+1))
		# read the size
		curr_size = reader.read_int()
		# read the resource
		curr_data = reader.read_bytes(curr_size)
		# create the resource if not exists
		if resource_name not in self.resources:
			self.resources[resource_name] = {}
		# add the fragment
		self.resources[resource_name][curr_fragment] = curr_data
		# save the resource if we got all the parts
		for i in range(total_fragments + 1):
			# don't save if a part doesn't exist
			if i not in self.resources[resource_name]:
				return
		# we can save the resource
		total_data = ""
		for i in range(total_fragments + 1):
			total_data += self.resources[resource_name][i]
		# delete the resource
		del self.resources[resource_name]
		# save the resource
		if res_type == 0: # icon resource
			# get the icon
			self.mutex.acquire()
			f = open("www/res/icon/" + resource_name + ".webp", "wb")
			f.write(total_data)
			f.close()
			self.mutex.release()
			self.send_client("\x00\x00\x00\x00RESR" + chr(len(resource_name)) + resource_name + "\x00")
		else:
			debug.debug("[WARNING] Got unknown resource type " + str(res_type) + ".")

	def get_applications(self):
		return self.applications



class ConnectionsHandler(ServiceThread):
	"""
		This class handles the connections' filtering.

		The ConnectionsHandler removes unused connections after a fixed amount
		of time (which is determined in the server properties).
	"""
	def __init__(self, tunnel, config):
		super(ConnectionsHandler, self).__init__()
		self.tunnel = tunnel
		self.config = config

	def start(self):
		try:
			while True:
				self.update()
				# remove unused connections
				self.tunnel.filter_connections(self.config.DISCONNECT_CLIENT_TIME)
				time.sleep(5)
		except KeyboardInterrupt:
			return

class AppData(object):
	"""
		Represents an application's network usage data.
	"""
	def __init__(self, package):
		self.package = package
		self.image = "icon/" + package + ".webp"
		self.connections = set()

	def clear_connections(self):
		# clear the old connections set
		self.connections.clear()

	def update_connections(self, ports):
		# add the ports and protocols tuples
		for port in ports:
			self.connections.add((port, ports[port]))

	def get_name(self):
		return self.package

	def get_image(self):
		return self.image

	def get_connections(self):
		return self.connections