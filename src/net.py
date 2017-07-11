###################################################################
#
#                      Python Network Tunnel
#                         Network Handler
#
# Author: Nir Haike
#
###################################################################

import sys
import debug
import socket
import struct
import threading
import traceback

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import sniff, send, hexdump, IP, TCP, UDP, Ether
from scapy.error import Scapy_Exception,log_loading,log_runtime
from scapy.layers.dns import DNS, DNSQR, DNSRR
sys.stdin, sys.stdout, sys.stderr = i, o, e


def get_packet_addresses(packet):
	return {packet.src, packet.dest}

def get_packet_source_ip(packet):
	return packet.src

def get_packet_destination_ip(packet):
	return packet.dest

def get_packet_source_port(packet):
	return packet.get_sport()

def get_packet_destination_port(packet):
	return packet.get_dport()

def get_packet_destination(packet):
	return (packet.dest, packet.get_dport())

def get_packet_raw_data(packet):
	return str(packet)

def get_local_ip():
	return socket.gethostbyname(socket.gethostname())

class Sniffer(object):
	def __init__(self, callback):
		self.port_set = set()
		self.callback = callback
		self.ip_addr = get_local_ip()
		self.stopped = False

	def update_port_set(self, values):
		"""
			@param values a set that contains port numbers
			This function updates the port set.
		"""
		self.port_set.update(values)

	def reset_port_set(self, values):
		"""
			@param values a set that contains port numbers
			This function makes the port set exactly as
			'values'.
		"""
		self.port_set.clear()
		self.port_set.update(values)

	def port_set_remove(self, value):
		self.port_set.remove(value)

	def start_sniffing(self):
		"""
			This function is a blocking function that
			sniffing packets.
		"""
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
		# get all from ports
		self.sock.bind((self.ip_addr, 0))
		# include ip headers
		self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
		# receive all packages
		self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
		# start running
		while not self.stopped:
			try:
				raw_data, addr = self.sock.recvfrom(65535)
				packet = Packet(raw_data)
				#debug.debug(str(packet.get_sport()) + " " + str(packet.get_dport()))
				# TODO check destination ip
				if packet.get_dport() in self.port_set:
					self.callback(packet)
			except:
				traceback.print_exc()
				debug.debug("Ended sniffing...")
				self.sock.close()
				return
		self.sock.close()

	def stop(self):
		self.stopped = True


class PacketHandler(object):
	def __init__(self):
		# keep this pc's ip address
		self.ip_addr = get_local_ip()

	def create_packet(self, raw_data):
		"""
			@param raw_data the packet's data at the IP layer.
			Returns: our representation of the packet (at IP layer).
		"""
		packet = Packet(raw_data)
		return packet

	def set_source_data(self, packet, port, ip=None):
		"""
			Sets the source ip of the packet to be the current interface's
			inner ip.
			@param packet the packet
			@param port the new source port
			@param ip the new source ip (default: our ip)
		"""
		if ip:
			packet.src = ip
		else:
			# the default ip is our ip
			packet.src = self.ip_addr
		packet.set_sport(port)

	def set_destination_data(self, packet, ip, port):
		"""
			Sets the source ip of the packet to be the current interface's
			inner ip.
		"""
		packet.dest = ip
		packet.set_dport(port)


	def send(self, packet):
		"""
			@param packet a packet.
			Sends the given packet.
			This function takes care of checksum calculation, etc.
		"""
		# TODO change implementation...
		pass
		#send(packet, verbose=False)


class Packet(object):

	def __init__(self, raw_data):
		self.raw_data = raw_data
		self.load()

	def load(self):
		header, identify, ttl, proto, src, dest = struct.unpack("! B 3x H 2x B B 2x 4s 4s", self.raw_data[:20])
		self.header = header
		self.identify = 0x3804 #identify
		self.version = header >> 4
		self.header_length = (header & 0xf) * 4
		self.ttl = ttl
		self.proto = proto
		self.src = self.get_address(src)
		self.dest = self.get_address(dest)
		self.data = self.raw_data[self.header_length:]

	def get_address(self, num):
		return socket.inet_ntoa(num)

	def get_address_number(self, ip):
		return socket.inet_aton(ip)

	def protocol_contains_port(self):
		if self.proto == 0x01 or self.proto == 0x02:
			return False
		return True

	def set_dport(self, port):
		if self.protocol_contains_port():
			sport, dport = struct.unpack("! H H", self.data[:4])
			dport = port
			port_data = struct.pack("! H H", sport, dport)
			self.data = port_data + self.data[4:]

	def set_sport(self, port):
		if self.protocol_contains_port():
			sport, dport = struct.unpack("! H H", self.data[:4])
			sport = port
			port_data = struct.pack("! H H", sport, dport)
			self.data = port_data + self.data[4:]

	def get_dport(self):
		if self.protocol_contains_port():
			sport, dport = struct.unpack("! H H", self.data[:4])
			return dport
		return 0

	def get_sport(self):
		if self.protocol_contains_port():
			sport, dport = struct.unpack("! H H", self.data[:4])
			return sport
		return 0

	def get_src_ip(self):
		return self.src

	def get_dest_ip(self):
		return self.dest

	def get_raw_data(self):
		if self.proto == 6: # tcp
			offset = (ord(self.data[12]) & 0xf)
			index = offset * 4
			return self.data[index:]
		if self.proto == 17: # udp
			return self.data[8:]
		return ""

	def calc_checksum(self, headers):
		cksum = 0
		pointer = 0
		size = self.header_length
		array = [int(ord(a)) for a in headers]#self.raw_data[:size]]
		# make the previous checksum zero
		array[10] = 0
		array[11] = 0
		while size > 1:
			cksum += int((str("%02x" % (array[pointer],)) + \
					str("%02x" % (array[pointer+1],))), 16)
			size -= 2
			pointer += 2
		if size:
			cksum += ip_header[pointer]
		cksum = (cksum >> 16) + (cksum & 0xffff)
		cksum += (cksum >>16)
		return (~cksum) & 0xFFFF

	def generate_headers(self):
		headers = struct.pack("! B", self.header) + self.raw_data[1:4] + struct.pack("! H", self.identify)
		headers += self.raw_data[6:8] + struct.pack("B B", self.ttl, self.proto)
		headers += "\x00\x00" + struct.pack("4s 4s", self.get_address_number(self.src), self.get_address_number(self.dest))
		headers += self.raw_data[20:self.header_length]
		return headers

	def __str__(self):
		headers = self.generate_headers()
		#data = (self.header, self.ttl, self.proto, self.get_address_number(self.src), self.get_address_number(self.dest))
		#headers = struct.pack("! B", self.header) + self.raw_data[1:4] + struct.pack("! H", self.identify)
		#headers += self.raw_data[6:8] + struct.pack("B B", self.ttl, self.proto)
		#headers += self.raw_data[10:12] + struct.pack("4s 4s", self.get_address_number(self.src), self.get_address_number(self.dest))
		checksum = struct.pack("! H", self.calc_checksum(headers))
		headers = headers[:10] + checksum + headers[12:]
		#return headers + "".join(self.raw_data[20:self.header_length])\
		return headers + "".join(self.data)

def fix_packet(packet):
	packet = IP(packet)
	del packet.chksum
	if UDP in packet:
		del packet[UDP].chksum
	if TCP in packet:
		del packet[TCP].chksum
	packet = packet.__class__(str(packet))
	return str(packet[IP])

def send_packet(packet):
	packet = IP(packet)
	del packet.chksum
	if UDP in packet:
		del packet[UDP].chksum
	if TCP in packet:
		del packet[TCP].chksum
	packet = packet.__class__(str(packet))
	send(packet, verbose=False)
