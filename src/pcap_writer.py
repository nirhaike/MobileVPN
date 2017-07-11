###################################################################
#
#                      Python Network Tunnel
#                           PCAP writer
#
# Author: Nir Haike
#
###################################################################

import os
import time
import debug
import struct
import zipfile
import threading

from os.path import basename


class PcapWriter(object):

	def __init__(self, filename, config):
		self.filename = filename
		self.mutex = threading.Lock()
		self.config = config
		self.count = 0
		# remember all saved .pcap files
		self.parts = []
		self.start_file()

	def start_file(self, inside=False):
		if not inside:
			self.mutex.acquire()
		# magic number
		self.fdata = "\xD4\xC3\xB2\xA1"
		# version
		self.fdata += "\x02\x00\x04\x00"
		# timestamp
		self.fdata += "\x00" * 8
		# max packet length (2^16)
		self.fdata += "\xFF\xFF\x00\x00"
		# Link-Layer header type (LINKTYPE_RAW = 101)
		self.fdata += "\x65\x00\x00\x00"
		if not inside:
			self.mutex.release()

	def write_packet(self, data):
		self.mutex.acquire()
		self.count += 1
		# timestamp (little endian)
		self.fdata += "\x00\x00\x00\x00"#struct.pack("<L", time.time())
		# time in seconds
		self.fdata += "\x00\x00\x00\x00"#struct.pack("<L", time.clock())
		# size (twice, capture and wire)
		self.fdata += struct.pack("<L", len(data)) * 2
		# add the data
		self.fdata += data
		self.mutex.release()
		if len(self.fdata) >= self.config.PCAP_FILE_SIZE:
			self.write_file()

	def write_file(self):
		self.mutex.acquire()
		self.close()
		self.start_file(inside=True)
		self.mutex.release()

	def close(self):
		fname = os.getcwd() + "\\pcap\\" + (self.filename + "_" + debug.get_current_timestamp()[:-1].replace("/", "_")).replace(" ", "_").replace(":", "_") + ".pcap"
		self.parts.append(fname)
		f = open(fname, "wb")
		f.write(self.fdata)
		f.close()

	def get_packets_count(self):
		return self.count

	def create_zip(self):
		"""
		Creates a zip file of all the pcap parts and returns the binary data.
		"""
		# the zip file's name
		zip_name = os.getcwd() + "\\pcap\\" + self.filename + ".zip"
		# critical section
		self.mutex.acquire()
		# declare the zip file
		zf = zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED)
		# write the parts
		for fname in self.parts:
			zf.write(fname, basename(fname))
		# write the current part
		zf.writestr("partial.pcap", self.fdata)
		zf.close()
		# read the file
		f = open(zip_name, "rb")
		data = f.read()
		self.mutex.release()
		return data