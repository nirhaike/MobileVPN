###################################################################
#
#                      Python Network Tunnel
#                          Binary Reader
#
# Author: Nir Haike
#
###################################################################



class BinaryReader(object):

	def __init__(self, data):
		self.data = data

	def read_string(self):
		end = self.data.find("\x00")
		if end == -1:
			return ""
		st = self.data[:end]
		self.data = self.data[end+1:]
		return st

	def read_byte(self):
		b = self.data[0]
		self.data = self.data[1:]
		return ord(b)

	def read_int(self):
		val = 0
		for i in range(4):
			val += ord(self.data[3-i]) << (i*8)
		self.data = self.data[4:]
		return val

	def read_bytes(self, amount):
		dat = self.data[:amount]
		self.data = self.data[amount:]
		return dat