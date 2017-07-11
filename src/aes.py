###################################################################
#
#                      Python Network Tunnel
#                        	AES Encryption
#
# Author: Nir Haike
#
###################################################################

from Crypto.Cipher import AES
import base64
import random
import debug

class AESSession(object):

	def __init__(self, key=""):
		# blocks padding
		self.padding = 16
		# encryption key
		self.key = key
		self.ivs = ["2FqTFHOqVprpOewD", "B8Yy1PefK9J6Q1Yg", "17vnnVuvDrkOU8RN", "SfQZFe9JTr2raO5E",
       				"TSOPWt5miyJNHHt3", "gaWBOQVXvOh5zpaP", "q7sDMKFa1sQ4Lzft", "0xHsuDoMPuMwp5W1",
	       			"YjkSxh8NRtLnjvnu", "NDsx0KwJyklnVtaj", "SsTClsNlBQ3FJbI8", "zxeI6RFjxlTevmkF",
       				"r8nR0Q0iZ8CBSgDG", "Fzc2zEjq5ZemhMo6", "vipSAXrqs0zm3Rzt", "qW6pRg6Hskw9rV82",
	       			"WDRHyf13xbFbgeHs", "Y0oxcTJwXMqGtW5G", "EuMOpLejvjCbpefs", "DV0PhrlWRB68nAH6",
       				"XJfsIBY2fQZOmucz", "II4NmLvCHEZg4zar", "T55aKZpSXOR77nP3", "xktD6nXeI7eo3L2X",
       				"o4AQDMIR0ejMnFti", "lzsobxc0ql2AGP4i", "3eCuX224H7BLnizE", "1xQOBNqMkfYZzi03",
       				"QFnC1MOBARvghfD2", "K7qqbSDJ8v2aEVX2", "muoaZa3nrzTa9gRu", "HAUDNVS5hBGqYRxS"]

	def encrypt(self, data, iv=None):
		"""
			Encrypts data given the initial vector.
		"""
		num = 0xff
		if not iv:
			# use one of the default MobileVPN IVs
			num = random.randint(0, 31)
			iv = self.ivs[num]
		# encrypt the data
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		padded = self.add_padding(data)
		return chr(num) + base64.b64encode(cipher.encrypt(padded))

	def decrypt(self, data, iv=None):
		"""
			Decrypts data given the initial vector.
		"""
		if not iv: # in this case the IV is included in the packet
			# get the first byte of the data
			try:
				b = int(data[0])
			except:
				b = ord(data[0])
			# use the given default MobileVPN IV
			iv = self.ivs[b%len(self.ivs)]
			data = data[1:]
		# decode from base64
		data = base64.b64decode(data)
		# decrypt the data
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		decrypted = cipher.decrypt(data)
		return self.remove_padding(decrypted)

	def add_padding(self, data):
		"""
			Adds padding to the data (to make
			the size divisible by 16).
		"""
		pad = self.padding - len(data) % self.padding
		return data + pad * chr(pad)

	def remove_padding(self, data):
		return data[0:-ord(data[-1])]

