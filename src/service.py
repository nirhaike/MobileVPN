###################################################################
#
#                      Python Network Tunnel
#                     Abstract Service Thread
#
# Author: Nir Haike
#
###################################################################

import time

class ServiceThread(object):
	"""
		Represents a thread that is functioning as a service.
	"""
	def __init__(self):
		self.update_time = time.time()

	def update(self):
		self.update_time = time.time()

	def get_update_time(self):
		return time.time() - self.update_time

	def get_last_update_time(self):
		return self.update_time