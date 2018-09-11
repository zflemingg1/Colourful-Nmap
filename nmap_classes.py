class Host_Details:
	def __init__(self, hostname, host_os):
		self.hostname = hostname
		self.host_os = host_os
		self.scan_information = []
		
class Scan_Information:
	def __init__(self, protocol, port, state, service, product, version, extra_info, tunnel):
		self.protocol = protocol
		self.port = port
		self.state = state
		self.service = service
		self.product = product
		self.version = version
		self.extra_info = extra_info
		self.tunnel = tunnel
		self.script_info = []
		
class Script_Information:
	def __init__(self, script_name, script_output):
		self.script_name = script_name
		self.script_output = script_output
