__G__ = "(G)bd249ce4"

from re import I, compile, findall
from binascii import unhexlify
from ipaddress import ip_address
from copy import deepcopy
from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout
from analyzer.mics.funcs import check_url
from analyzer.intell.qbdescription import add_description

class QBPatterns:
	@verbose(True, verbose_flag, verbose_timeout, "Starting QBPatterns")
	def __init__(self):
		self.datastruct = {  "IP4S":[], 
							 "IP4SANDPORT":[], 
							 "IP6S":[], 
							 "LINKS":[], 
							 "EMAILS":[], 
							 "TELS":[], 
							 "TAGS":[], 
							 "HEX":[], 
							 "_IP4S":["Count", "IP", "Code", "Alpha2", "Description"], 
							 "_IP4SANDPORT":["Count", "IP", "Port", "Description"], 
							 "_IP6S":["Count", "IP", "Code", "Alpha2", "Description"], 
							 "_LINKS":["Count", "Link", "Description"], 
							 "_EMAILS":["Count", "EMAIL", "Description"], 
							 "_TELS":["Count", "TEL", "Description"], 
							 "_TAGS":["Count", "TAG", "Description"], 
							 "_HEX":["Count", "HEX", "Parsed"]}


		self.links = compile(r"((?:(smb|srm|ssh|ftps|file|http|https|ftp):\/\/)?[a-zA-Z0-9]+(\.[a-zA-Z0-9-]+)+([a-zA-Z0-9_\,\'\/\+&amp;%#\$\?\=~\.\-]*[a-zA-Z0-9_\,\'\/\+&amp;%#\$\?\=~\.\-])?)", I)
		self.ip4 = compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\b', I)
		self.ip4andports = compile(r'\b((?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]):[0-9]{1,5})\b', I)
		self.ip6 = compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', I)
		self.email = compile(r'(\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*)', I)
		self.tel = compile(r'(\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*)', I)
		self.html = compile(r'>([^<]*)<\/', I)
		self.hex = compile(r'([0-9a-fA-F]{4,})', I)

	@verbose(True, verbose_flag, verbose_timeout, "Finding URLs patterns")
	def check_link(self, _data):
		'''
		check if buffer contains ips xxx://xxxxxxxxxxxxx.xxx
		'''
		_List = []
		x = list(set(findall(self.links, self.wordsstripped)))
		if len(x) > 0:
			for _ in x:
				if (check_url(_[0])):
					_List.append(_[0])
		for x in set(_List):
			_data.append({"Count":_List.count(x), "Link":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding IP4s patterns")
	def check_ip4(self, _data):
		'''
		check if buffer contains ips x.x.x.x
		'''
		_List = []
		x = findall(self.ip4, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				try:
					ip_address(_)
					_List.append(_)
				except:
					pass
		for x in set(_List):
			_data.append({"Count":_List.count(x), "IP":x, "Code":"", "Alpha2":"", "Description":""})

	@verbose(True, verbose_flag, verbose_timeout, "Finding IP4 ports patterns")
	def check_ip4_ports(self, _data):
		'''
		check if buffer contains ips x.x.x.x:xxxxx
		'''
		_List = []
		x = findall(self.ip4andports, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				try:
					ip, port = _.split(":")
					ip_address(ip)
					_List.append(_)
				except:
					pass
		for x in set(_List):
			ip, port = x.split(":")
			_data.append({"Count":_List.count(x), "IP":ip, "Port":port, "Description":""})

	@verbose(True, verbose_flag, verbose_timeout, "Finding IP6s patterns")
	def check_ip6(self, _data):
		'''
		check if buffer contains ips x.x.x.x
		'''
		_List = []
		x = findall(self.ip6, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			_data.append({"Count":_List.count(x), "IP":x, "Code":"", "Alpha2":"", "Description":""})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Emails patterns")
	def check_email(self, _data):
		'''
		check if buffer contains email xxxxxxx@xxxxxxx.xxx
		'''
		_List = []
		x = findall(self.email, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_[0])
		for x in set(_List):
			_data.append({"Count":_List.count(x), "EMAIL":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding TELs patterns")
	def check_phone_number(self, _data):
		'''
		check if buffer contains tel numbers 012 1234 567
		'''
		_List = []
		x = findall(self.tel, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			_data.append({"Count":_List.count(x), "TEL":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding tags patterns")
	def check_tags(self, _data):
		'''
		check if buffer contains tags <>
		'''
		_List = []
		x = findall(self.html, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			_data.append({"Count":_List.count(x), "TAG":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding HEX patterns")
	def check_hex(self, _data):
		'''
		check if buffer contains tags <>
		'''
		_List = []
		x = findall(self.hex, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			try:
				parsed = unhexlify(x)
				_data.append({"Count":_List.count(x), "HEX":x, "Parsed":parsed.decode('utf-8', errors="ignore")})
			except:
				pass

	@verbose(True, verbose_flag, verbose_timeout, None)
	def analyze(self, data):
		'''
		start pattern analysis for words and wordsstripped
		'''
		data["Patterns"] = deepcopy(self.datastruct)
		self.words = data["StringsRAW"]["wordsinsensitive"]
		self.wordsstripped = data["StringsRAW"]["wordsstripped"]
		self.check_link(data["Patterns"]["LINKS"])
		self.check_ip4(data["Patterns"]["IP4S"])
		self.check_ip4_ports(data["Patterns"]["IP4SANDPORT"])
		self.check_ip6(data["Patterns"]["IP6S"])
		self.check_email(data["Patterns"]["EMAILS"])
		self.check_tags(data["Patterns"]["TAGS"])
		self.check_hex(data["Patterns"]["HEX"])
		add_description("URLshorteners", data["Patterns"]["LINKS"], "Link")
		add_description("DNSServers", data["Patterns"]["IP4S"], "IP")
		add_description("ReservedIP", data["Patterns"]["IP4S"], "IP")
		add_description("CountriesIPs", data["Patterns"]["IP4S"], "IP")
		add_description("Ports", data["Patterns"]["IP4SANDPORT"], "Port")
		add_description("Emails", data["Patterns"]["EMAILS"], "EMAIL")