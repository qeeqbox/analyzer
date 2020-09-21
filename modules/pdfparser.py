__G__ = "(G)bd249ce4"

from re import DOTALL, MULTILINE, compile, findall
from magic import from_buffer
from zlib import decompress
from copy import deepcopy
from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout
from analyzer.mics.funcs import get_words_multi_filesarray, get_words

class PDFParser:
	@verbose(True, verbose_flag, verbose_timeout, "Starting PDFParser")
	def __init__(self):
		self.datastruct = {  "Count":{}, 
							 "Object":[], 
							 "Stream":[], 
							 "JS":[], 
							 "Javascript":[], 
							 "OpenAction":[], 
							 "Launch":[], 
							 "URI":[], 
							 "Action":[], 
							 "GoTo":[], 
							 "RichMedia":[], 
							 "AA":[], 
							 "_Count":{}, 
							 "_Object":["Object", "Value"], 
							 "_Stream":["Stream", "Parsed", "Value"], 
							 "_JS":["Key", "Value"], 
							 "_Javascript":["Key", "Value"], 
							 "_Launch":["Key", "Value"], 
							 "_OpenAction":["Key", "Value"], 
							 "_URI":["Key", "Value"], 
							 "_Action":["Key", "Value"], 
							 "_GoTo":["Key", "Value"], 
							 "_RichMedia":["Key", "Value"], 
							 "_AA":["Key", "Value"]}

		self.Objectsdetection = compile(br'(\d+\s\d)+\sobj([\s\S]*?\<\<([\s\S]*?))endobj',DOTALL|MULTILINE)
		self.Streamdetection = compile(br'.*?FlateDecode.*?stream(.*?)endstream', DOTALL|MULTILINE)
		self.jsdetection = compile(br'/JS([\S][^>]+)',DOTALL|MULTILINE)
		self.javascriptdetection = compile(br'/JavaScript([\S][^>]+)',DOTALL|MULTILINE)
		self.OpenActiondetection = compile(br'/OpenAction([\S][^>]+)',DOTALL|MULTILINE)
		self.Launchdetection = compile(br'/Launch([\S][^>]+)',DOTALL|MULTILINE)
		self.URIdetection = compile(br'/URI([\S][^>]+)',DOTALL|MULTILINE)
		self.Actiondetection = compile(br'/Action([\S][^>]+)',DOTALL|MULTILINE)
		self.GoTodetection = compile(br'/GoTo([\S][^>]+)',DOTALL|MULTILINE)
		self.RichMediadetection = compile(br'/RichMedia([\S][^>]+)',DOTALL|MULTILINE)
		self.AAdetection = compile(br'/AA([\S][^>]+)',DOTALL|MULTILINE)

	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_object(self, pdf) -> (str, list):
		'''
		get objects from pdf by regex
		'''
		_List = []
		Objects = findall(self.Objectsdetection, pdf)
		for _ in Objects:
			_List.append({"Object":_[0].decode("utf-8", errors="ignore"), "Value":_[1].decode('utf-8', errors="ignore")})
		return len(Objects), _List

	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_stream(self, pdf) -> (str, list, list):
		'''
		get streams from pdf by regex
		'''
		_List = []
		_Streams = []
		Streams = findall(self.Streamdetection, pdf)
		for _ in Streams:
			parsed = None
			parseddecode = None
			x = _.strip(b"\r").strip(b"\n")
			mime = from_buffer(x, mime=True)
			if mime == "application/zlib":
				parsed = decompress(x)
				parseddecode = parsed.decode("utf-8", errors="ignore")
				_Streams.append(parsed)
			_List.append({"Stream":mime, "Parsed":parseddecode, "Value":x.decode('utf-8', errors="ignore")})
		return len(Streams), _List, _Streams

	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_js(self, pdf) -> (str, list):
		'''
		get JS from pdf by regex
		'''
		_List = []
		jslist = findall(self.jsdetection, pdf)
		for _ in jslist:
			_List.append({"Key":"/JS", "Value":_.decode("utf-8", errors="ignore")})
		return len(jslist), _List

	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_javascript(self, pdf) -> (str, list):
		'''
		get JavaScript from pdf by regex
		'''
		_List = []
		Javascriptlist = findall(self.javascriptdetection, pdf)
		for _ in Javascriptlist:
			_List.append({"Key":"/JavaScript", "Value":_.decode("utf-8", errors="ignore")})
		return len(Javascriptlist), _List

	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_openaction(self, pdf) -> (str, list):
		'''
		get openactions from pdf by regex
		'''
		_List = []
		OpenActionlist = findall(self.OpenActiondetection, pdf)
		for _ in OpenActionlist:
			_List.append({"Key":"/OpenAction", "Value":_.decode("utf-8", errors="ignore")})
		return len(OpenActionlist), _List

	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_lunch(self, pdf) -> (str, list):
		'''
		get Launch from pdf by regex
		'''
		_List = []
		Launchlist = findall(self.Launchdetection, pdf)
		for _ in Launchlist:
			_List.append({"Key":"/Launch", "Value":_.decode("utf-8", errors="ignore")})
		return len(Launchlist), _List

	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_uri(self, pdf) -> (str, list):
		'''
		get URI from pdf by regex
		'''
		_List = []
		URIlist = findall(self.URIdetection, pdf)
		for _ in URIlist:
			_List.append({"Key":"/URI", "Value":_.decode("utf-8", errors="ignore")})
		return len(URIlist), _List

	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_action(self, pdf) -> (str, list):
		'''
		get Action from pdf by regex
		'''
		_List = []
		Actionlist = findall(self.Actiondetection, pdf)
		for _ in Actionlist:
			_List.append({"Key":"/Action", "Value":_.decode("utf-8", errors="ignore")})
		return len(Actionlist), _List

	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_gotor(self, pdf) -> (str, list):
		'''
		get GoToR from pdf by regex
		'''
		_List = []
		Gotorlist = findall(self.GoTodetection, pdf)
		for _ in Gotorlist:
			_List.append({"Key":"/GoToR", "Value":_.decode("utf-8", errors="ignore")})
		return len(Gotorlist), _List


	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_richmedia(self, pdf) -> (str, list):
		'''
		get RichMedia from pdf by regex
		'''
		_List = []
		Richmedialist = findall(self.RichMediadetection, pdf)
		for _ in Richmedialist:
			_List.append({"Key":"/RichMedia", "Value":_.decode("utf-8", errors="ignore")})
		return len(Richmedialist), _List

	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_aa(self, pdf) -> (str, list):
		'''
		get AA from pdf by regex
		'''
		_List = []
		aalist = findall(self.AAdetection, pdf)
		for _ in aalist:
			_List.append({"Key":"/AA", "Value":_.decode("utf-8", errors="ignore")})
		return len(aalist), _List

	@verbose(True, verbose_flag, verbose_timeout, None)
	def check_sig(self, data) -> bool:
		'''
		check if mime is pdf
		'''
		if data["Details"]["Properties"]["mime"] == "application/pdf":
			return True


	@verbose(True, verbose_flag, verbose_timeout, "Analyzing PDF file")
	def analyze(self, data):
		'''
		start analyzing pdf logic, get pdf objects, 
		get words and wordsstripped from buffers if streams exist 
		otherwise get words and wordsstripped from file
		'''
		_Streams = []
		data["PDF"] = deepcopy(self.datastruct)
		f = data["FilesDumps"][data["Location"]["File"]]
		objlen, objs = self.get_object(f)
		strlen, strs, _Streams = self.get_stream(f)
		jslen, jslist = self.get_js(f)
		jalen, jaslist = self.get_javascript(f)
		oalen, oalist = self.get_openaction(f)
		llen, llist = self.get_lunch(f)
		ulen, ulist = self.get_uri(f)
		alen, alist = self.get_action(f)
		gtrlen, gtrlist = self.get_gotor(f)
		rmlen, rmlist = self.get_richmedia(f)
		aalen, aalist = self.get_aa(f)

		data["PDF"]["Count"] = { "Object" :objlen, 
								  "Stream" :strlen, 
								  "JS" :jslen, 
								  "Javascript" :jalen, 
								  "OpenAction" :oalen, 
								  "Launch" :llen, 
								  "URI" :ulen, 
								  "Action" :alen, 
								  "GoTo" :gtrlen, 
								  "RichMedia" :rmlen, 
								  "AA" :aalen}

		data["PDF"]["Object"] = objs
		data["PDF"]["JS"] = jslist
		data["PDF"]["Javascript"] = jaslist
		data["PDF"]["OpenAction"] = oalist
		data["PDF"]["Launch"] = llist
		data["PDF"]["URI"] = ulist
		data["PDF"]["Action"] = alist
		data["PDF"]["GoTo"] = gtrlist
		data["PDF"]["RichMedia"] = rmlist
		data["PDF"]["AA"] = aalist
		data["PDF"]["Stream"] = strs

		if len(_Streams) > 0:
			get_words_multi_filesarray(data, _Streams)
		else:
			get_words(data, _Streams)