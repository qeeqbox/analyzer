__G__ = "(G)bd249ce4"

from re import sub
from xml.dom.minidom import parseString
from xml.etree.cElementTree import XML as cetXML
from copy import deepcopy
from oletools.olevba3 import VBA_Parser
from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout
from analyzer.mics.funcs import get_words_multi_files
from analyzer.modules.archive import check_packed_files, unpack_file

class Officex:
	@verbose(True, verbose_flag, verbose_timeout, "Starting Officex")
	def __init__(self):
		self.datastruct ={   "General":{}, 
							 "Text":"", 
							 "Hyper":[], 
							 "Other":[], 
							 "Macro":[], 
							 "DDE":[], 
							 "_General":{}, 
							 "_Text":"", 
							 "_Hyper":["Count", "Link"], 
							 "_Other":["Count", "Link"], 
							 "_Macro":["Name", "VBA"], 
							 "_DDE":""}

		self.word_namespace = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
		self.para = self.word_namespace + 'p'
		self.text = self.word_namespace + 't'
		self.instrText = self.word_namespace + 'instrText'

	@verbose(True, verbose_flag, verbose_timeout, None)
	def office_analysis(self, data) -> dict:
		'''
		get hyber links or other links by regex
		'''
		_dict = {"Hyber":[], "Other":[]}
		_temp = {"Hyber":[], "Other":[]}
		for i, v in enumerate(data["Packed"]["Files"]):
			if v["Name"].lower().endswith(".xml"):
				try:
					x = parseString(open(v["Path"]).read()).toprettyxml(indent='  ')
					for hyber in re.findall('http.*?\<', x):
						_dict["Hyber"].append(hyber)
					for hyber in re.findall('(http.*?) ', x):
						_dict["Other"].append(hyber[:-1]) #-1 for "
				except:
					pass
		for key in _dict.keys():
			for x in set(_dict[key]):
				_temp[key].append({"Count":_dict[key].count(x), "Link":x})
		return _temp

	@verbose(True, verbose_flag, verbose_timeout, None)
	def office_read_bin(self, data):
		'''
		get all bins from office
		'''
		for i, v in enumerate(data["Packed"]["Files"]):
			if v["Name"].lower().endswith(".bin"):
				k = 'Office_bin_{}'.format(i)
				data[k] = { "Bin_Printable":"", 
							"_Bin_Printable":""}
				
				x = open(v["Path"], "r", encoding="utf-8", errors='ignore').read()
				data[k]["Bin_Printable"] = sub(r'[^\x20-\x7F]+', '', x)

	@verbose(True, verbose_flag, verbose_timeout, None)
	def office_meta_info(self, data) -> dict:
		'''
		get office meta data
		'''
		_dict = {}
		corePropNS = '{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}'
		meta = ["filename", "title", "subject", "creator", "keywords", "description", "lastModifiedBy", "revision", "modified", "created"]
		for i, v in enumerate(data["Packed"]["Files"]):
			if v["Name"].lower() == "core.xml":
				tree = cetXML(open(v["Path"], "rb").read())
				for item in meta:
					x = tree.find("{}{}".format(corePropNS, item))
					if x is not None:
						_dict.update({item:x.text})
				break
		return _dict

	@verbose(True, verbose_flag, verbose_timeout, None)
	def extract_text(self, data) -> str:
		text = []
		for i, v in enumerate(data["Packed"]["Files"]):
			if v["Name"].lower() == "document.xml":
				tree = cetXML(open(v["Path"], "rb").read())
				for par in tree.iter(self.para):
					text.append(''.join(node.text for node in par.iter(self.text)))
		return '\n'.join(text)

	@verbose(True, verbose_flag, verbose_timeout, None)
	def extract_dde(self, data) -> str:
		text = []
		for i, v in enumerate(data["Packed"]["Files"]):
			if v["Name"].lower() == "document.xml":
				tree = cetXML(open(v["Path"], "rb").read())
				for par in tree.iter(self.para):
					string = ''.join(node.text for node in par.iter(self.instrText))
					if len(string):
						text.append(string)
		return '\n'.join(text)

	@verbose(True, verbose_flag, verbose_timeout, None)
	def extract_macros(self, path) -> list:
		'''
		Extract macros
		'''
		List = []
		try:
			for (f, s, vbaname, vbacode) in VBA_Parser(path).extract_macros():
				List.append({"Name":vbaname, "VBA":vbacode})
		except:
			pass
		return List

	@verbose(True, verbose_flag, verbose_timeout, None)
	def check_sig(self, data) -> bool:
		'''
		check if file is office or contains [Content_Types].xml
		'''
		if "application/vnd.openxmlformats-officedocument" in data["Details"]["Properties"]["mime"] or \
			check_packed_files(data["Location"]["File"], ["[Content_Types].xml"]):
				unpack_file(data, data["Location"]["File"])
				return True


	@verbose(True, verbose_flag, verbose_timeout, "Analyzing office[x] file")
	def analyze(self, data):
		'''
		start analyzing office logic, get office meta informations add description 
		to strings, get words and wordsstripped from the packed files 
		'''
		data["Office"] = deepcopy(self.datastruct)
		data["Office"]["General"] = self.office_meta_info(data)
		data["Office"]["Text"] = self.extract_text(data)
		data["Office"]["DDE"] = self.extract_dde(data)
		data["Office"]["Macro"] = self.extract_macros(data["Location"]["File"])
		data["Office"].update(self.office_analysis(data))
		self.office_read_bin(data)
		get_words_multi_files(data, data["Packed"]["Files"])
