__G__ = "(G)bd249ce4"

from email import message_from_bytes, policy
from email.parser import BytesParser
from hashlib import md5
from random import choice
from os import path, mkdir
from string import ascii_lowercase
from re import match
from magic import from_file
from mimetypes import guess_type
from copy import deepcopy
from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout
from analyzer.mics.funcs import get_words_multi_filesarray, get_words

class EmailParser():
	@verbose(True, verbose_flag, verbose_timeout, "Starting EmailParser")
	def __init__(self):
		self.datastruct = { "General":[], 
							"Parsed":"", 
							"Attachments":[], 
							"_General":["Key", "Value", "descriptions"], 
							"_Parsed":"", 
							"_Attachments":["Name", "Type", "Extension", "md5", "Path"]}

	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_attachment(self, data, msg) -> list:
		'''
		get attachment of email
		'''

		_Stream = []

		if msg.get_content_maintype() == 'multipart':
			for attachment in msg.walk():
				if attachment.get_content_maintype() == 'multipart':continue
				if attachment.get('Content-Disposition') is None:continue
				tempstring = "".join([choice(ascii_lowercase) for _ in range(5)])
				safename = "temp_"+tempstring
				file = path.join(data["Location"]["Folder"], safename)
				tempfilename = "temp"+"".join([c for c in attachment.get_filename() if match(r'[\w\.]', c)])
				buffer = attachment.get_payload(decode=True)
				with open(file, "wb") as f:
					f.write(buffer)
					_md5 = md5(buffer).hexdigest()
					mime = from_file(file, mime=True)
					data["EMAIL"]["Attachments"].append({"Name":attachment.get_filename(), 
														 "Type":mime, 
														 "Extension":guess_type(tempfilename)[0], 
														 "Path":file, 
														 "md5":_md5})
					data[tempstring] = { "Attached":"", 
										 "_Attached":""}
					data[tempstring]["Attached"] = buffer.decode("utf-8", errors="ignore")
					_Stream.append(buffer)
		return _Stream

	@verbose(True, verbose_flag, verbose_timeout, None)
	def check_attachment_and_make_dir(self, data, msg) -> (bool):
		'''
		check if an email has attachments or not
		'''
		if msg.get_content_maintype() == 'multipart':
			for attachment in msg.walk():
				if attachment.get_content_maintype() == 'multipart':continue
				if attachment.get('Content-Disposition') is None:continue
				if not path.isdir(data["Location"]["Folder"]):
					mkdir(data["Location"]["Folder"])
				return True

	@verbose(True, verbose_flag, verbose_timeout, "Getting email content")
	def get_content_multi(self, data, msg) -> list:
		'''
		get email content multipart
		'''
		_Parts = []
		counter = 1
		if msg.is_multipart():
			for part in msg.get_payload():
				tempstring = "".join([choice(ascii_lowercase) for _ in range(5)])
				temppart = "Part {}".format(counter)
				data[tempstring] = { temppart:"", 
									 "_"+temppart:""}
				data[tempstring][temppart] = part.get_payload()
				_Parts.append(bytes(part.get_payload(), 'utf8'))
				counter += 1
		else:
			body = msg.get_payload()
			tempstring = "".join([choice(ascii_lowercase) for _ in range(5)])
			temppart = "Part {}".format(counter)
			data[tempstring] = { temppart:"", 
								 "_"+temppart:""}
			data[tempstring][temppart] = body.get_payload()
			_Parts.append(bytes(body.get_payload(), 'utf8'))
			counter += 1

		return _Parts

	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_content(self, data, path) -> str:
		'''
		get email content parsed
		'''
		with open(path, 'rb') as file:
			msg = BytesParser(policy=policy.default).parse(file)
			data["Parsed"] = msg.get_body(preferencelist=('plain')).get_content()

	@verbose(True, verbose_flag, verbose_timeout, None)
	def get_headers(self, data, msg) -> list:
		'''
		get email headers by buffer
		'''

		_Headers = []

		#with open(path, 'r') as file:
		#    headers = HeaderParser().parse(file, headersonly=True)
		#    for key, value in headers.items():
		#        data.update({key:value.replace('\n', ' ').replace('\t', ' ').replace('\r', ' ')})

		for key, value in msg.items():
			data.append({"Key":key, "Value":value, "descriptions":""})
			try:
				_Headers.append(str.encode(value)) # convert to bytes...
			except:
				pass
		return _Headers

	@verbose(True, verbose_flag, verbose_timeout, None)
	def check_sig(self, data) -> bool:
		'''
		check mime if it contains message or not
		'''
		if "message" in data["Details"]["Properties"]["mime"] or \
			data["Location"]["Original"].endswith(".eml"):
			return True

	@verbose(True, verbose_flag, verbose_timeout, "Starting analyzing email")
	def analyze(self, data, parsed):
		'''
		start analyzing exe logic, add descriptions and get words and wordsstripped from array 
		'''
		Streams = []
		Parts = []
		Mixed = []
		Headers = []
		data["EMAIL"] = deepcopy(self.datastruct)
		f = data["FilesDumps"][data["Location"]["File"]]
		message = message_from_bytes(f)
		Headers = self.get_headers(data["EMAIL"]["General"], message)
		self.get_content(data["EMAIL"], data["Location"]["File"])
		Parts = self.get_content_multi(data, message)
		if self.check_attachment_and_make_dir(data, message):
			Streams = self.get_attachment(data, message)
		else:
			pass
		Mixed = Streams + Parts + Headers
		if len(Mixed) > 0:
			get_words_multi_filesarray(data, Mixed) #have to be bytes < will check this later on
		else:
			get_words(data, data["Location"]["File"])
		parsed.type = "email"