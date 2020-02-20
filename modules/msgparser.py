__G__ = "(G)bd249ce4"

from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout
from analyzer.mics.funcs import get_words_multi_filesarray,get_words
from hashlib import md5
from random import choice
from os import path,mkdir
from string import ascii_lowercase
from re import match
from magic import from_file
from mimetypes import guess_type
from copy import deepcopy
from extract_msg import Message

class MSGParser():
    @verbose(True,verbose_flag,verbose_timeout,"Starting MSGParser")
    def __init__(self):
        self.datastruct = { "General": [],
                            "Parsed":"",
                            "Attachments": [],
                            "_General": ["Key","Value","descriptions"],
                            "_Parsed":"",
                            "_Attachments": ["Name","Type","Extension","md5","Path"]}

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_attachment(self,data, msg) -> list:
        '''
        get attachment of msg
        '''

        _Stream = []
        if msg.attachments != 0:
            for attachment in msg.attachments:
                tempstring = "".join([choice(ascii_lowercase) for _ in range(5)])
                safename = "temp_"+tempstring
                file = path.join(data["Location"]["Folder"], safename)
                tempfilename = "temp"+"".join([c for c in attachment.longFilename if match(r'[\w\.]', c)])
                buffer = attachment.data
                with open(file,"wb") as f:
                    f.write(buffer)
                    _md5 = md5(buffer).hexdigest()
                    mime = from_file(file,mime=True)
                    data["MSG"]["Attachments"].append({"Name":attachment.longFilename,
                                                         "Type":mime,
                                                         "Extension":guess_type(tempfilename)[0],
                                                         "Path":file,
                                                         "md5":_md5})
                    data[tempstring] = { "Attached":"",
                                         "_Attached":""}
                    data[tempstring]["Attached"] = buffer.decode("utf-8",errors="ignore")
                    _Stream.append(buffer)
        return _Stream

    @verbose(True,verbose_flag,verbose_timeout,None)
    def check_attachment_and_make_dir(self,data, msg) -> (bool):
        '''
        check if an email has attachments or not
        '''
        if msg.attachments != 0:
            if not path.isdir(data["Location"]["Folder"]):
                mkdir(data["Location"]["Folder"])
            return True

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_content(self,data,msg) -> str:
        '''
        get msg content parsed
        '''
        data["Parsed"] = msg.body

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_headers(self,data,msg) -> list:
        '''
        get msg headers by buffer
        '''

        _Headers = []

        for key, value in msg.header.items():
            data.append({"Key":key,"Value":value,"descriptions":""})
            try:
                _Headers.append(str.encode(value)) # convert to bytes...
            except:
                pass
        return _Headers

    @verbose(True,verbose_flag,verbose_timeout,None)
    def check_sig(self, data) -> bool:
        '''
        check mime if it contains message or not
        '''
        if "vnd.ms-outlook" in data["Details"]["Properties"]["mime"] or \
            data["Location"]["Original"].endswith(".msg"):
            return True

    @verbose(True,verbose_flag,verbose_timeout,"Starting analyzing msg")
    def analyze(self, data, parsed):
        '''
        start analyzing exe logic, add descriptions and get words and wordsstripped from array 
        '''
        Streams = []
        Parts = []
        Mixed = []
        Headers = []
        data["MSG"] = deepcopy(self.datastruct)
        message = Message(data["Location"]["File"])
        Headers = self.get_headers(data["MSG"]["General"],message)
        self.get_content(data["MSG"],message)
        if self.check_attachment_and_make_dir(data,message):
            Streams = self.get_attachment(data,message)
        else:
            pass
        Mixed = Streams + Parts + Headers
        if len(Mixed) > 0:
            get_words_multi_filesarray(data,Mixed) #have to be bytes < will check this later on
        else:
            get_words(data,data["Location"]["File"])
        parsed.type = "msg"