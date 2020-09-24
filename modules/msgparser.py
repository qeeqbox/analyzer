'''
    __G__ = "(G)bd249ce4"
    modules -> msg
'''

from hashlib import md5
from random import choice
from os import path, mkdir
from string import ascii_lowercase
from re import match
from copy import deepcopy
from mimetypes import guess_type
from magic import from_file
from extract_msg import Message
from analyzer.logger.logger import ignore_excpetion, verbose
from analyzer.mics.funcs import get_words_multi_filesarray, get_words

class MSGParser():
    '''
    MSGParser extracts artifacts from emails
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting MSGParser")
    def __init__(self):
        '''
        initialize class and datastruct, this has to pass
        '''
        self.datastruct = {"General":[],
                           "Parsed":"",
                           "Attachments":[],
                           "_General":["Key", "Value", "descriptions"],
                           "_Parsed":"",
                           "_Attachments":["Name", "Type", "Extension", "md5", "Path"]}

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_attachment(self, data, msg) -> list:
        '''
        get attachment of msg
        '''
        streams = []
        if msg.attachments != 0:
            for attachment in msg.attachments:
                tempstring = "".join([choice(ascii_lowercase) for _ in range(5)])
                safename = "temp_"+tempstring
                file = path.join(data["Location"]["Folder"], safename)
                tempfilename = "temp"+"".join([c for c in attachment.longFilename if match(r'[\w\.]', c)])
                buffer = attachment.data
                with open(file, "wb") as temp_file:
                    temp_file.write(buffer)
                    _md5 = md5(buffer).hexdigest()
                    mime = from_file(file, mime=True)
                    data["MSG"]["Attachments"].append({"Name":attachment.longFilename,
                                                       "Type":mime,
                                                       "Extension":guess_type(tempfilename)[0],
                                                       "Path":file,
                                                       "md5":_md5})
                    data[tempstring] = {"Attached":"",
                                        "_Attached":""}
                    data[tempstring]["Attached"] = buffer.decode("utf-8", errors="ignore")
                    streams.append(buffer)
        return streams

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_attachment_and_make_dir(self, data, msg) -> (bool):
        '''
        check if an email has attachments or not
        '''
        if msg.attachments != 0:
            if not path.isdir(data["Location"]["Folder"]):
                mkdir(data["Location"]["Folder"])
            return True
        return False

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_content(self, data, msg):
        '''
        get msg content parsed
        '''
        data["Parsed"] = msg.body

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_headers(self, data, msg) -> list:
        '''
        get msg headers by buffer
        '''
        headers = []
        for key, value in msg.header.items():
            data.append({"Key":key, "Value":value, "descriptions":""})
            with ignore_excpetion(Exception):
                headers.append(str.encode(value)) # convert to bytes...
        return headers

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig(self, data) -> bool:
        '''
        check mime if it contains message or not
        '''
        if "vnd.ms-outlook" in data["Details"]["Properties"]["mime"] or \
            data["Location"]["Original"].endswith(".msg"):
            return True
        return False

    @verbose(True, verbose_output=False, timeout=None, _str="Starting analyzing msg")
    def analyze(self, data, parsed):
        '''
        start analyzing exe logic, add descriptions and get words and wordsstripped from array (need to implement from extract_msg.dev_classes import Message)
        '''
        streams = []
        parts = []
        mixed = []
        headers = []
        data["MSG"] = deepcopy(self.datastruct)
        message = Message(data["Location"]["File"])
        headers = self.get_headers(data["MSG"]["General"], message)
        self.get_content(data["MSG"], message)
        if self.check_attachment_and_make_dir(data, message):
            streams = self.get_attachment(data, message)
        else:
            pass
        mixed = streams + parts + headers
        if len(mixed) > 0:
            get_words_multi_filesarray(data, mixed) #have to be bytes < will check this later on
        else:
            get_words(data, data["Location"]["File"])
        parsed.type = "msg"
