__G__ = "(G)bd249ce4"

from ..logger.logger import log_string,verbose,verbose_flag,verbose_timeout
from ..mics.funcs import get_words_multi_filesarray
from email import message_from_bytes
from hashlib import md5
from random import choice
from os import path,mkdir
from string import ascii_lowercase
from re import match
from magic import from_file,Magic
from ssdeep import hash_from_file
from mimetypes import guess_type
from copy import deepcopy

class EmailParser():
    @verbose(True,verbose_flag,verbose_timeout,"Starting EmailParser")
    def __init__(self):
        self.datastruct = { "General": {},
                            "_General": {},
                            "Attachments": [],
                            "_Attachments": ["Name","Type","Extension","md5","Path"]}

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_attachment(self,data, msg) -> (list):
        '''
        get attachment of email
        '''

        _Stream = []

        if msg.get_content_maintype() == 'multipart':
            for attachment in msg.walk():
                if attachment.get_content_maintype() == 'multipart': continue
                if attachment.get('Content-Disposition') is None: continue
                tempstring = "".join([choice(ascii_lowercase) for _ in range(5)])
                safename = "temp_"+tempstring
                file = path.join(data["Location"]["Folder"], safename)
                tempfilename = "temp"+"".join([c for c in attachment.get_filename() if match(r'[\w\.]', c)])
                buffer = attachment.get_payload(decode=True)
                with open(file,"wb") as f:
                    f.write(buffer)
                    _md5 = md5(buffer).hexdigest()
                    mime = from_file(file,mime=True)
                    data["EMAIL"]["Attachments"].append({"Name":attachment.get_filename(),
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
        if msg.get_content_maintype() == 'multipart':
            for attachment in msg.walk():
                if attachment.get_content_maintype() == 'multipart': continue
                if attachment.get('Content-Disposition') is None: continue
                if not path.isdir(data["Location"]["Folder"]):
                    mkdir(data["Location"]["Folder"])
                return True

    @verbose(True,verbose_flag,verbose_timeout,None)
    def check_sig(self, data) -> bool:
        '''
        check mime if it contains message or not
        '''
        if "message" in data["Details"]["Properties"]["mime"] or \
            data["Location"]["Original"].endswith(".eml"):
            return True


    @verbose(True,verbose_flag,verbose_timeout,"Starting analyzing email")
    def analyze(self, data):
        '''
        start analyzing exe logic, add descriptions and get words and wordsstripped from array 
        '''
        data["EMAIL"] = deepcopy(self.datastruct)
        f = data["FilesDumps"][data["Location"]["File"]]
        message = message_from_bytes(f)
        if self.check_attachment_and_make_dir(data,message):
            Attachments = True
            Streams = self.get_attachment(data,message)
        else:
            Attachments = False
        data["EMAIL"]["General"] = {"From": message['From'],
                                    "To": message['To'],
                                    "Subject": message['Subject'],
                                    "Sender": message['Sender'],
                                    "X-Mailer": message['X-Mailer'],
                                    "MIME-Version": message['MIME-Version'],
                                    "Content-Type": message['Content-Type'],
                                    "Date": message['Date'],
                                    "Message-ID": message['Message-ID'],
                                    "Attachments":Attachments}
        if len(Streams) > 0:
            get_words_multi_filesarray(data,Streams)
