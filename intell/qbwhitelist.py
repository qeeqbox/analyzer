__G__ = "(G)bd249ce4"

from ..logger.logger import verbose, verbose_flag, verbose_timeout
from ..connections.mongodbconn import find_items
from re import I, compile
from copy import deepcopy

class QBWhitelist:
    @verbose(True,verbose_flag,verbose_timeout,"Starting QBWhitelist")
    def __init__(self):
        self.datastruct = {   "ByInternalName":[],
                              "OriginalFilename":[],
                              "Bymd5":[],
                              "Fromwords":[],
                              "_ByInternalName":["Collection","CompanyName","FileDescription","FileVersion","InternalName","LegalCopyright","OriginalFilename","ProductName","ProductVersion","md5","entropy","path"],
                              "_OriginalFilename":["Collection","CompanyName","FileDescription","FileVersion","InternalName","LegalCopyright","OriginalFilename","ProductName","ProductVersion","md5","entropy","path"],
                              "_Bymd5":["Collection","CompanyName","FileDescription","FileVersion","InternalName","LegalCopyright","OriginalFilename","ProductName","ProductVersion","md5","entropy","path"],
                              "_Fromwords":["Collection","FileDescription","InternalName","OriginalFilename","ProductName","md5","entropy","path"]}


    @verbose(True,verbose_flag,verbose_timeout,None)
    def find_it_from_words(self,data):
        items = []
        keys = ["Collection","FileDescription","InternalName","OriginalFilename","ProductName","md5","entropy","path"]
        for word in self.words:
            #pass on "unterminated character set at position 1" some words are not escaped
            try:
                items = find_items("QBWindows",{"$or":[{"InternalName":compile(word, I)},{"OriginalFilename":compile(word, I)},{"md5":compile(word, I)}]})
                if len(items) > 0:
                    for item in items:
                        i = {}
                        for key in keys:
                            if key in item:
                                i.update({key:item[key]})
                        if len(i) > 0:
                            data.append(i)
            except:
                pass

    @verbose(True,verbose_flag,verbose_timeout,None)
    def find_it_by_hash(self,md5,data):
        items = []
        items = find_items("QBWindows",{"md5":compile(md5, I)})
        keys = ["Collection","CompanyName","FileDescription","FileVersion","InternalName","LegalCopyright","OriginalFilename","ProductName","ProductVersion","md5","entropy","path"]
        if len(items) > 0:
            for item in items:
                i = {}
                for key in keys:
                    if key in item:
                        i.update({key:item[key]})
                if len(i) > 0:
                    data.append(i)

    @verbose(True,verbose_flag,verbose_timeout,None)
    def find_it_by_original_filename(self,name,data):
        items = []
        items = find_items("QBWindows",{"OriginalFilename":compile(name, I)})
        keys = ["Collection","CompanyName","FileDescription","FileVersion","InternalName","LegalCopyright","OriginalFilename","ProductName","ProductVersion","md5","entropy","path"]
        if len(items) > 0:
            for item in items:
                i = {}
                for key in keys:
                    if key in item:
                        i.update({key:item[key]})
                if len(i) > 0:
                    data.append(i)

    @verbose(True,verbose_flag,verbose_timeout,None)
    def find_it_by_internal_name(self,name,data):
        items = []
        items = find_items("QBWindows",{"InternalName":compile(name, I)})
        keys = ["Collection","CompanyName","FileDescription","FileVersion","InternalName","LegalCopyright","OriginalFilename","ProductName","ProductVersion","md5","entropy","path"]
        if len(items) > 0:
            for item in items:
                i = {}
                for key in keys:
                    if key in item:
                        i.update({key:item[key]})
                if len(i) > 0:
                    data.append(i)

    @verbose(True,verbose_flag,verbose_timeout,"Checking whitelist")
    def analyze(self,data,parsed):
        data["WhiteList"] = deepcopy(self.datastruct)
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        if parsed.w_internal or parsed.w_all or parsed.full:
            if len(data["Details"]["Properties"]["Name"]) > 3:
                self.find_it_by_internal_name(data["Details"]["Properties"]["Name"],data["WhiteList"]["ByInternalName"])
        if parsed.w_original or parsed.w_all or parsed.full:
            if len(data["Details"]["Properties"]["Name"]) > 3:
                self.find_it_by_original_filename(data["Details"]["Properties"]["Name"],data["WhiteList"]["ByInternalName"])
        if parsed.w_hash or parsed.w_all or parsed.full:
            self.find_it_by_hash(data["Details"]["Properties"]["md5"],data["WhiteList"]["Bymd5"])
        if parsed.w_all or ((parsed.w_words or parsed.full) and parsed.buffer != None):
            self.find_it_from_words(data["WhiteList"]["Fromwords"])
