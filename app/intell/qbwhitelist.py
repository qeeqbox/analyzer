__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag,verbose_timeout
from ..mics.connection import finditems
from re import I, compile

class QBWhitelist:
    @verbose(True,verbose_flag,verbose_timeout,"Starting QBWhitelist")
    def __init__(self):
        '''
        initialize class
        '''

    @verbose(True,verbose_flag,verbose_timeout,None)
    def finditfromwords(self,data):
        items = []
        keys = ["Collection","FileDescription","InternalName","OriginalFilename","ProductName","md5","entropy","path"]
        for word in self.words:
            #pass on "unterminated character set at position 1" some words are not escaped
            try:
                items = finditems("QBWindows",{"$or":[{"InternalName":compile(word, I)},{"OriginalFilename":compile(word, I)},{"md5":compile(word, I)}]})
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
    def finditbyhash(self,md5,data):
        items = []
        items = finditems("QBWindows",{"md5":compile(md5, I)})
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
    def finditbyoriginalfilename(self,name,data):
        items = []
        items = finditems("QBWindows",{"OriginalFilename":compile(name, I)})
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
    def finditbyinternalname(self,name,data):
        items = []
        items = finditems("QBWindows",{"InternalName":compile(name, I)})
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
    def isitwhitelisted(self,data,parsed):
        data["WhiteList"] = { "ByInternalName":[],
                              "OriginalFilename":[],
                              "Bymd5":[],
                              "Fromwords":[],
                              "_ByInternalName":["Collection","CompanyName","FileDescription","FileVersion","InternalName","LegalCopyright","OriginalFilename","ProductName","ProductVersion","md5","entropy","path"],
                              "_OriginalFilename":["Collection","CompanyName","FileDescription","FileVersion","InternalName","LegalCopyright","OriginalFilename","ProductName","ProductVersion","md5","entropy","path"],
                              "_Bymd5":["Collection","CompanyName","FileDescription","FileVersion","InternalName","LegalCopyright","OriginalFilename","ProductName","ProductVersion","md5","entropy","path"],
                              "_Fromwords":["Collection","FileDescription","InternalName","OriginalFilename","ProductName","md5","entropy","path"]}
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        if parsed.w_internal or parsed.w_all or parsed.full:
            self.finditbyinternalname(data["Details"]["Properties"]["Name"],data["WhiteList"]["ByInternalName"])
        if parsed.w_original or parsed.w_all or parsed.full:
            self.finditbyoriginalfilename(data["Details"]["Properties"]["Name"],data["WhiteList"]["ByInternalName"])
        if parsed.w_hash or parsed.w_all or parsed.full:
            self.finditbyhash(data["Details"]["Properties"]["md5"],data["WhiteList"]["Bymd5"])
        if (parsed.w_words or parsed.w_all or parsed.full) and parsed.buffer != None:
            self.finditfromwords(data["WhiteList"]["Fromwords"])
