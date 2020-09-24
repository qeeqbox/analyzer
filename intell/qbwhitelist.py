'''
    __G__ = "(G)bd249ce4"
    connection ->  whitelist
'''

from re import I
from re import compile as rcompile
from copy import deepcopy
from analyzer.logger.logger import ignore_excpetion, verbose
from analyzer.connections.mongodbconn import find_items

class QBWhitelist:
    '''
    QBWafDetect for find original system files (Has to be enabled explicitly)
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBWhitelist")
    def __init__(self):
        '''
        initialize class and make detections path
        '''
        self.datastruct = {"ByInternalName":[],
                           "OriginalFilename":[],
                           "Bymd5":[],
                           "Fromwords":[],
                           "_ByInternalName":["Collection", "CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion", "md5", "entropy", "path"],
                           "_OriginalFilename":["Collection", "CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion", "md5", "entropy", "path"],
                           "_Bymd5":["Collection", "CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion", "md5", "entropy", "path"],
                           "_Fromwords":["Collection", "FileDescription", "InternalName", "OriginalFilename", "ProductName", "md5", "entropy", "path"]}
        self.words = []
        self.wordsstripped = ""

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def find_it_from_words(self, data):
        '''
        look in the databases by words
        '''
        items = []
        keys = ["Collection", "FileDescription", "InternalName", "OriginalFilename", "ProductName", "md5", "entropy", "path"]
        for word in self.words:
            #pass on "unterminated character set at position 1" some words are not escaped
            with ignore_excpetion(Exception):
                items = find_items("QBWindows", {"$or":[{"InternalName":rcompile(word, I)}, {"OriginalFilename":rcompile(word, I)}, {"md5":rcompile(word, I)}]})
                if len(items) > 0:
                    for item in items:
                        temp_dict = {}
                        for key in keys:
                            if key in item:
                                temp_dict.update({key:item[key]})
                        if len(temp_dict) > 0:
                            data.append(temp_dict)

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def find_it_by_hash(self, md5, data):
        '''
        look in the databases by hash
        '''
        items = []
        items = find_items("QBWindows", {"md5":rcompile(md5, I)})
        keys = ["Collection", "CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion", "md5", "entropy", "path"]
        if len(items) > 0:
            for item in items:
                temp_dict = {}
                for key in keys:
                    if key in item:
                        temp_dict.update({key:item[key]})
                if len(temp_dict) > 0:
                    data.append(temp_dict)

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def find_it_by_original_filename(self, name, data):
        '''
        look in the databases by name (most common)
        '''
        items = []
        items = find_items("QBWindows", {"OriginalFilename":rcompile(name, I)})
        keys = ["Collection", "CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion", "md5", "entropy", "path"]
        if len(items) > 0:
            for item in items:
                temp_dict = {}
                for key in keys:
                    if key in item:
                        temp_dict.update({key:item[key]})
                if len(temp_dict) > 0:
                    data.append(temp_dict)

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def find_it_by_internal_name(self, name, data):
        '''
        look in the databases by internal name
        '''
        items = []
        items = find_items("QBWindows", {"InternalName":rcompile(name, I)})
        keys = ["Collection", "CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion", "md5", "entropy", "path"]
        if len(items) > 0:
            for item in items:
                temp_dict = {}
                for key in keys:
                    if key in item:
                        temp_dict.update({key:item[key]})
                if len(temp_dict) > 0:
                    data.append(temp_dict)

    @verbose(True, verbose_output=False, timeout=None, _str="Checking whitelist")
    def analyze(self, data, parsed):
        '''
        start analyzing logic
        '''
        data["WhiteList"] = deepcopy(self.datastruct)
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        if parsed.w_internal or parsed.w_all or parsed.full:
            if len(data["Details"]["Properties"]["Name"]) > 3:
                self.find_it_by_internal_name(data["Details"]["Properties"]["Name"], data["WhiteList"]["ByInternalName"])
        if parsed.w_original or parsed.w_all or parsed.full:
            if len(data["Details"]["Properties"]["Name"]) > 3:
                self.find_it_by_original_filename(data["Details"]["Properties"]["Name"], data["WhiteList"]["ByInternalName"])
        if parsed.w_hash or parsed.w_all or parsed.full:
            self.find_it_by_hash(data["Details"]["Properties"]["md5"], data["WhiteList"]["Bymd5"])
        if parsed.w_all or ((parsed.w_words or parsed.full) and parsed.buffer is not None):
            self.find_it_from_words(data["WhiteList"]["Fromwords"])
