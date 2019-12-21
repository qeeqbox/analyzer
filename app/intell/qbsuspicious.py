__G__ = "(G)bd249ce4"

from ..logger.logger import log_string,verbose,verbose_flag,verbose_timeout
from re import I, compile, findall
from copy import deepcopy

class QBSuspicious:
    @verbose(True,verbose_flag,verbose_timeout,"Starting QBSuspicious")
    def __init__(self):
        self.datastruct = { "Suspicious":[],
                            "_Suspicious":["Count","Detected"]}

        self.suspicious = ["crypt","==","ransom","+tcp","pool.","bitcoin","encrypt","decrypt","mail","ftp","http","https","btc","address","sudo","password","pass","admin","payment"]

    @verbose(True,verbose_flag,verbose_timeout,None)
    def find_suspicious_regex(self,data):
        for sus in self.suspicious:
            _List = []
            x = findall(compile(r'(([^\n]+)?({})([^\n]+)?)'.format(sus),I),self.wordsstripped)
            if len(x) > 0:
                for _ in x:
                    _List.append(_[0])
            for x in set(_List):
                data.append({"Count":_List.count(x),"Detected":x})

    @verbose(True,verbose_flag,verbose_timeout,None)
    def find_suspicious(self,data):
        for sus in self.suspicious:
            _List = []
            for _ in self.words:
                if sus in _:
                    _List.append(_)
            for x in set(_List):
                data.append({"Count":_List.count(x),"Detected":x})

    @verbose(True,verbose_flag,verbose_timeout,"Finding suspicious strings")
    def analyze(self,data):
        data["Suspicious"] = deepcopy(self.datastruct)
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.find_suspicious(data["Suspicious"]["Suspicious"])