__version__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from re import I, compile, findall

class QBSuspicious:
    @verbose(True,verbose_flag,"Starting QBSuspicious")
    def __init__(self):
        '''
        initialize class and make detections path 
        '''
        self.suspicious = ["crypt","==","ransom","+tcp","pool.","bitcoin","encrypt","decrypt","mail","ftp","http","https","btc","address","sudo","password","pass","admin","payment"]

    @verbose(True,verbose_flag,None)
    def findsusregex(self,data):
        for sus in self.suspicious:
            _List = []
            x = findall(compile(r'(([^\n]+)?({})([^\n]+)?)'.format(sus),I),self.wordsstripped)
            if len(x) > 0:
                for _ in x:
                    _List.append(_[0])
            for x in set(_List):
                data.append({"Count":_List.count(x),"Detected":x})

    @verbose(True,verbose_flag,None)
    def findsus(self,data):
        for sus in self.suspicious:
            _List = []
            for _ in self.words:
                if sus in _:
                    _List.append(_)
            for x in set(_List):
                data.append({"Count":_List.count(x),"Detected":x})

    @verbose(True,verbose_flag,"Finding suspicious strings")
    def checksusp(self,data):
        data["Suspicious"] = {  "Suspicious":[],
                                "_Suspicious":["Count","Detected"]}
    
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.findsus(data["Suspicious"]["Suspicious"])