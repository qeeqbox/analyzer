__G__ = "(G)bd249ce4"

from ..logger.logger import verbose, verbose_flag, verbose_timeout
from ..mics.funcs import get_words_multi_filesarray,get_words
from re import DOTALL, MULTILINE, compile, finditer, sub
from binascii import unhexlify
from oletools.olevba3 import VBA_Parser

class MSParser:
    @verbose(True,verbose_flag,verbose_timeout,"Starting MSParser")
    def __init__(self):
        self.datastruct ={   "General":{},
                             "Objects":[],
                             "Macro":[],
                             "_General":{},
                             "_Objects":["Len","Parsed"],
                             "_Macro":["Name","VBA"]}

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_objects(self,data,buffer) -> (list,list):
        '''
        get objects from rtf by regex
        '''
        x = compile(rb'\\objdata\b',DOTALL|MULTILINE)
        _List = []
        _Listobjects = []
        for _ in finditer(x,buffer):
            start,position = _.span()
            position += 1
            startcurlybracket = 0
            endcurlybracket = 0
            for i in range(position, position+len(buffer[position:])):
                if chr(buffer[i]) == "{":
                    startcurlybracket += 1
                if chr(buffer[i]) == "}":
                    endcurlybracket += 1
                if startcurlybracket == 0 and endcurlybracket == 1 or \
                    endcurlybracket > startcurlybracket:
                    whitespaces = sub(rb'\s+', b'', buffer[position:i])
                    temp = unhexlify(whitespaces)
                    tempdecoded = sub(br'[^\x20-\x7F]+',b'', temp)
                    _Listobjects.append(tempdecoded)
                    _List.append({"Len":len(buffer[position:i]),"Parsed":tempdecoded.decode("utf-8",errors="ignore")})
                    break
        return _List,_Listobjects


    @verbose(True,verbose_flag,verbose_timeout,None)
    def extract_macros(self,path) -> list:
        '''
        Extract macros
        '''
        List = []
        try:
            for (f, s, vbaname, vbacode) in VBA_Parser(path).extract_macros():
                List.append({"Name":vbaname,"VBA":vbacode})
        except:
            pass
        return List

    @verbose(True,verbose_flag,verbose_timeout,None)
    def check_sig(self,data) -> bool:
        '''
        check if mime is rtf
        '''
        if "text/rtf" == data["Details"]["Properties"]["mime"] or data["Details"]["Properties"]["mime"].startswith("application/vnd.ms"):
            return True

    @verbose(True,verbose_flag,verbose_timeout,"Analyze MS file")
    def analyze(self,data):
        '''
        start analyzing exe logic, add descriptions and get words and wordsstripped from buffers 
        '''
        data["MS"]=self.datastruct
        f = data["FilesDumps"][data["Location"]["File"]]
        data["MS"]["Objects"],objects = self.get_objects(data,f)
        data["MS"]["Macro"] = self.extract_macros(data["Location"]["File"])
        data["MS"]["General"] = {"Objects":len(objects)}
        if len(objects) > 0:
            get_words_multi_filesarray(data,objects)
        else:
            get_words(data,data["Location"]["File"])