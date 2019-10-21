__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from ...mics.funcs import getwordsmultifilesarray,getwords,getwordsmultifiles
from ...modules.files.filetypes import checkpackedfiles,dmgunpack,unpackfile
from magic import from_buffer,Magic
from zlib import decompress
from re import DOTALL, MULTILINE, compile, finditer, sub
from binascii import unhexlify

#this module need some optimization

class RTFParser:
    @verbose(verbose_flag)
    @progressbar(True,"Starting RTFParser")
    def __init__(self):
        pass

    @verbose(verbose_flag)
    def getobjects(self,data,buffer) -> (list,list):
        '''
        get objects from rtf by regex

        Args:
            data: not used

        Return:
            list of objects
            list of parsed objects
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
                    _List.append({"Len":len(buffer[position:i]),"Parsed":tempdecoded.decode("utf-8")})
                    break
        return _List,_Listobjects

    @verbose(verbose_flag)
    def checkrtfsig(self,data) -> bool:
        '''
        check if mime is rtf

        Args:
            data: data dict

        Return:
            true if rtf
        '''
        if "text/rtf" == data["Details"]["Properties"]["mime"]:
            return True

    @verbose(verbose_flag)
    @progressbar(True,"Analyze rtf file")
    def checkrtf(self,data):
        '''
        start analyzing exe logic, add descriptions and get words and wordsstripped from buffers 

        Args:
            data: data dict
        '''
        data["RTF"] ={"General":{},
                         "Objects":[],
                         "_General":{},
                         "_Objects":["Len","Parsed"]}
        f = data["FilesDumps"][data["Location"]["File"]]
        data["RTF"]["Objects"],objects = self.getobjects(data,f)
        data["RTF"]["General"] = {"Objects":len(objects)}
        getwordsmultifilesarray(data,objects)