__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.funcs import getwordsmultifilesarray,getwords,getwordsmultifiles
from ..modules.filetypes import checkpackedfiles,dmgunpack,unpackfile
from magic import from_buffer,Magic
from zlib import decompress
from binascii import unhexlify

class BufferParser:
    @verbose(True,verbose_flag,"Starting BufferParser")
    def __init__(self):
        pass

    @verbose(True,verbose_flag,"Analyze buffer")
    def checkrtf(self,data):
        '''
        start analyzing exe logic, add descriptions and get words and wordsstripped from buffers 
        '''
        data["RTF"] ={"General":{},
                         "Objects":[],
                         "_General":{},
                         "_Objects":["Len","Parsed"]}
        f = data["FilesDumps"][data["Location"]["File"]]
        data["RTF"]["Objects"],objects = self.getobjects(data,f)
        data["RTF"]["General"] = {"Objects":len(objects)}
        getwordsmultifilesarray(data,objects)