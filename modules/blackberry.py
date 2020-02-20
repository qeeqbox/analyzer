__G__ = "(G)bd249ce4"

from ctypes import Structure, c_uint16, c_uint32, c_uint8, sizeof
from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout
from analyzer.mics.funcs import get_words
from re import findall
from copy import deepcopy

class Header(Structure):
    _fields_ = [("Flashid",c_uint32),
                ("Sectionnumber",c_uint32),
                ("Vtablepointer",c_uint32),
                ("Timestamp",c_uint32),
                ("Userversion",c_uint32),
                ("Fieldrefpointer",c_uint32),
                ("Maxtypelistsize",c_uint16),
                ("Reserved",c_uint16),
                ("Datasection",c_uint32),
                ("Moduleinfo",c_uint32),
                ("Version",c_uint16),
                ("Codesize",c_uint16),
                ("Datasize",c_uint16),
                ("Flags",c_uint16)]
class _Data(Structure):
    _fields_ = [("Flags",c_uint8),
                ("Version",c_uint8),
                ("Numberofimportedcalls",c_uint16),
                ("Numberofmodules",c_uint8),
                ("Numberofclasses",c_uint8),
                ("Exportedstringoffset",c_uint16),
                ("Databytesoffset",c_uint16),
                ("Emptyfield",c_uint16),
                ("Classdefinitions",c_uint16),
                ("Unknwon1",c_uint8*14),
                ("Aliases",c_uint16),
                ("Unknwon2",c_uint8*22)]
class ResourceData(Structure):
    _fields_ = [("TypePointer",c_uint16),
                 ("Size",c_uint16),
                 ("DataPointer",c_uint16)]

class BBParser:
    @verbose(True,verbose_flag,verbose_timeout,"Starting BBParser")
    def __init__(self):
        self.datastruct = { "Header" : {},
                            "Data":{},
                            "Resources":[],
                            "Symbols":[],
                            "_Header" : {},
                            "data":{},
                            "_Resources":["DataPointer","Size","Sig","Data"],
                            "_Symbols":["Type","Name"]}

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_functions_old(self,f) -> list:
        '''
        get function names and constant strings by regex
        '''
        _list = []
        strings = findall(b"[\x24][\xd8]\\*\*\* ([\x20-\x7e]{4,})",f)
        for _ in strings:
            if b"() " in _:
                __ = _.split(b"() ")
                try:
                    _list.append({"Type":"Function","Name":__[0].decode("utf-8",errors="ignore")})
                    _list.append({"Type":"String","Name":__[1].decode("utf-8",errors="ignore")})
                except:
                    pass
        strings = findall(b"[\x24][\xd8] ([\x20-\x7e]{4,})",f) #<--- check this out
        for _ in strings:
            try:
                _list.append({"Type":"String","Name":_.decode("utf-8",errors="ignore")})
            except:
                pass
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def check_sig(self,data) -> bool:
        '''
        check mime is cod or not
        '''
        if  data["Details"]["Properties"]["mime"] == "application/octet-stream" and \
            data["Location"]["Original"].endswith(".cod"):
                return True


    @verbose(True,verbose_flag,verbose_timeout,"Analzying COD file")
    def analyze(self,data):
        '''
        start analyzing cod logic, get words and wordsstripped from the file 
        '''
        with open(data["Location"]["File"], 'rb') as file:

            data["COD"] = deepcopy(self.datastruct)
            _temp = []
            f = file.read(sizeof(Header))
            header = Header.from_buffer_copy(f)
            file.read(header.Codesize)
            dataraw = file.read(header.Datasize)
            _data = _Data.from_buffer_copy(dataraw)
            Roffset = _data.Exportedstringoffset
            rall = int((_data.Databytesoffset-_data.Exportedstringoffset)/sizeof(ResourceData))
            for _ in range(rall):
                Sig = ""
                R = ResourceData.from_buffer_copy(dataraw[Roffset:])
                if R.Size > 1:
                    Sig = "".join("{:02x}".format(x) for x in dataraw[R.DataPointer:R.DataPointer+10])
                _temp.append({  "DataPointer":R.DataPointer,
                                "Size":R.Size,"Sig":Sig,
                                "Data":(dataraw[R.DataPointer:R.DataPointer+R.Size]).decode("utf-8","ignore")})
                #print(dataraw[R.Dataptr:R.Dataptr+R.Size])
                Roffset = Roffset + sizeof(ResourceData)
            for x,y in header._fields_:
                if isinstance(getattr(header,x),int):
                    data["COD"]["Header"].update({x:hex(getattr(header,x))})
            for x,y in _data._fields_:
                if isinstance(getattr(_data,x),int):
                    data["COD"]["Data"].update({x:hex(getattr(_data,x))})
            data["COD"]["Resources"] = _temp
            file.seek(0)
            data["COD"]["Symbols"] = self.get_functions_old(file.read())
            get_words(data,data["Location"]["File"])