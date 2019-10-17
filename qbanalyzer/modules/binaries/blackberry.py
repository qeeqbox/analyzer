__G__ = "(G)bd249ce4"

from ctypes import *
from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from ...mics.funcs import getwords,getwordsmultifiles
from re import findall

class BBParser:
    @verbose(verbose_flag)
    @progressbar(True,"Starting BBParser")
    def __init__(self):
        pass

    @verbose(verbose_flag)
    def checkbbsig(self,data):
        if  data["Details"]["Properties"]["mime"] == "application/octet-stream" and \
            data["Location"]["Original"].endswith(".cod"):
                return True

    @verbose(verbose_flag)
    def getfunctionsold(self,f):
        _list = []
        strings = findall(b"[\x24][\xd8]\\*\*\* ([\x20-\x7e]{4,})",f)
        for _ in strings:
            if b"() " in _:
                __ = _.split(b"() ")
                try:
                    _list.append({"Type":"Function","Name":__[0].decode("utf-8")})
                    _list.append({"Type":"String","Name":__[1].decode("utf-8")})
                except:
                    pass
        strings = findall(b"[\x24][\xd8] ([\x20-\x7e]{4,})",f) #<--- check this out
        for _ in strings:
            try:
                _list.append({"Type":"String","Name":_.decode("utf-8")})
            except:
                pass
        return _list

    @verbose(verbose_flag)
    @progressbar(True,"Analzying cod file")
    def getbbdeatils(self,_data):
        with open(_data["Location"]["File"], 'rb') as file:
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
            class Data(Structure):
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
            _data["COD"] = {"Header" : {},
                            "Data":{},
                            "Resources":[],
                            "Symbols":[],
                            "_Header" : {},
                            "_Data":{},
                            "_Resources":["DataPointer","Size","Sig","Data"],
                            "_Symbols":["Type","Name"]}
            _temp = []
            f = file.read(sizeof(Header))
            header = Header.from_buffer_copy(f)
            file.read(header.Codesize)
            dataraw = file.read(header.Datasize)
            data = Data.from_buffer_copy(dataraw)
            Roffset = data.Exportedstringoffset
            rall = int((data.Databytesoffset-data.Exportedstringoffset)/sizeof(ResourceData))
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
                    _data["COD"]["Header"].update({x:hex(getattr(header,x))})
            for x,y in data._fields_:
                if isinstance(getattr(data,x),int):
                    _data["COD"]["Data"].update({x:hex(getattr(data,x))})
            _data["COD"]["Resources"] = _temp
            file.seek(0)
            _data["COD"]["Symbols"] = self.getfunctionsold(file.read())
            words,wordsstripped = getwords(_data["Location"]["File"])
            _data["StringsRAW"] = {"words":words,
                                  "wordsstripped":wordsstripped}