'''
    __G__ = "(G)bd249ce4"
    modules -> blackberry
'''

from re import findall
from copy import deepcopy
from ctypes import Structure, c_uint16, c_uint32, c_uint8, sizeof
from analyzer.logger.logger import ignore_excpetion, verbose
from analyzer.mics.funcs import get_words


class Header(Structure):
    '''
    Header Struct
    '''
    _fields_ = [("Flashid", c_uint32),
                ("Sectionnumber", c_uint32),
                ("Vtablepointer", c_uint32),
                ("Timestamp", c_uint32),
                ("Userversion", c_uint32),
                ("Fieldrefpointer", c_uint32),
                ("Maxtypelistsize", c_uint16),
                ("Reserved", c_uint16),
                ("Datasection", c_uint32),
                ("Moduleinfo", c_uint32),
                ("Version", c_uint16),
                ("Codesize", c_uint16),
                ("Datasize", c_uint16),
                ("Flags", c_uint16)]


class _Data(Structure):
    '''
    Data Struct
    '''
    _fields_ = [("Flags", c_uint8),
                ("Version", c_uint8),
                ("Numberofimportedcalls", c_uint16),
                ("Numberofmodules", c_uint8),
                ("Numberofclasses", c_uint8),
                ("Exportedstringoffset", c_uint16),
                ("Databytesoffset", c_uint16),
                ("Emptyfield", c_uint16),
                ("Classdefinitions", c_uint16),
                ("Unknwon1", c_uint8 * 14),
                ("Aliases", c_uint16),
                ("Unknwon2", c_uint8 * 22)]


class ResourceData(Structure):
    '''
    Resource Data Struct
    '''
    _fields_ = [("TypePointer", c_uint16),
                ("Size", c_uint16),
                ("DataPointer", c_uint16)]


class BBParser:
    '''
    Blackberry extract artifacts from apk files
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting BBParser")
    def __init__(self):
        self.datastruct = {"Header": {},
                           "Data": {},
                           "Resources": [],
                           "Symbols": [],
                           "_Header": {},
                           "data": {},
                           "_Resources": ["DataPointer", "Size", "Sig", "Data"],
                           "_Symbols": ["Type", "Name"]}

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_functions_old(self, temp_f) -> list:
        '''
        get function names and constant strings by regex
        '''
        _list = []
        print(temp_f)
        strings = findall(rb"[\x24][\xd8]\\*\*\* ([\x20-\x7e]{4,})", temp_f)
        for _ in strings:
            if b"() " in _:
                __ = _.split(b"() ")
                with ignore_excpetion(Exception):
                    _list.append({"Type": "Function", "Name": __[0].decode("utf-8", errors="ignore")})
                    _list.append({"Type": "String", "Name": __[1].decode("utf-8", errors="ignore")})
        strings = findall(b"[\x24][\xd8] ([\x20-\x7e]{4,})", temp_f)  # <--- check this out
        for _ in strings:
            with ignore_excpetion(Exception):
                _list.append({"Type": "String", "Name": _.decode("utf-8", errors="ignore")})
        return _list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig(self, data) -> bool:
        '''
        check mime is cod or not
        '''
        if data["Details"]["Properties"]["mime"] == "application/octet-stream" and \
           data["Location"]["Original"].endswith(".cod"):
            return True
        return False

    @verbose(True, verbose_output=False, timeout=None, _str="Analzying COD file")
    def analyze(self, data):
        '''
        start analyzing cod logic, get words and wordsstripped from the file
        '''
        with open(data["Location"]["File"], 'rb') as file:

            data["COD"] = deepcopy(self.datastruct)
            _temp = []
            temp_f = file.read(sizeof(Header))
            header = Header.from_buffer_copy(temp_f)
            file.read(header.Codesize)
            dataraw = file.read(header.Datasize)
            _data = _Data.from_buffer_copy(dataraw)
            r_offset = _data.Exportedstringoffset
            rall = int((_data.Databytesoffset - _data.Exportedstringoffset) / sizeof(ResourceData))
            for _ in range(rall):
                temp_sig = ""
                resource_data = ResourceData.from_buffer_copy(dataraw[r_offset:])
                if resource_data.Size > 1:
                    temp_sig = "".join("{:02x}".format(x) for x in dataraw[resource_data.DataPointer:resource_data.DataPointer + 10])
                _temp.append({"DataPointer": resource_data.DataPointer,
                              "Size": resource_data.Size, "Sig": temp_sig,
                              "Data": (dataraw[resource_data.DataPointer:resource_data.DataPointer + resource_data.Size]).decode("utf-8", "ignore")})
                # print(dataraw[resource_data.Dataptr:resource_data.Dataptr+resource_data.Size])
                r_offset = r_offset + sizeof(ResourceData)
            for temp_x, temp_y in header._fields_:
                if isinstance(getattr(header, temp_x), int):
                    data["COD"]["Header"].update({temp_x: hex(getattr(header, temp_x))})
            for temp_x, temp_y in _data._fields_:
                if isinstance(getattr(_data, temp_x), int):
                    data["COD"]["Data"].update({temp_x: hex(getattr(_data, temp_x))})
            data["COD"]["Resources"] = _temp
            file.seek(0)
            data["COD"]["Symbols"] = self.get_functions_old(file.read())
            get_words(data, data["Location"]["File"])
