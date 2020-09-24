'''
    __G__ = "(G)bd249ce4"
    modules -> ole
'''

from re import DOTALL, MULTILINE, finditer, sub
from re import compile as rcompile
from binascii import unhexlify
from olefile import OleFileIO, isOleFile
from oletools.olevba3 import VBA_Parser
from analyzer.logger.logger import ignore_excpetion, verbose
from analyzer.mics.funcs import get_words_multi_filesarray, get_words

class OLEParser:
    '''
    OLEParser extracts artifacts from office files
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting OLEParser")
    def __init__(self):
        '''
        initialize class and datastruct, this has to pass
        '''
        self.datastruct = {"General":{},
                           "Objects":[],
                           "Macro":[],
                           "_General":{},
                           "_Objects":["Name", "Parsed"],
                           "_Macro":["Name", "VBA"]}

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_objects(self, data, buffer) -> (list, list):
        '''
        get objects from rtf by regex
        '''
        temp_x = rcompile(rb'\\objdata\b', DOTALL|MULTILINE)
        temp_list = []
        temp_list_objects = []
        for _ in finditer(temp_x, buffer):
            start, position = _.span()
            position += 1
            startcurlybracket = 0
            endcurlybracket = 0
            for item in range(position, position+len(buffer[position:])):
                if chr(buffer[item]) == "{":
                    startcurlybracket += 1
                if chr(buffer[item]) == "}":
                    endcurlybracket += 1
                if startcurlybracket == 0 and endcurlybracket == 1 or \
                    endcurlybracket > startcurlybracket:
                    whitespaces = sub(rb'\s+', b'', buffer[position:item])
                    temp = unhexlify(whitespaces)
                    tempdecoded = sub(br'[^\x20-\x7F]+', b'', temp)
                    temp_list_objects.append(tempdecoded)
                    temp_list.append({"Len":len(buffer[position:item]), "Parsed":tempdecoded.decode("utf-8", errors="ignore")})
                    break
        return temp_list, temp_list_objects

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_streams(self, dump) -> (list, list):
        '''
        get streams
        '''
        temp_list_objects = []
        temp_list = []
        ole = OleFileIO(dump)
        listdir = ole.listdir()
        for direntry in listdir:
            dirs = sub(r'[^\x20-\x7f]', r'', " : ".join(direntry))
            tempdecoded = sub(br'[^\x20-\x7F]+', b'', ole.openstream(direntry).getvalue())
            temp_list_objects.append(tempdecoded)
            temp_list.append({"Name":dirs, "Parsed":tempdecoded.decode("utf-8", errors="ignore")})
        return temp_list, temp_list_objects


    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_general(self, data, temp_f):
        '''
        Extract general info
        '''
        for temp_k, temp_v in OleFileIO(temp_f).get_metadata().__dict__.items():
            if temp_v is not None:
                if isinstance(temp_v, bytes):
                    if len(temp_v) > 0:
                        data.update({temp_k:temp_v.decode("utf-8", errors="ignore")})
                else:
                    data.update({temp_k:temp_v})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def extract_macros(self, path) -> list:
        '''
        Extract macros
        '''
        temp_list = []
        with ignore_excpetion(Exception):
            for (temp_f, temp_s, vbaname, vbacode) in VBA_Parser(path).extract_macros():
                temp_list.append({"Name":vbaname, "VBA":vbacode})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig(self, data) -> bool:
        '''
        check if mime is ole
        '''

        return bool(isOleFile(data["Location"]["File"]))

    @verbose(True, verbose_output=False, timeout=None, _str="Analyze OLE file")
    def analyze(self, data):
        '''
        start analyzing ole logic
        '''
        data["OLE"] = self.datastruct
        temp_f = data["FilesDumps"][data["Location"]["File"]]
        self.get_general(data["OLE"]["General"], temp_f)
        data["OLE"]["Objects"], objects = self.get_streams(temp_f)
        data["OLE"]["Macro"] = self.extract_macros(data["Location"]["File"])
        #data["OLE"]["Objects"], objects = self.get_objects(data, temp_f)
        if len(objects) > 0:
            get_words_multi_filesarray(data, objects)
        else:
            get_words(data, data["Location"]["File"])
