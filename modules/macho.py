__G__ = "(G)bd249ce4"

from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout
from analyzer.mics.funcs import get_words,get_words_multi_files,get_entropy,get_entropy_float_ret
from analyzer.modules.archive import check_packed_files,dmg_unpack,unpack_file
from analyzer.intell.qbdescription import add_description
from macholib.MachO import LC_SEGMENT,LC_SEGMENT_64,LC_LOAD_DYLIB
from macholib import MachO,SymbolTable
from plistlib import readPlist
from hashlib import md5
from io import BytesIO
from copy import deepcopy

class Macho:
    @verbose(True,verbose_flag,verbose_timeout,"Starting Macho")
    def __init__(self):
        self.datastruct = { "General":{},
                            "Sections":[],
                            "Libraries":[],
                            "Symbols":[],
                            "Undefined Symbols":[],
                            "External Symbols":[],
                            "Local Symbols":[],
                            "General":{},
                            "_Sections":["Section","Suspicious","Size","Entropy","MD5","Description"],
                            "_Libraries":["Library","Description"],
                            "_Symbols":["Symbol","Description"],
                            "_Undefined Symbols":["Symbol","Description"],
                            "_External Symbols":["Symbol","Description"],
                            "_Local Symbols":["Symbol","Description"]}

    @verbose(True,verbose_flag,verbose_timeout,None)
    def entry_point(self,machos) -> bool:
        '''
        get entry point of macho (needs debugging)
        '''
        for h in machos.headers:
            for lc, cmd, data in h.commands:
                if lc.cmd == LC_MAIN:
                    return True

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_libs(self,machos) -> list:
        '''
        get libs 
        '''
        _list = []
        for h in machos.headers:
            for lc, cmd, data in h.commands:
                if lc.cmd == LC_LOAD_DYLIB:
                    _list.append({  "Library":data.decode("utf-8",errors="ignore").rstrip('\x00'),
                                    "Description":""})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_segments(self,machos) -> list:
        '''
        get segments 
        '''
        _list = []
        for h in machos.headers:
            for lc, cmd, data in h.commands:
                if lc.cmd in (LC_SEGMENT, LC_SEGMENT_64):
                    name = cmd.segname[:cmd.segname.find(b'\x00')].decode("utf-8",errors="ignore")
                    _list.append({  "Segment":name,
                                    "Address":hex(cmd.vmaddr),
                                    "Description":""})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_sections(self,machos,fbuffer) -> list:
        '''
        get sections 
        '''
        _list = []
        for h in machos.headers:
            for lc, cmd, data in h.commands:
                if hasattr(cmd, "segname"):
                    #fbuffer[cmd.fileoff:cmd.filesize]
                    with BytesIO(fbuffer) as bio:
                        bio.seek(cmd.fileoff)
                        x = bio.read(cmd.filesize)
                        sus = "No"
                        entropy = get_entropy_float_ret(x)
                        if entropy > 6 or entropy >= 0 and entropy <=1:
                            sus = "True, {}".format(entropy)
                        elif cmd.filesize == 0:
                            sus = "True, section size 0"
                        
                        seg = cmd.segname[:cmd.segname.find(b'\x00')].decode("utf-8",errors="ignore")
                        if seg == "__PAGEZERO":
                            sus = ""
                        
                        _list.append({"Section":seg,
                                      "Suspicious":sus,
                                      "Size":cmd.filesize,
                                      "Entropy":get_entropy(x),
                                      "MD5":md5(x).hexdigest(),
                                      "Description":""})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_symbols(self,machos) -> list:
        '''
        get all symbols
        '''
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.nlists:
            _list.append({"Symbol":name.decode("utf-8",errors="ignore"),
                          "Description":""})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_local_symbols(self,machos) -> list:
        '''
        get local symbols
        '''
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.localsyms:
            _list.append({  "Symbol":name.decode("utf-8",errors="ignore"),
                            "Description":""})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_undef_symbols(self,machos) -> list:
        '''
        get undefined symbols
        '''
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.undefsyms:
            _list.append({ "Symbol":name.decode("utf-8",errors="ignore"),
                            "Description":""})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_extdef_symbols(self,machos) -> list:
        '''
        get external reference symbol indices
        '''
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.extdefsyms:
            _list.append({  "Symbol":name.decode("utf-8",errors="ignore"),
                            "Description":""})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_plist(self,plist) -> dict:
        '''
        read plist file
        '''
        return readPlist(plist)

    @verbose(True,verbose_flag,verbose_timeout,None)
    def check_sig_dmg(self,data) -> bool:
        '''
        check mime is dmg or not
        '''
        if  data["Details"]["Properties"]["mime"] == "application/zlib" and \
            data["Location"]["Original"].endswith(".dmg"):
            x = dmg_unpack(data["Location"]["File"])
            if x: 
                if check_packed_files(x,["info.plist"]) or check_packed_files(x,["Install"]):
                    unpack_file(data,x)
                    return True

    @verbose(True,verbose_flag,verbose_timeout,None)
    def check_sig_macho(self,data) -> bool:
        '''
        check mime is machO or not
        '''
        if data["Details"]["Properties"]["mime"] == "application/x-mach-binary":
            return True

    @verbose(True,verbose_flag,verbose_timeout,None)
    def check_sig_ipa(self,data) -> bool:
        '''
        check mime is dmg or not
        '''
        if  data["Details"]["Properties"]["mime"] == "application/zlib" and \
            data["Location"]["Original"].endswith(".ipa"):
            x = dmg_unpack(data["Location"]["File"])
            if x: 
                if check_packed_files(x,["info.plist"]):
                    unpack_file(data,x)
                    return True


    @verbose(True,verbose_flag,verbose_timeout,"Analzying IPA file")
    def analyze_ipa(self,data):
        '''
        start analyzing dmg file, loop over packed file and extract info.plist and shells
        '''
        data["IPA"] = {"General":{},
                       "_General":{}}
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Path"].lower().endswith("info.plist"):
                data["DMG"]["General"] = self.get_plist(v["Path"])
                break
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Type"] == "text/x-shellscript":
                k = 'DMG_Shellscript_{}'.format(i)
                data[k] = { "Shell":"",
                            "_Shell":""}
                data[k]["Shell"] = open(v["Path"],"r").read()
        get_words_multi_files(data,data["Packed"]["Files"])


    @verbose(True,verbose_flag,verbose_timeout,"Analzying DMG file")
    def analyze_dmg(self,data):
        '''
        start analyzing dmg file, loop over packed file and extract info.plist and shells
        '''
        data["DMG"] = {"General":{},
                       "_General":{}}
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Path"].lower().endswith("info.plist"):
                data["DMG"]["General"] = self.get_plist(v["Path"])
                break
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Type"] == "text/x-shellscript":
                k = 'DMG_Shellscript_{}'.format(i)
                data[k] = { "Shell":"",
                            "_Shell":""}
                data[k]["Shell"] = open(v["Path"],"r").read()
        get_words_multi_files(data,data["Packed"]["Files"])
                

    @verbose(True,verbose_flag,verbose_timeout,"Analzying MACHO file")
    def analyze_macho(self,data):
        '''
        start analyzing macho logic, add descriptions and get words and wordsstripped from the file 
        '''
        try:
            macho = MachO.MachO(data["Location"]["File"])
        except:
            return
        data["MACHO"] = deepcopy(self.datastruct)
        fbuffer = data["FilesDumps"][data["Location"]["File"]]
        data["MACHO"]["General"]:{}
        data["MACHO"]["Sections"] = self.get_sections(macho,fbuffer)
        data["MACHO"]["Libraries"] = self.get_libs(macho)
        data["MACHO"]["Symbols"] = self.get_symbols(macho)
        data["MACHO"]["Undefined Symbols"] = self.get_undef_symbols(macho)
        data["MACHO"]["External Symbols"] = self.get_extdef_symbols(macho)
        data["MACHO"]["Local Symbols"] = self.get_local_symbols(macho)
        add_description("ManHelp",data["MACHO"]["Symbols"],"Symbol")
        get_words(data,data["Location"]["File"])
