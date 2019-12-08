__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.funcs import getwords,getwordsmultifiles,getentropy
from ..general.archive import checkpackedfiles,dmgunpack,unpackfile
from ..intell.qbdescription import adddescription
from macholib.MachO import LC_SEGMENT,LC_SEGMENT_64,LC_LOAD_DYLIB
from macholib import MachO,SymbolTable
from plistlib import readPlist

class Macho:
    @verbose(True,verbose_flag,"Starting Macho")
    def __init__(self):
        pass

    @verbose(True,verbose_flag,None)
    def entry_point(self,machos) -> bool:
        '''
        get entry point of macho (needs debugging)
        '''
        for h in machos.headers:
            for lc, cmd, data in h.commands:
                if lc.cmd == LC_MAIN:
                    return True

    @verbose(True,verbose_flag,None)
    def getlibs(self,machos) -> list:
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

    @verbose(True,verbose_flag,None)
    def getsegments(self,machos) -> list:
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

    @verbose(True,verbose_flag,None)
    def getsections(self,machos) -> list:
        '''
        get sections 
        '''
        _list = []
        for h in machos.headers:
            for lc, cmd, data in h.commands:
                if lc.cmd in (LC_SEGMENT, LC_SEGMENT_64):
                    for section in data:
                        name = section.sectname[:section.sectname.find(b'\x00')].decode("utf-8",errors="ignore")
                        seg = section.segname[:section.segname.find(b'\x00')].decode("utf-8",errors="ignore")
                        _list.append({"Section":name,
                                      "Address":hex(section.addr),
                                      "Segment":seg,
                                      "Description":""})
        return _list

    @verbose(True,verbose_flag,None)
    def getsymbols(self,machos) -> list:
        '''
        get all symbols
        '''
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.nlists:
            _list.append({"Symbol":name.decode("utf-8",errors="ignore"),
                          "Description":""})
        return _list

    @verbose(True,verbose_flag,None)
    def getlocalsymbols(self,machos) -> list:
        '''
        get local symbols
        '''
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.localsyms:
            _list.append({  "Symbol":name.decode("utf-8",errors="ignore"),
                            "Description":""})
        return _list

    @verbose(True,verbose_flag,None)
    def getundefsymbols(self,machos) -> list:
        '''
        get undefined symbols
        '''
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.undefsyms:
            _list.append({ "Symbol":name.decode("utf-8",errors="ignore"),
                            "Description":""})
        return _list

    @verbose(True,verbose_flag,None)
    def getextdefsymbols(self,machos) -> list:
        '''
        get external reference symbol indices
        '''
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.extdefsyms:
            _list.append({  "Symbol":name.decode("utf-8",errors="ignore"),
                            "Description":""})
        return _list

    @verbose(True,verbose_flag,None)
    def getplist(self,plist) -> dict:
        '''
        read plist file
        '''
        return readPlist(plist)

    @verbose(True,verbose_flag,None)
    def checkdmgsig(self,data) -> bool:
        '''
        check mime is dmg or not
        '''
        if  data["Details"]["Properties"]["mime"] == "application/zlib" and \
            data["Location"]["Original"].endswith(".dmg"):
            x = dmgunpack(data["Location"]["File"])
            if x: 
                if checkpackedfiles(x,["info.plist"]):
                    unpackfile(data,x)
                    return True

    @verbose(True,verbose_flag,None)
    def checkmacsig(self,data) -> bool:
        '''
        check mime is machO or not
        '''
        if data["Details"]["Properties"]["mime"] == "application/x-mach-binary":
            return True

    @verbose(True,verbose_flag,None)
    def checkipa(self,data) -> bool:
        '''
        check mime is dmg or not
        '''
        if  data["Details"]["Properties"]["mime"] == "application/zlib" and \
            data["Location"]["Original"].endswith(".ipa"):
            x = dmgunpack(data["Location"]["File"])
            if x: 
                if checkpackedfiles(x,["info.plist"]):
                    unpackfile(data,x)
                    return True


    @verbose(True,verbose_flag,"Analzying IPA file")
    def getipadeatils(self,data):
        '''
        start analyzing dmg file, loop over packed file and extract info.plist and shells
        '''
        data["IPA"] = {"General":{},
                       "_General":{}}
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Path"].lower().endswith("info.plist"):
                data["DMG"]["General"] = self.getplist(v["Path"])
                break
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Type"] == "text/x-shellscript":
                k = 'DMG_Shellscript_{}'.format(i)
                data[k] = { "Shell":"",
                            "_Shell":""}
                data[k]["Shell"] = open(v["Path"],"r").read()
        getwordsmultifiles(data,data["Packed"]["Files"])


    @verbose(True,verbose_flag,"Analzying DMG file")
    def getdmgdeatils(self,data):
        '''
        start analyzing dmg file, loop over packed file and extract info.plist and shells
        '''
        data["DMG"] = {"General":{},
                       "_General":{}}
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Path"].lower().endswith("info.plist"):
                data["DMG"]["General"] = self.getplist(v["Path"])
                break
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Type"] == "text/x-shellscript":
                k = 'DMG_Shellscript_{}'.format(i)
                data[k] = { "Shell":"",
                            "_Shell":""}
                data[k]["Shell"] = open(v["Path"],"r").read()
        getwordsmultifiles(data,data["Packed"]["Files"])
                

    @verbose(True,verbose_flag,"Analzying MACHO file")
    def getmachodeatils(self,data):
        '''
        start analyzing macho logic, add descriptions and get words and wordsstripped from the file 
        '''
        try:
            macho = MachO.MachO(data["Location"]["File"])
        except:
            return
        data["MACHO"] = {   "General":{},
                            "Sections":[],
                            "Libraries":[],
                            "Segments":[],
                            "Symbols":[],
                            "Undefined Symbols":[],
                            "External Symbols":[],
                            "Local Symbols":[],
                            "General":{},
                            "_Sections":["Section","Address","Segment","Description"],
                            "_Libraries":["Library","Description"],
                            "_Segments":["Segment","Address","Description"],
                            "_Symbols":["Symbol","Description"],
                            "_Undefined Symbols":["Symbol","Description"],
                            "_External Symbols":["Symbol","Description"],
                            "_Local Symbols":["Symbol","Description"]}
        data["MACHO"]["General"]:{}
        data["MACHO"]["Sections"] = self.getsections(macho)
        data["MACHO"]["Libraries"] = self.getlibs(macho)
        data["MACHO"]["Segments"] = self.getsegments(macho)
        data["MACHO"]["Symbols"] = self.getsymbols(macho)
        data["MACHO"]["Undefined Symbols"] = self.getundefsymbols(macho)
        data["MACHO"]["External Symbols"] = self.getextdefsymbols(macho)
        data["MACHO"]["Local Symbols"] = self.getlocalsymbols(macho)
        adddescription("ManHelp",data["MACHO"]["Symbols"],"Symbol")
        getwords(data,data["Location"]["File"])
