__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from ..mics.funcs import getwords,getwordsmultifiles,getentropy
from ..modules.filetypes import checkpackedfiles,dmgunpack,unpackfile
from macholib.MachO import LC_SEGMENT,LC_SEGMENT_64,LC_LOAD_DYLIB
from macholib import MachO,SymbolTable
from plistlib import readPlist


class Macho:
    @verbose(verbose_flag)
    @progressbar(True,"Starting Macho")
    def __init__(self,qbs):
        '''
        initialize class

        Args:
            qbs: is QBStrings class, needed for string description
        '''
        self.qbs = qbs

    @verbose(verbose_flag)
    def entry_point(self,machos) -> bool:
        '''
        get entry point of macho (needs debugging)

        Args:
            machos: machos object

        Return:
            True if found
        '''
        for h in machos.headers:
            for lc, cmd, data in h.commands:
                if lc.cmd == LC_MAIN:
                    return True

    @verbose(verbose_flag)
    def getlibs(self,machos) -> list:
        '''
        get libs 

        Args:
            machos: machos object

        Return:
            list of libs with their info
        '''
        _list = []
        for h in machos.headers:
            for lc, cmd, data in h.commands:
                if lc.cmd == LC_LOAD_DYLIB:
                    _list.append({  "Library":data.decode("utf-8",errors="ignore").rstrip('\x00'),
                                    "Description":""})
        return _list

    @verbose(verbose_flag)
    def getsegments(self,machos) -> list:
        '''
        get segments 

        Args:
            machos: machos object

        Return:
            list of segments with their info
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

    @verbose(verbose_flag)
    def getsections(self,machos) -> list:
        '''
        get sections 

        Args:
            machos: machos object

        Return:
            list of segments with their info
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

    @verbose(verbose_flag)
    def getsymbols(self,machos) -> list:
        '''
        get all symbols

        Args:
            machos: machos object

        Return:
            list of symbols
        '''
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.nlists:
            _list.append({"Symbol":name.decode("utf-8",errors="ignore"),
                          "Description":""})
        return _list

    @verbose(verbose_flag)
    def getlocalsymbols(self,machos) -> list:
        '''
        get local symbols

        Args:
            machos: machos object

        Return:
            list of local symbols
        '''
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.localsyms:
            _list.append({  "Symbol":name.decode("utf-8",errors="ignore"),
                            "Description":""})
        return _list

    @verbose(verbose_flag)
    def getundefsymbols(self,machos) -> list:
        '''
        get undefined symbols

        Args:
            machos: machos object

        Return:
            list of undefined symbols
        '''
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.undefsyms:
            _list.append({ "Symbol":name.decode("utf-8",errors="ignore"),
                            "Description":""})
        return _list

    @verbose(verbose_flag)
    def getextdefsymbols(self,machos) -> list:
        '''
        get external reference symbol indices

        Args:
            machos: machos object

        Return:
            list of external symbols
        '''
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.extdefsyms:
            _list.append({  "Symbol":name.decode("utf-8",errors="ignore"),
                            "Description":""})
        return _list

    @verbose(verbose_flag)
    def getplist(self,plist) -> dict:
        '''
        read plist file

        Args:
            plist: path of info.plist

        Return:
            dict conatins key and values of plist
        '''
        return readPlist(plist)

    @verbose(verbose_flag)
    def checkdmgsig(self,data) -> bool:
        '''
        check mime is dmg or not

        Args:
            data: data dict

        Return:
            True if dmg
        '''
        if  data["Details"]["Properties"]["mime"] == "application/zlib" and \
            data["Location"]["Original"].endswith(".dmg"):
            x = dmgunpack(data["Location"]["File"])
            if x: 
                if checkpackedfiles(x,["info.plist"]):
                    unpackfile(data,x)
                    return True

    @verbose(verbose_flag)
    def checkmacsig(self,data) -> bool:
        '''
        check mime is machO or not

        Args:
            data: data dict

        Return:
            True if machO
        '''
        if data["Details"]["Properties"]["mime"] == "application/x-mach-binary":
            return True

    @verbose(verbose_flag)
    def checkipa(self,data) -> bool:
        '''
        check mime is dmg or not

        Args:
            data: data dict

        Return:
            True if dmg
        '''
        if  data["Details"]["Properties"]["mime"] == "application/zlib" and \
            data["Location"]["Original"].endswith(".ipa"):
            x = dmgunpack(data["Location"]["File"])
            if x: 
                if checkpackedfiles(x,["info.plist"]):
                    unpackfile(data,x)
                    return True

    @verbose(verbose_flag)
    @progressbar(True,"Analzying DMG file")
    def getipadeatils(self,data):
        '''
        start analyzing dmg file, loop over packed file and extract info.plist and shells

        Args:
            data: data dict
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

    @verbose(verbose_flag)
    @progressbar(True,"Analzying DMG file")
    def getdmgdeatils(self,data):
        '''
        start analyzing dmg file, loop over packed file and extract info.plist and shells

        Args:
            data: data dict
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
                
    @verbose(verbose_flag)
    @progressbar(True,"Analzying MACHO file")
    def getmachodeatils(self,data):
        '''
        start analyzing macho logic, add descriptions and get words and wordsstripped from the file 

        Args:
            data: data dict
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
        self.qbs.adddescription("ManHelp",data["MACHO"]["Symbols"],"Symbol")
        getwords(data,data["Location"]["File"])
