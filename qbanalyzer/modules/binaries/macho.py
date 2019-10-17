__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from ...mics.funcs import getwords,getwordsmultifiles
from ...modules.files.filetypes import checkpackedfiles,dmgunpack,unpackfile
from macholib.MachO import LC_SEGMENT,LC_SEGMENT_64,LC_LOAD_DYLIB
from macholib import MachO
from macholib import SymbolTable
from plistlib import readPlist

#cmd.initprot & 0x4][0]

class Macho:
    @verbose(verbose_flag)
    @progressbar(True,"Starting Macho")
    def __init__(self,qbs):
        self.qbs = qbs

    @verbose(verbose_flag)
    def entry_point(self,machos):
        for h in machos.headers:
            for lc, cmd, data in h.commands:
                if lc.cmd == LC_MAIN:
                    return True

    @verbose(verbose_flag)
    def getlibs(self,machos):
        _list = []
        #headers[0].commands
        for h in machos.headers:
            for lc, cmd, data in h.commands:
                if lc.cmd == LC_LOAD_DYLIB:
                    _list.append({  "Library":data.decode("utf-8").rstrip('\x00'),
                                    "Description":""})
        return _list

    @verbose(verbose_flag)
    def getsegments(self,machos):
        _list = []
        #headers[0].commands
        for h in machos.headers:
            for lc, cmd, data in h.commands:
                if lc.cmd in (LC_SEGMENT, LC_SEGMENT_64):
                    name = cmd.segname[:cmd.segname.find(b'\x00')].decode("utf-8")
                    _list.append({  "Segment":name,
                                    "Address":hex(cmd.vmaddr),
                                    "Description":""})
        return _list

    @verbose(verbose_flag)
    def getsections(self,machos):
        _list = []
        #headers[0].commands
        for h in machos.headers:
            for lc, cmd, data in h.commands:
                if lc.cmd in (LC_SEGMENT, LC_SEGMENT_64):
                    for section in data:
                        name = section.sectname[:section.sectname.find(b'\x00')].decode("utf-8")
                        seg = section.segname[:section.segname.find(b'\x00')].decode("utf-8")
                        _list.append({"Section":name,
                                      "Address":hex(section.addr),
                                      "Segment":seg,
                                      "Description":""})
        return _list

    @verbose(verbose_flag)
    def getsymbols(self,machos):
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.nlists:
            _list.append({"Symbol":name.decode("utf-8"),
                          "Description":""})
        return _list

    @verbose(verbose_flag)
    def getlocalsymbols(self,machos):
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.localsyms:
            _list.append({  "Symbol":name.decode("utf-8"),
                            "Description":""})
        return _list

    @verbose(verbose_flag)
    def getundefsymbols(self,machos):
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.undefsyms:
            _list.append({ "Symbol":name.decode("utf-8"),
                            "Description":""})
        return _list

    @verbose(verbose_flag)
    def getextdefsymbols(self,machos):
        _list = []
        s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in s.extdefsyms:
            _list.append({  "Symbol":name.decode("utf-8"),
                            "Description":""})
        return _list

    @verbose(verbose_flag)
    def getentropy(self,data):
        entropy = 0
        if len(data) > 0:
            for x in range(0, 256):
                p_x = float(data.count(bytes(x))) / len(data)
                if p_x > 0:
                    entropy += - p_x*log(p_x, 2)
            return "%f" % (entropy / 8)
        else:
            return "None"

    @verbose(verbose_flag)
    def getplist(self,plist):
        return readPlist(plist)

    @verbose(verbose_flag)
    def checkdmgsig(self,data):
        if  data["Details"]["Properties"]["mime"] == "application/zlib" and \
            data["Location"]["Original"].endswith(".dmg"):
            x = dmgunpack(data["Location"]["File"])
            if x: 
                if checkpackedfiles(x,[b"Info.plist"]):
                    unpackfile(data,x)
                    return True

    @verbose(verbose_flag)
    def checkmacsig(self,data):
        if data["Details"]["Properties"]["mime"] == "application/x-mach-binary":
            return True

    @verbose(verbose_flag)
    @progressbar(True,"Analzying DMG file")
    def getdmgdeatils(self,data):
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
        words,wordsstripped = getwordsmultifiles(data["Packed"]["Files"])
        data["StringsRAW"] = {"words":words,
                              "wordsstripped":wordsstripped}
                
    @verbose(verbose_flag)
    @progressbar(True,"Analzying MACHO file")
    def getmachodeatils(self,data):
        try:
            macho = MachO.MachO(data["Location"]["File"])
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
        except:
            return False
        sections = self.getsections(macho)
        libs = self.getlibs(macho)
        segments = self.getsegments(macho)
        symbols = self.getsymbols(macho)
        undefsymbols = self.getundefsymbols(macho)
        extdefsymbols = self.getextdefsymbols(macho)
        localsymbols = self.getlocalsymbols(macho)
        data["MACHO"]["General"]:{}
        data["MACHO"]["Sections"] = sections
        data["MACHO"]["Libraries"] = libs
        data["MACHO"]["Segments"] = segments
        data["MACHO"]["Symbols"] = symbols
        data["MACHO"]["Undefined Symbols"] = undefsymbols
        data["MACHO"]["External Symbols"] = extdefsymbols
        data["MACHO"]["Local Symbols"] = localsymbols
        self.qbs.adddescription("ManHelp",data["MACHO"]["Symbols"],"Symbol")
        words,wordsstripped = getwords(data["Location"]["File"])
        data["StringsRAW"] = {"words":words,
                              "wordsstripped":wordsstripped}
