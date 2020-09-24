'''
    __G__ = "(G)bd249ce4"
    modules -> macos
'''

from io import BytesIO
from copy import deepcopy
from hashlib import md5
from plistlib import readPlist
from macholib.MachO import LC_SEGMENT, LC_SEGMENT_64, LC_LOAD_DYLIB
from macholib import MachO, SymbolTable
from analyzer.logger.logger import verbose
from analyzer.mics.funcs import get_words, get_words_multi_files, get_entropy, get_entropy_float_ret
from analyzer.modules.archive import check_packed_files, dmg_unpack, unpack_file
from analyzer.intell.qbdescription import add_description

LC_MAIN = 0x28 | 0x80000000

class Macho:
    '''
    Macho extracts artifacts from Macho
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting Macho")
    def __init__(self):
        '''
        initialize class and datastruct, this has to pass
        '''
        self.datastruct = {"General":{},
                           "Sections":[],
                           "Libraries":[],
                           "Symbols":[],
                           "Undefined Symbols":[],
                           "External Symbols":[],
                           "Local Symbols":[],
                           "_Sections":["Section", "Suspicious", "Size", "Entropy", "MD5", "Description"],
                           "_Libraries":["Library", "Description"],
                           "_Symbols":["Symbol", "Description"],
                           "_Undefined Symbols":["Symbol", "Description"],
                           "_External Symbols":["Symbol", "Description"],
                           "_Local Symbols":["Symbol", "Description"]}

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def entry_point(self, machos) -> bool:
        '''
        get entry point of macho (needs debugging)
        '''
        for header in machos.headers:
            for temp_lc, cmd, data in header.commands:
                if temp_lc.cmd == LC_MAIN:
                    return True
        return False

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_libs(self, machos) -> list:
        '''
        get libs
        '''
        temp_list = []
        for header in machos.headers:
            for temp_lc, cmd, data in header.commands:
                if temp_lc.cmd == LC_LOAD_DYLIB:
                    temp_list.append({"Library":data.decode("utf-8", errors="ignore").rstrip('\x00'),
                                      "Description":""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_segments(self, machos) -> list:
        '''
        get segments
        '''
        temp_list = []
        for header in machos.headers:
            for temp_lc, cmd, data in header.commands:
                if temp_lc.cmd in (LC_SEGMENT, LC_SEGMENT_64):
                    name = cmd.segname[:cmd.segname.find(b'\x00')].decode("utf-8", errors="ignore")
                    temp_list.append({"Segment":name,
                                      "Address":hex(cmd.vmaddr),
                                      "Description":""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_sections(self, machos, fbuffer) -> list:
        '''
        get sections
        '''
        temp_list = []
        for header in machos.headers:
            for temp_lc, cmd, data in header.commands:
                if hasattr(cmd, "segname"):
                    #fbuffer[cmd.fileoff:cmd.filesize]
                    with BytesIO(fbuffer) as bio:
                        bio.seek(cmd.fileoff)
                        temp_x = bio.read(cmd.filesize)
                        sus = "No"
                        entropy = get_entropy_float_ret(temp_x)
                        if entropy > 6 or (0 <= entropy <= 1):
                            sus = "True, {}".format(entropy)
                        elif cmd.filesize == 0:
                            sus = "True, section size 0"
                        seg = cmd.segname[:cmd.segname.find(b'\x00')].decode("utf-8", errors="ignore")
                        if seg == "__PAGEZERO":
                            sus = ""
                        temp_list.append({"Section":seg,
                                          "Suspicious":sus,
                                          "Size":cmd.filesize,
                                          "Entropy":get_entropy(temp_x),
                                          "MD5":md5(temp_x).hexdigest(),
                                          "Description":""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_symbols(self, machos) -> list:
        '''
        get all symbols
        '''
        temp_list = []
        temp_s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in temp_s.nlists:
            temp_list.append({"Symbol":name.decode("utf-8", errors="ignore"),
                              "Description":""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_local_symbols(self, machos) -> list:
        '''
        get local symbols
        '''
        temp_list = []
        temp_s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in temp_s.localsyms:
            temp_list.append({"Symbol":name.decode("utf-8", errors="ignore"),
                              "Description":""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_undef_symbols(self, machos) -> list:
        '''
        get undefined symbols
        '''
        temp_list = []
        temp_s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in temp_s.undefsyms:
            temp_list.append({"Symbol":name.decode("utf-8", errors="ignore"),
                              "Description":""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_extdef_symbols(self, machos) -> list:
        '''
        get external reference symbol indices
        '''
        temp_list = []
        temp_s = SymbolTable.SymbolTable(machos)
        for (nlist, name) in temp_s.extdefsyms:
            temp_list.append({"Symbol":name.decode("utf-8", errors="ignore"),
                              "Description":""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_plist(self, plist) -> dict:
        '''
        read plist file
        '''
        return readPlist(plist)

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig_dmg(self, data) -> bool:
        '''
        check mime is dmg or not
        '''
        if  data["Details"]["Properties"]["mime"] == "application/zlib" and \
            data["Location"]["Original"].endswith(".dmg"):
            temp_x = dmg_unpack(data["Location"]["File"])
            if temp_x:
                if check_packed_files(temp_x, ["info.plist"]) or check_packed_files(temp_x, ["Install"]):
                    unpack_file(data, temp_x)
                    return True
        return False

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig_macho(self, data) -> bool:
        '''
        check mime is machO or not
        '''
        if data["Details"]["Properties"]["mime"] == "application/x-mach-binary":
            return True
        return False

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig_ipa(self, data) -> bool:
        '''
        check mime is dmg or not
        '''
        if  data["Details"]["Properties"]["mime"] == "application/zlib" and \
            data["Location"]["Original"].endswith(".ipa"):
            temp_x = dmg_unpack(data["Location"]["File"])
            if temp_x:
                if check_packed_files(temp_x, ["info.plist"]):
                    unpack_file(data, temp_x)
                    return True
        return False


    @verbose(True, verbose_output=False, timeout=None, _str="Analzying IPA file")
    def analyze_ipa(self, data):
        '''
        start analyzing dmg file, loop over packed file and extract info.plist and shells
        '''
        data["IPA"] = {"General":{},
                       "_General":{}}
        for index, temp_var in enumerate(data["Packed"]["Files"]):
            if temp_var["Path"].lower().endswith("info.plist"):
                data["DMG"]["General"] = self.get_plist(temp_var["Path"])
                break
        for index, temp_var in enumerate(data["Packed"]["Files"]):
            if temp_var["Type"] == "text/x-shellscript":
                temp_k = 'DMG_Shellscript_{}'.format(index)
                data[temp_k] = {"Shell":"",
                                "_Shell":""}
                data[temp_k]["Shell"] = open(temp_var["Path"], "r").read()
        get_words_multi_files(data, data["Packed"]["Files"])


    @verbose(True, verbose_output=False, timeout=None, _str="Analzying DMG file")
    def analyze_dmg(self, data):
        '''
        start analyzing dmg file, loop over packed file and extract info.plist and shells
        '''
        data["DMG"] = {"General":{},
                       "_General":{}}
        for index, temp_var in enumerate(data["Packed"]["Files"]):
            if temp_var["Path"].lower().endswith("info.plist"):
                data["DMG"]["General"] = self.get_plist(temp_var["Path"])
                break
        for index, temp_var in enumerate(data["Packed"]["Files"]):
            if temp_var["Type"] == "text/x-shellscript":
                temp_k = 'DMG_Shellscript_{}'.format(index)
                data[temp_k] = {"Shell":"",
                                "_Shell":""}
                data[temp_k]["Shell"] = open(temp_var["Path"], "r").read()
        get_words_multi_files(data, data["Packed"]["Files"])

    @verbose(True, verbose_output=False, timeout=None, _str="Analzying MACHO file")
    def analyze_macho(self, data):
        '''
        start analyzing macho logic, add descriptions and get words and wordsstripped from the file
        '''
        macho = MachO.MachO(data["Location"]["File"])
        data["MACHO"] = deepcopy(self.datastruct)
        fbuffer = data["FilesDumps"][data["Location"]["File"]]
        data["MACHO"]["General"]: {}
        data["MACHO"]["Sections"] = self.get_sections(macho, fbuffer)
        data["MACHO"]["Libraries"] = self.get_libs(macho)
        data["MACHO"]["Symbols"] = self.get_symbols(macho)
        data["MACHO"]["Undefined Symbols"] = self.get_undef_symbols(macho)
        data["MACHO"]["External Symbols"] = self.get_extdef_symbols(macho)
        data["MACHO"]["Local Symbols"] = self.get_local_symbols(macho)
        add_description("ManHelp", data["MACHO"]["Symbols"], "Symbol")
        get_words(data, data["Location"]["File"])
