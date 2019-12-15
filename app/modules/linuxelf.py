__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag,verbose_timeout
from ..mics.funcs import getentropy,getwords,getentropyfloatret
from ..intell.qbdescription import adddescription
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import describe_reloc_type
from elftools.elf.descriptions import describe_symbol_type
from hashlib import md5
from elftools.elf.sections import SymbolTableSection

class LinuxELF:
    @verbose(True,verbose_flag,verbose_timeout,"Starting LinuxELF")
    def __init__(self):
        pass

    @verbose(True,verbose_flag,verbose_timeout,None)
    def getrelocations(self,elf) -> list:
        '''
        get symbols locations
        '''
        _list = []
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                symboltable = elf.get_section(section['sh_link'])
                for relocation in section.iter_relocations():
                    symbol = symboltable.get_symbol(relocation['r_info_sym'])
                    #address = hex(relocation['r_offset']) section['sh_flags']  section['sh_type']
                    #some have no names, need to check this out
                    if symbol.name != "":
                        _list.append({  "Section":section.name,
                                        "Name":symbol.name,
                                        "Description":""})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def getsymbols(self,elf) -> list:
        '''
        get symbols and types 
        '''
        _list = []
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if len(symbol.name) > 0:
                    _list.append({  "Type":describe_symbol_type(symbol['st_info']['type']),
                                    "Symbol":symbol.name,
                                    "Description":""})
            return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def getdynamic(self,elf) -> list:
        '''
        get dynamic libraries 
        '''
        _list = []
        section = elf.get_section_by_name('.dynamic')
        if section != None:
            for tag in section.iter_tags():
                if tag.entry.d_tag != "DT_NEEDED":
                    continue
                _list.append({  "Needed":tag.needed,
                                "Description":""})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def getsection(self,elf) -> list:
        '''
        get all sections of elf 
        '''
        _list = []
        for section in elf.iter_sections():
            if section.name != "":
                sus = "No"
                entropy = getentropyfloatret(section.data())
                if entropy > 6 or entropy >= 0 and entropy <=1:
                    sus = "True, {}".format(entropy)
                elif section.data_size == 0:
                    sus = "True, section size 0"
                _list.append({  "Section":section.name,
                                "Suspicious":sus,
                                "Size":section.data_size,
                                "MD5":md5(section.data()).hexdigest(),
                                "Entropy":getentropy(section.data()),
                                "Description":""})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def getiter(self,elf) -> str:
        '''
        get run-time linker 
        '''
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_INTERP':
                return segment.get_interp_name()

    @verbose(True,verbose_flag,verbose_timeout,None)
    def checkelfsig(self,data) -> bool:
        '''
        check if mime is linux type 
        '''
        if  data["Details"]["Properties"]["mime"] == "application/x-pie-executable" or \
            data["Details"]["Properties"]["mime"] == "application/x-sharedlib" or \
            data["Details"]["Properties"]["mime"] == "application/x-executable":
            return True


    @verbose(True,verbose_flag,verbose_timeout,"Analyzing ELF file")
    def getelfdeatils(self,data):
        '''
        start analyzing elf logic, add description to strings and get words and wordsstripped from the file 
        '''
        with open(data["Location"]["File"], 'rb') as f, open(data["Location"]["File"], 'rb') as ff:
            data["ELF"] = { "General":{},
                            "Sections":[],
                            "Dynamic":[],
                            "Symbols":[],
                            "Relocations":[],
                            "_General":{},
                            "_Sections":["Section","Suspicious","Size","Entropy","MD5","Description"],
                            "_Dynamic":["Needed","Description"],
                            "_Symbols":["Type","Symbol","Description"],
                            "_Relocations":["Section","Name","Description"]}
            elf = ELFFile(f)
            data["ELF"]["General"] = {  "ELF Type" : elf.header.e_type,
                                        "ELF Machine" : elf.header.e_machine,
                                        "Entropy": getentropy(ff.read()),
                                        "Entrypoint": hex(elf.header.e_entry),
                                        "Interpreter":self.getiter(elf)}
            data["ELF"]["Sections"] = self.getsection(elf)
            data["ELF"]["Dynamic"] = self.getdynamic(elf)
            data["ELF"]["Symbols"] = self.getsymbols(elf)
            data["ELF"]["Relocations"] = self.getrelocations(elf)
            adddescription("ManHelp",data["ELF"]["Symbols"],"Symbol")
            adddescription("LinuxSections",data["ELF"]["Sections"],"Section")
            getwords(data,data["Location"]["File"])
