__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from ...mics.funcs import getwords
from pefile import PE,RESOURCE_TYPE,DIRECTORY_ENTRY
from hashlib import md5
from magic import from_file
from datetime import datetime

class WindowsPe:
    @verbose(verbose_flag)
    @progressbar(True,"Starting WindowsPe")
    def __init__(self,qbs):
        self.qbs = qbs

    @verbose(verbose_flag)
    def whattype(self,pe):
        if pe.is_exe():
            return "exe"
        elif pe.is_dll():
            return "dll"
        elif pe.is_driver():
            return "driver"
        return None

    @verbose(verbose_flag)
    def checkifsinged(self,pe):
        _list = []
        address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
        if address != 0:
            sig = pe.write()[address+8:]
            sighex = "".join("{:02x}".format(x) for x in sig)
            _list.append({"Signature":"Yes",
                          "SignatureHex":sighex})
        return _list

    @verbose(verbose_flag)
    def findentrypointfunction(self,pe, rva):
        for section in pe.sections:
            if section.contains_rva(rva):
                return section
        return None

    @verbose(verbose_flag)
    def getdlls(self,pe):
        _list = []
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            if dll.dll.decode("utf-8") not in str(_list):
                _list.append({"Dll":dll.dll.decode("utf-8"),
                              "Description":""})
        return _list

    @verbose(verbose_flag)
    def getsections(self,pe):
        _list = []
        for section in pe.sections:
            _list.append({  "Section":section.Name.decode("utf-8").strip("\00"),
                            "MD5":section.get_hash_md5(),
                            "Description":""})
        return _list

    @verbose(verbose_flag)
    def getimportedfunctions(self,pe):
        _importedfunctions = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for func in entry.imports:
                    #print({entry.dll.decode("utf-8"):func.name.decode("utf-8")})
                    _importedfunctions.append({ "Dll":entry.dll.decode("utf-8"),
                                                "Function":func.name.decode("utf-8"),
                                                "Description":""})
        return _importedfunctions

    @verbose(verbose_flag)
    def getexportedfunctions(self,pe):
        _exportedfunction = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for func in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                _exportedfunction.append({ "Function":func.name.decode("utf-8"),
                                           "Description":""})
        return _exportedfunction

    @verbose(verbose_flag)
    def getrecourse(self,pe):
        manifest = ""
        resources = []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    name = resource_type.name
                else:
                    name = RESOURCE_TYPE.get(resource_type.struct.Id)
                if name == None:
                    name = resource_type.struct.Id
                if hasattr(resource_type, "directory"):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, "directory"):
                            for resource_lang in resource_id.directory.entries:
                                resourcedata = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                if name == "RT_MANIFEST":
                                    try:
                                        manifest = resourcedata.decode("utf-8")
                                    except:
                                        pass
                                sig = ""
                                if len(resourcedata) >= 12:
                                    sig = "".join("{:02x}".format(x) for x in resourcedata[:12])
                                resources.append({  "Resource":name,
                                                    "Offset":hex(resource_lang.data.struct.OffsetToData),
                                                    "MD5":md5(resourcedata).hexdigest(),
                                                    "Sig":sig,
                                                    "Description":""})
        return resources,manifest



    @verbose(verbose_flag)
    def getCharacteristics(self,pe):
        x = {"High Entropy":pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
             "aslr":pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
             "Force Integrity":pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
             "dep":pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
             "seh":not pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH,
             "No Bind":pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_BIND,
             "cfg":pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF,
             "No Isolation":pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
             "App Container":pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_APPCONTAINER,
             "wdm Driver":pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_WDM_DRIVER}
        return x

    @verbose(verbose_flag)
    def getdebug(self,pe):
        _list = []
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            for i in pe.DIRECTORY_ENTRY_DEBUG:
                _list.append({  "Name":i.entries.PdbFileName,
                                "Description":""})

    @verbose(verbose_flag)
    def checkpesig(self,data):
        if data["Details"]["Properties"]["mime"] == "application/x-dosexec" or data["Details"]["Properties"]["mime"] == "application/x-msi":
            return True

    @verbose(verbose_flag)
    @progressbar(True,"Analyzing PE file")
    def getpedeatils(self,data):
        data["PE"] = {  "General" : {},
                        "Characteristics":{},
                        "Singed":[],
                        "Sections":[],
                        "Dlls":[],
                        "Resources":[],
                        "Imported functions":[],
                        "Exported functions":[],
                        "Manifest":"",
                        "_General": {},
                        "_Characteristics": {},
                        "_Singed":["Signature","SignatureHex"],
                        "_Sections":["Section","MD5","Description"],
                        "_Dlls":["Dll","Description"],
                        "_Resources":["Resource","Offset","MD5","Sig","Description"],
                        "_Imported functions":["Dll","Function","Description"],
                        "_Exported functions":["Dll","Function","Description"],
                        "_Manifest":""}
        pe = PE(data["Location"]["File"])
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        _ep = ep
        section = self.findentrypointfunction(pe,ep)
        sig = section.get_data(ep, 12)
        sectionname = section.Name.decode("utf-8").strip("\00")
        singinhex = "".join("{:02x}".format(x) for x in sig)
        sectionentropy = section.get_entropy()
        imphash = pe.get_imphash()
        warning = pe.get_warnings()
        checksum = pe.verify_checksum()
        timestamp = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
        sections = self.getsections(pe)
        dlls = self.getdlls(pe)
        pe_type = self.whattype(pe)
        resources,manifest = self.getrecourse(pe)
        self.getdebug(pe)
        signature = self.checkifsinged(pe)
        Characteristics = self.getCharacteristics(pe)
        importedfunctions = self.getimportedfunctions(pe)
        exportedfunctions = self.getexportedfunctions(pe)
        data["PE"]["General"] = {   "PE Type" : pe_type,
                                    "Entropy": sectionentropy,
                                    "Entrypoint": _ep,
                                    "Entrypoint Section":sectionname,
                                    "verify checksum":checksum,
                                    "Sig":singinhex,
                                    "imphash":imphash,
                                    "warning":warning,
                                    "Timestamp":timestamp}
        data["PE"]["Characteristics"] = Characteristics
        data["PE"]["Singed"] = signature
        data["PE"]["Sections"] = sections
        data["PE"]["Dlls"] = dlls
        data["PE"]["Resources"] = resources
        data["PE"]["Imported functions"] = importedfunctions
        data["PE"]["Exported functions"] = exportedfunctions
        data["PE"]["Manifest"] = manifest
        self.qbs.adddescription("WinApis",data["PE"]["Imported functions"],"Function")
        self.qbs.adddescription("ManHelp",data["PE"]["Imported functions"],"Function")
        self.qbs.adddescription("WinDlls",data["PE"]["Dlls"],"Dll")
        self.qbs.adddescription("WinSections",data["PE"]["Sections"],"Section")
        self.qbs.adddescription("WinResources",data["PE"]["Resources"],"Resource")
        words,wordsstripped = getwords(data["Location"]["File"])
        data["StringsRAW"] = {"words":words,
                              "wordsstripped":wordsstripped}