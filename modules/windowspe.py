'''
    __G__ = "(G)bd249ce4"
    modules -> pcap
'''
from hashlib import md5
from datetime import datetime
from copy import deepcopy
from pefile import PE, RESOURCE_TYPE, DIRECTORY_ENTRY
from M2Crypto import BIO, m2, SMIME, X509
from analyzer.logger.logger import ignore_excpetion, verbose
from analyzer.mics.funcs import get_words, get_entropy, get_entropy_float_ret
from analyzer.intell.qbdescription import add_description
from r2pipe import open as r2open


class WindowsPe:
    '''
    WindowsPe extract artifacts from pe
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting WindowsPe")
    def __init__(self):
        self.datastruct = {"General": {},
                           "Characteristics": {},
                           "Singed": [],
                           "SignatureExtracted": {},
                           "Stringfileinfo": {},
                           "Sections": [],
                           "Dlls": [],
                           "Resources": [],
                           "Imported functions": [],
                           "Exported functions": [],
                           "Debug": [],
                           "Manifest": "",
                           "Entrypoint": "",
                           "_General": {},
                           "_Characteristics": {},
                           "_Singed": ["Wrong", "SignatureHex"],
                           "__SignatureExtracted": {},
                           "_Stringfileinfo": {},
                           "_Sections": ["Section", "Suspicious", "Size", "Entropy", "MD5", "Description"],
                           "_Dlls": ["Dll", "Description"],
                           "_Resources": ["Resource", "Offset", "MD5", "Sig", "Description"],
                           "_Imported functions": ["Dll", "Function", "Description"],
                           "_Exported functions": ["Dll", "Function", "Description"],
                           "_Debug": ["Name", "Description"],
                           "_Manifest": "",
                           "_Entrypoint": ""}

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def what_type(self, pe_info) -> str:
        '''
        check file exe or dll or driver
        '''
        temp_string = ""
        if pe_info.is_exe():
            temp_string = "exe"
        elif pe_info.is_dll():
            temp_string = "dll"
        elif pe_info.is_driver():
            temp_string = "driver"
        return temp_string

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_if_singed(self, pe_info) -> list:
        '''
        check file if it has Signature or not
        '''
        index = 0
        temp_list = []
        _extracted = {}
        problems = True
        address = pe_info.OPTIONAL_HEADER.DATA_DIRECTORY[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
        if address != 0:
            with ignore_excpetion(Exception):
                sig = pe_info.write()[address + 8:]
                m2cbio = BIO.MemoryBuffer(bytes(sig))
                if m2cbio:
                    pkcs7bio = m2.pkcs7_read_bio_der(m2cbio.bio_ptr())
                    if pkcs7bio:
                        pkcs7 = SMIME.PKCS7(pkcs7bio)
                        for cert in pkcs7.get0_signers(X509.X509_Stack()):
                            tempcert = "CERT_{}".format(index)
                            _extracted[tempcert] = {"CommonName": None,
                                                    "OrganizationalUnit": None,
                                                    "Organization": None,
                                                    "Locality": None,
                                                    "StateOrProvinceName": None,
                                                    "CountryName": None,
                                                    "Start": None,
                                                    "Ends": None,
                                                    "SerialNumber": None}
                            with ignore_excpetion(Exception):
                                _extracted[tempcert]["CommonName"] = cert.get_subject().CN
                            with ignore_excpetion(Exception):
                                _extracted[tempcert]["OrganizationalUnit"] = cert.get_subject().OU
                            with ignore_excpetion(Exception):
                                _extracted[tempcert]["Organization"] = cert.get_subject().O
                            with ignore_excpetion(Exception):
                                _extracted[tempcert]["Locality"] = cert.get_subject().L
                            with ignore_excpetion(Exception):
                                _extracted[tempcert]["StateOrProvinceName"] = cert.get_subject().S
                            with ignore_excpetion(Exception):
                                _extracted[tempcert]["CountryName"] = cert.get_subject().C
                            with ignore_excpetion(Exception):
                                _extracted[tempcert]["Email"] = cert.get_subject().Email
                            with ignore_excpetion(Exception):
                                _extracted[tempcert]["Start"] = str(cert.get_not_before())
                            with ignore_excpetion(Exception):
                                _extracted[tempcert]["Ends"] = str(cert.get_not_after())
                            with ignore_excpetion(Exception):
                                _extracted[tempcert]["SerialNumber"] = cert.get_serial_number()
                                _extracted[tempcert]["SerialNumberMD5"] = cert.get_fingerprint('md5').lower().rjust(32, '0')
                problems = False
            sighex = "".join("{:02x}".format(x) for x in sig)
            temp_list.append({"Wrong": problems,
                              "SignatureHex": sighex})
        return temp_list, _extracted

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def find_entry_point_function(self, pe_info, rva_off) -> str:
        '''
        find entery point in sections
        '''
        for section in pe_info.sections:
            if section.contains_rva(rva_off):
                return section
        return ""

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_dlls(self, pe_info) -> list:
        '''
        get dlls
        '''
        temp_list = []
        for dll in pe_info.DIRECTORY_ENTRY_IMPORT:
            if dll.dll.decode("utf-8", errors="ignore") not in str(temp_list):
                temp_list.append({"Dll": dll.dll.decode("utf-8", errors="ignore"),
                                  "Description": ""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_sections(self, pe_info) -> list:
        '''
        get sections
        '''
        temp_list = []
        for section in pe_info.sections:
            is_sus = "No"
            entropy = get_entropy_float_ret(section.get_data())
            if entropy > 6 or (0 <= entropy <= 1):
                is_sus = "True, {}".format(entropy)
            elif section.SizeOfRawData == 0:
                is_sus = "True, section size 0"
            temp_list.append({"Section": section.Name.decode("utf-8", errors="ignore").strip("\00"),
                              "Suspicious": is_sus,
                              "Size": section.SizeOfRawData,
                              "MD5": section.get_hash_md5(),
                              "Entropy": get_entropy(section.get_data()),
                              "Description": ""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_imported_functions(self, pe_info) -> list:
        '''
        get import functions
        '''
        temp_list = []
        if hasattr(pe_info, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe_info.DIRECTORY_ENTRY_IMPORT:
                for func in entry.imports:
                    #print({entry.dll.decode("utf-8", errors="ignore"):func.name.decode("utf-8", errors="ignore")})
                    temp_list.append({"Dll": entry.dll.decode("utf-8", errors="ignore"),
                                      "Function": func.name.decode("utf-8", errors="ignore"),
                                      "Description": ""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_exported_functions(self, pe_info) -> list:
        '''
        get export functions
        '''
        temp_list = []
        if hasattr(pe_info, "DIRECTORY_ENTRY_EXPORT"):
            for func in pe_info.DIRECTORY_ENTRY_EXPORT.symbols:
                temp_list.append({"Function": func.name.decode("utf-8", errors="ignore"),
                                  "Description": ""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_recourse(self, pe_info) -> (list, str):
        '''
        get resources
        '''
        manifest = ""
        temp_list = []
        _icons = []
        if hasattr(pe_info, "DIRECTORY_ENTRY_RESOURCE"):
            for resource_type in pe_info.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    name = resource_type.name
                else:
                    name = RESOURCE_TYPE.get(resource_type.struct.Id)
                if name is None:
                    name = resource_type.struct.Id
                if hasattr(resource_type, "directory"):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, "directory"):
                            for resource_lang in resource_id.directory.entries:
                                resourcedata = pe_info.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                if name == "RT_MANIFEST":
                                    with ignore_excpetion(Exception):
                                        manifest = resourcedata.decode("utf-8", errors="ignore")
                                sig = ""
                                if len(resourcedata) >= 12:
                                    sig = "".join("{:02x}".format(x) for x in resourcedata[:12])
                                temp_list.append({"Resource": name,
                                                  "Offset": hex(resource_lang.data.struct.OffsetToData),
                                                  "MD5": md5(resourcedata).hexdigest(),
                                                  "Sig": sig,
                                                  "Description": ""})
                                if name == "RT_ICON":
                                    _icons.append(resourcedata)
        return temp_list, manifest, _icons

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_string_file_info(self, pe_info) -> dict:
        '''
        get string
        '''
        _dict = {}
        if hasattr(pe_info, "IMAGE_DIRECTORY_ENTRY_RESOURCE"):
            pe_info.parse_data_directories(directories=[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            for fileinfo in pe_info.FileInfo[0]:
                if fileinfo.Key.decode() == 'StringFileInfo':
                    for string_table in fileinfo.StringTable:
                        for entry in string_table.entries.items():
                            _dict.update({(entry[0].decode("utf-8", errors="ignore")): entry[1].decode("utf-8", errors="ignore")})
                    if len(_dict) > 0:
                        return _dict
        return _dict

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_characteristics(self, pe_info) -> dict:
        '''
        get characteristics of file
        '''
        temp_x = {"High Entropy": pe_info.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
                  "aslr": pe_info.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
                  "Force Integrity": pe_info.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
                  "dep": pe_info.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
                  "seh": not pe_info.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH,
                  "No Bind": pe_info.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_BIND,
                  "cfg": pe_info.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF,
                  "No Isolation": pe_info.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
                  "App Container": pe_info.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_APPCONTAINER,
                  "wdm Driver": pe_info.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_WDM_DRIVER}
        return temp_x

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_debug(self, pe_info) -> list:
        '''
        get debug directory
        '''
        temp_list = []
        if hasattr(pe_info, "DIRECTORY_ENTRY_DEBUG"):
            for item in pe_info.DIRECTORY_ENTRY_DEBUG:
                temp_list.append({"Name": item.entries.PdbFileName,
                                  "Description": ""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig(self, data) -> bool:
        '''
        check mime is exe or msi
        '''
        if data["Details"]["Properties"]["mime"] == "application/x-dosexec" or \
                data["Details"]["Properties"]["mime"] == "application/x-msi":
            return True
        return False

    @verbose(True, verbose_output=False, timeout=None, _str="Analyzing PE file")
    def analyze(self, data):
        '''
        start analyzing exe logic, add descriptions and get words and wordsstripped from the file
        '''
        data["PE"] = deepcopy(self.datastruct)
        data["ICONS"] = {"ICONS": []}
        pe_info = PE(data["Location"]["File"])
        ep_info = pe_info.OPTIONAL_HEADER.AddressOfEntryPoint
        section = self.find_entry_point_function(pe_info, ep_info)
        singinhex = "UnKnown"
        en_section_name = "UnKnown"
        sig_instructions = "UnKnown"
        with ignore_excpetion(Exception):
            sig = section.get_data(ep_info, 52)
            singinhex = "".join("{:02x}".format(x) for x in sig)
            r2p = r2open("-", flags=['-2'])
            r2p.cmd("e anal.timeout = 5")
            temp_sig_instructions = r2p.cmd("pad {}".format(singinhex)).split("\n")[:8]
            sig_instructions = "\n".join(temp_sig_instructions)
        with ignore_excpetion(Exception):
            en_section_name = section.Name.decode("utf-8", errors="ignore").strip("\00")
        data["PE"]["General"] = {"PE Type": self.what_type(pe_info),
                                 "Entrypoint": pe_info.OPTIONAL_HEADER.AddressOfEntryPoint,
                                 "Entrypoint Section": en_section_name,
                                 "Header checksum": hex(pe_info.OPTIONAL_HEADER.CheckSum),
                                 "Verify checksum": hex(pe_info.generate_checksum()),
                                 "Match checksum": pe_info.verify_checksum(),
                                 "Sig": singinhex,
                                 "imphash": pe_info.get_imphash(),
                                 "warning": pe_info.get_warnings() if len(pe_info.get_warnings()) > 0 else "None",
                                 "Timestamp": datetime.fromtimestamp(pe_info.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S')}
        data["PE"]["Characteristics"] = self.get_characteristics(pe_info)
        data["PE"]["Singed"], data["PE"]["SignatureExtracted"] = self.check_if_singed(pe_info)
        data["PE"]["Stringfileinfo"] = self.get_string_file_info(pe_info)
        data["PE"]["Sections"] = self.get_sections(pe_info)
        data["PE"]["Dlls"] = self.get_dlls(pe_info)
        data["PE"]["Resources"], data["PE"]["Manifest"], data["ICONS"]["ICONS"] = self.get_recourse(pe_info)
        data["PE"]["Imported functions"] = self.get_imported_functions(pe_info)
        data["PE"]["Exported functions"] = self.get_exported_functions(pe_info)
        data["PE"]["Entrypoint"] = sig_instructions
        add_description("WinApis", data["PE"]["Imported functions"], "Function")
        add_description("ManHelp", data["PE"]["Imported functions"], "Function")
        add_description("WinDlls", data["PE"]["Dlls"], "Dll")
        add_description("WinSections", data["PE"]["Sections"], "Section")
        add_description("WinResources", data["PE"]["Resources"], "Resource")
        get_words(data, data["Location"]["File"])
