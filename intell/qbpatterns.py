'''
    __G__ = "(G)bd249ce4"
    connection ->  common patterns
'''

from re import I, findall
from re import compile as rcompile
from binascii import unhexlify
from ipaddress import ip_address
from copy import deepcopy
from analyzer.logger.logger import ignore_excpetion, verbose
from analyzer.mics.funcs import check_url
from analyzer.intell.qbdescription import add_description


class QBPatterns:
    '''
    QBPatterns for detecting common patterns
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBPatterns")
    def __init__(self):
        '''
        Initialize QBPatterns, this has to pass
        '''
        self.datastruct = {"IP4S": [],
                           "IP4SANDPORT": [],
                           "IP6S": [],
                           "LINKS": [],
                           "EMAILS": [],
                           "TELS": [],
                           "TAGS": [],
                           "HEX": [],
                           "_IP4S": ["Count", "IP", "Code", "Alpha2", "Description"],
                           "_IP4SANDPORT": ["Count", "IP", "Port", "Description"],
                           "_IP6S": ["Count", "IP", "Code", "Alpha2", "Description"],
                           "_LINKS": ["Count", "Link", "Description"],
                           "_EMAILS": ["Count", "EMAIL", "Description"],
                           "_TELS": ["Count", "TEL", "Description"],
                           "_TAGS": ["Count", "TAG", "Description"],
                           "_HEX": ["Count", "HEX", "Parsed"]}

        self.links = rcompile(r"((?:(smb|srm|ssh|ftps|file|http|https|ftp):\/\/)?[a-zA-Z0-9]+(\.[a-zA-Z0-9-]+)+([a-zA-Z0-9_\,\'\/\+&amp;%#\$\?\=~\.\-]*[a-zA-Z0-9_\,\'\/\+&amp;%#\$\?\=~\.\-])?)", I)
        self.ip4 = rcompile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\b', I)
        self.ip4andports = rcompile(r'\b((?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]):[0-9]{1,5})\b', I)
        self.ip6 = rcompile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', I)
        self.email = rcompile(r'(\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*)', I)
        self.tel = rcompile(r'(\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*)', I)
        self.html = rcompile(r'>([^<]*)<\/', I)
        self.hex = rcompile(r'([0-9a-fA-F]{4,})', I)
        self.words = []
        self.wordsstripped = ""

    @verbose(True, verbose_output=False, timeout=None, _str="Finding URLs patterns")
    def check_link(self, _data):
        '''
        check if buffer contains ips xxx://xxxxxxxxxxxxx.xxx
        '''
        temp_list = []
        temp_var = list(set(findall(self.links, self.wordsstripped)))
        if len(temp_var) > 0:
            for _ in temp_var:
                if check_url(_[0]):
                    temp_list.append(_[0])
        for temp_var in set(temp_list):
            _data.append({"Count": temp_list.count(temp_var), "Link": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding IP4s patterns")
    def check_ip4(self, _data):
        '''
        check if buffer contains ips x.x.x.x
        '''
        temp_list = []
        temp_var = findall(self.ip4, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                with ignore_excpetion(Exception):
                    ip_address(_)
                    temp_list.append(_)
        for temp_var in set(temp_list):
            _data.append({"Count": temp_list.count(temp_var), "IP": temp_var, "Code": "", "Alpha2": "", "Description": ""})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding IP4 ports patterns")
    def check_ip4_ports(self, _data):
        '''
        check if buffer contains ips x.x.x.x:xxxxx
        '''
        temp_list = []
        temp_var = findall(self.ip4andports, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                with ignore_excpetion(Exception):
                    temp_ip, temp_port = _.split(":")
                    ip_address(temp_ip)
                    temp_list.append(_)
        for temp_var in set(temp_list):
            temp_ip, temp_port = temp_var.split(":")
            _data.append({"Count": temp_list.count(temp_var), "IP": temp_ip, "Port": temp_port, "Description": ""})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding IP6s patterns")
    def check_ip6(self, _data):
        '''
        check if buffer contains ips x.x.x.x
        '''
        temp_list = []
        temp_var = findall(self.ip6, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            _data.append({"Count": temp_list.count(temp_var), "IP": temp_var, "Code": "", "Alpha2": "", "Description": ""})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Emails patterns")
    def check_email(self, _data):
        '''
        check if buffer contains email xxxxxxx@xxxxxxx.xxx
        '''
        temp_list = []
        temp_var = findall(self.email, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_[0])
        for temp_var in set(temp_list):
            _data.append({"Count": temp_list.count(temp_var), "EMAIL": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding TELs patterns")
    def check_phone_number(self, _data):
        '''
        check if buffer contains tel numbers 012 1234 567
        '''
        temp_list = []
        temp_var = findall(self.tel, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            _data.append({"Count": temp_list.count(temp_var), "TEL": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding tags patterns")
    def check_tags(self, _data):
        '''
        check if buffer contains tags <>
        '''
        temp_list = []
        temp_var = findall(self.html, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            _data.append({"Count": temp_list.count(temp_var), "TAG": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding HEX patterns")
    def check_hex(self, _data):
        '''
        check if buffer contains tags <>
        '''
        temp_list = []
        temp_var = findall(self.hex, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            with ignore_excpetion(Exception):
                parsed = unhexlify(temp_var)
                _data.append({"Count": temp_list.count(temp_var), "HEX": temp_var, "Parsed": parsed.decode('utf-8', errors="ignore")})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def analyze(self, data):
        '''
        start pattern analysis for words and wordsstripped
        '''
        data["Patterns"] = deepcopy(self.datastruct)
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.check_link(data["Patterns"]["LINKS"])
        self.check_ip4(data["Patterns"]["IP4S"])
        self.check_ip4_ports(data["Patterns"]["IP4SANDPORT"])
        self.check_ip6(data["Patterns"]["IP6S"])
        self.check_email(data["Patterns"]["EMAILS"])
        self.check_tags(data["Patterns"]["TAGS"])
        self.check_hex(data["Patterns"]["HEX"])
        add_description("URLshorteners", data["Patterns"]["LINKS"], "Link")
        add_description("DNSServers", data["Patterns"]["IP4S"], "IP")
        add_description("ReservedIP", data["Patterns"]["IP4S"], "IP")
        add_description("CountriesIPs", data["Patterns"]["IP4S"], "IP")
        add_description("Ports", data["Patterns"]["IP4SANDPORT"], "Port")
        add_description("Emails", data["Patterns"]["EMAILS"], "EMAIL")
