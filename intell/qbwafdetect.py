'''
    __G__ = "(G)bd249ce4"
    connection ->  waf
'''

from re import search, I
from re import compile as rcompile
from codecs import open as copen
from json import loads
from os import mkdir, path
from analyzer.logger.logger import ignore_excpetion, verbose

class QBWafDetect:
    '''
    QBWafDetect for waf detections, it uses detections folder
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBWafDetect")
    def __init__(self):
        '''
        initialize class and make detections path
        '''
        self.intell = path.abspath(path.join(path.dirname(__file__), 'detections'))
        if not self.intell.endswith(path.sep):
            self.intell = self.intell+path.sep
        if not path.isdir(self.intell):
            mkdir(self.intell)
        self.ipv4privateonelinebad = rcompile(r"^(10|127|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\..*", I)

    @verbose(True, verbose_output=False, timeout=None, _str="Checking bypass proxy")
    def check_proxy_bypass(self, data, _data):
        '''
        this function will check if headers contian common proxy bypass fields (Could be normal)
        '''
        for _ in data:
            found = ""
            if "X-Originating-IP" in _["fields"]:
                found = "X-Originating-IP"
            elif "X-Forwarded-For" in _["fields"]:
                found = "X-Forwarded-For"
            elif "X-Remote-IP" in _["fields"]:
                found = "X-Remote-IP"
            elif "X-Remote-Addr" in _["fields"]:
                found = "X-Remote-Addr"
            if found != "":
                temp_var = search(self.ipv4privateonelinebad, _["fields"][found])
                if temp_var is not None:
                    _data.append({"Matched":"1", "Required":1, "WAF":"{} contains private IP".format(found), "Detected":temp_var.group()})

    @verbose(True, verbose_output=False, timeout=None, _str="Checking packets for WAF detection")
    def analyze(self, data, _data, filename):
        '''
        start analyzing logic
        '''
        listheaders = []
        listpayloads = []

        for _ in data:
            listheaders.append(str(_["fields"]))
            listpayloads.append(str(_["payload"]))

        headers = "".join(listheaders)
        content = "".join(listpayloads)

        with copen(self.intell+filename, "r", encoding='utf8') as file:
            for _ in loads(file.read()):
                with ignore_excpetion(Exception):
                    if "Type" in _ and "WQREGEX" in _["Type"]:
                        if _["Options"]["Word"] == "Normal" and "Header_Detection" in _:
                            temp_var = search(rcompile(r"{}".format(_["Header_Detection"]), _["Options"]["Flag"]), headers)
                        elif _["Options"]["Word"] == "Normal" and "Content_Detection" in _:
                            temp_var = search(rcompile(r"{}".format(_["Content_Detection"]), _["Options"]["Flag"]), content)
                        if temp_var is not None:
                            _data.append({"Matched":"1", "Required":_["Options"]["Required"], "WAF":_["Name"], "Detected":temp_var.group()})

        self.check_proxy_bypass(data, _data)
