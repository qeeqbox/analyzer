'''
    __G__ = "(G)bd249ce4"
    intell -> Flags
'''

from copy import deepcopy
from analyzer.logger.logger import ignore_excpetion, verbose


class QBCountriesviz:
    '''
    QBCountriesviz extracting flags and codes
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBCountriesviz")
    def __init__(self):
        '''
        Initialize QBCountriesviz, this has to pass
        '''
        self.datastruct = {"Codes": []}

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def find_flags(self, flags, data):
        '''
        get ISO 3166-1 alpha-2 codes
        '''
        keys = ["PCAP", "Patterns"]
        for key in keys:
            with ignore_excpetion(Exception):
                if key in data and "IP4S" in data[key]:
                    for temp_value in data[key]["IP4S"]:
                        if temp_value["Alpha2"] not in flags and len(temp_value["Alpha2"]) > 0:
                            flags.append(temp_value["Alpha2"].lower())

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def find_codes(self, codes, data):
        '''
        find codes
        '''
        keys = ["PCAP", "Patterns"]
        for key in keys:
            with ignore_excpetion(Exception):
                if key in data and "IP4S" in data[key]:
                    for temp_value in data[key]["IP4S"]:
                        if temp_value["Code"] not in codes and temp_value["Code"]:
                            codes.append(temp_value["Code"])

    @verbose(True, verbose_output=False, timeout=None, _str="Get countries flags")
    def get_flags_from_codes(self, data):
        '''
        start get countries flags logic
        '''
        data["Flags"] = {"Flags": []}
        self.find_flags(data["Flags"]["Flags"], data)

    @verbose(True, verbose_output=False, timeout=None, _str="Get countries codes")
    def get_all_codes(self, data):
        '''
        start get countries codes logic
        '''
        data["Codes"] = deepcopy(self.datastruct)
        self.find_codes(data["Codes"]["Codes"], data)
