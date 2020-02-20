__G__ = "(G)bd249ce4"

from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout
from copy import deepcopy

class QBCountriesviz:
    @verbose(True,verbose_flag,verbose_timeout,"Starting QBCountriesviz")
    def __init__(self):
        self.datastruct = {"Codes":[]}

    @verbose(True,verbose_flag,verbose_timeout,None)
    def find_flags(self,flags,data):
        keys = ["PCAP","Patterns"]
        for key in keys:
            try:
                if key in data and "IP4S" in data[key]:
                    for x in data[key]["IP4S"]:
                        if x["Alpha2"] not in flags and len(x["Alpha2"]) > 0:
                            flags.append(x["Alpha2"].lower())
            except:
                pass

    @verbose(True,verbose_flag,verbose_timeout,None)
    def find_codes(self,codes,data):
        keys = ["PCAP","Patterns"]
        for key in keys:
            try:
                if key in data and "IP4S" in data[key]:
                    for x in data[key]["IP4S"]:
                        if x["Code"] not in codes and x["Code"]:
                            codes.append(x["Code"])
            except:
                pass

    @verbose(True,verbose_flag,verbose_timeout,"Get countries flags")
    def get_flags_from_codes(self,data):
        '''
        start get countries flags logic
        '''
        data["Flags"] = {"Flags":[]}
        self.find_flags(data["Flags"]["Flags"],data)

    @verbose(True,verbose_flag,verbose_timeout,"Get countries codes")
    def get_all_codes(self,data):
        '''
        start get countries codes logic
        '''
        data["Codes"] = deepcopy(self.datastruct)
        self.find_codes(data["Codes"]["Codes"],data)
