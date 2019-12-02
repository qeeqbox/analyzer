__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar

class QBCountriesviz:
    @verbose(verbose_flag)
    @progressbar(True,"Starting QBCountriesviz")
    def __init__(self):
        '''
        initialize class
        '''

    @verbose(verbose_flag)
    def findflags(self,flags,data):
        keys = ["PCAP","Patterns"]
        for key in keys:
            try:
                if key in data and "IP4S" in data[key]:
                    for x in data[key]["IP4S"]:
                        if x["Alpha2"] not in flags and len(x["Alpha2"]) > 0:
                            flags.append(x["Alpha2"].lower())
            except:
                pass

    @verbose(verbose_flag)
    def findcodes(self,codes,data):
        keys = ["PCAP","Patterns"]
        for key in keys:
            try:
                if key in data and "IP4S" in data[key]:
                    for x in data[key]["IP4S"]:
                        if x["Code"] not in codes and x["Code"]:
                            codes.append(x["Code"])
            except:
                pass

    @verbose(verbose_flag)
    @progressbar(True,"Get countries flags")
    def getflagsfromcodes(self,data):
        '''
        start get countries flags logic
        '''

        data["Flags"] = {"Flags":[]}
        self.findflags(data["Flags"]["Flags"],data)

    @verbose(verbose_flag)
    @progressbar(True,"Get countries flags")
    def getallcodes(self,data):
        '''
        start get countries codes logic
        '''

        data["Codes"] = {"Codes":[]}
        self.findcodes(data["Codes"]["Codes"],data)
