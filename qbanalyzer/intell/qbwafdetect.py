__version__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from re import compile, search
from codecs import open as copen
from json import loads
from os import mkdir, path
#need refactoring

@progressbar(True,"Starting QBWafDetect")
class QBWafDetect:
    def __init__(self):
        '''
        initialize class and make detections path 
        '''
        self.intell = path.abspath(path.join(path.dirname( __file__ ),'detections'))
        if not self.intell.endswith(path.sep): self.intell = self.intell+path.sep
        if not path.isdir(self.intell): mkdir(self.intell)

    @progressbar(True,"Checking packets for WAF detection")
    def checkpacketsforwaf(self,data,_data,filename):
        listheaders = []
        listpayloads = []

        for _ in data:
            listheaders.append(str( _["fields"]))
            listpayloads.append(str( _["payload"]))

        headers = "".join(listheaders)
        "".join(listpayloads)

        with copen(self.intell+filename,"r",encoding='utf8') as f:
            for _ in loads(f.read()):
                try:
                    if "Type" in _ and "WQREGEX" in _["Type"]:
                        if _["Options"]["Word"] == "Normal" and "Header_Detection" in _:
                            x = search(compile(r"{}".format(_["Header_Detection"]),_["Options"]["Flag"]),headers)
                        elif _["Options"]["Word"] == "Normal" and "Content_Detection" in _:
                            x = search(compile(r"{}".format(_["Content_Detection"]),_["Options"]["Flag"]),headers)
                        if x is not None:
                            _data.append({"Matched":"1","Required":_["Options"]["Required"],"WAF":_["Name"],"Detected":x.group()})
                except:
                    pass