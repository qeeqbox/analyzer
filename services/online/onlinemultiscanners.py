__G__ = "(G)bd249ce4"

from os import path
from ...logger.logger import verbose, verbose_flag, verbose_timeout
from .hybridanalysis import HybridAnalysis
from .malshare import MalShare
from .metadefender import MetaDefender
from .virustotal import VirusTotal
from .alienvault import AlienVault
from copy import deepcopy

class OnlineMultiScanners:
    @verbose(True,verbose_flag,verbose_timeout,"Starting OnlineMultiScanners")
    def __init__(self):
        tokens_full_path = path.abspath(path.join(path.dirname( __file__ ),'tokens.json'))
        file = "analyzer" + tokens_full_path.split("analyzer")[1]
        self.ha = HybridAnalysis(tokens_full_path,file)
        self.ms = MalShare(tokens_full_path,file)
        self.md = MetaDefender(tokens_full_path,file)
        self.vt = VirusTotal(tokens_full_path,file)
        self.av = AlienVault(tokens_full_path,file)
        self.datastruct = {  "HybridAnalysis":"",
                             "MalShare":"",
                             "MetaDefender":"",
                             "VirusTotal":"",
                             "AlienVault":"",
                             "_____HybridAnalysis":{},
                             "_____MalShare":{},
                             "_____MetaDefender":{},
                             "_____VirusTotal":{},
                             "_____AlienVault":{}}

    @verbose(True,verbose_flag,verbose_timeout,"Checking hash in online multiscanners services")
    def analyze(self,data,parsed):
        data["ONLINEMULTISCANNERS"] = deepcopy(self.datastruct)
        data["ONLINEMULTISCANNERS"]["HybridAnalysis"] = self.ha.get_hash_details(data["Details"]["Properties"]["md5"])
        data["ONLINEMULTISCANNERS"]["MalShare"] = self.ms.get_hash_details(data["Details"]["Properties"]["md5"])
        data["ONLINEMULTISCANNERS"]["MetaDefender"] = self.md.get_hash_details(data["Details"]["Properties"]["md5"])
        data["ONLINEMULTISCANNERS"]["VirusTotal"] = self.vt.get_hash_details(data["Details"]["Properties"]["md5"])
        data["ONLINEMULTISCANNERS"]["AlienVault"] = self.av.get_hash_details(data["Details"]["Properties"]["md5"])