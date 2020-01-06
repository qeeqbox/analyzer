from requests import get
from requests.auth import HTTPBasicAuth
from ...logger.logger import verbose, verbose_flag, verbose_timeout
from json import load,dumps

class HybridAnalysis:
    @verbose(True,verbose_flag,verbose_timeout,"Starting HybridAnalysis module")
    def __init__(self,tokens_path):
        with open(tokens_path,"r") as f:
            tokens = load(f)
            self.api = tokens["hybridanalysis_key"]
            self.secret = tokens["hybridanalysis_secert"]
            self.auth = HTTPBasicAuth(self.api, self.secret)
            self.link = "https://www.hybrid-analysis.com/api"
            self.headers = {"User-Agent":"Falcon Sandbox",}

    @verbose(True,verbose_flag,5,"Getting hash details from HybridAnalysis")
    def get_hash_details(self,hash) -> dict:
        return dumps(get("{}/scan/{}".format(self.link,hash),headers=self.headers, auth=self.auth).json(),indent=4)

#print(hybridanalysis().get_hash_details("b300a83ad84f844f68d6ca4ca4c4f3823ac0239ea227e33147737db5e4cab782"))
