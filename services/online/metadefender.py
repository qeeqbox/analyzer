__G__ = "(G)bd249ce4"

from requests import get
from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout
from json import load,dumps

class MetaDefender:
    @verbose(True,verbose_flag,verbose_timeout,"Starting MetaDefender module")
    def __init__(self,tokens_path,file):
        self.file = file
        with open(tokens_path,"r") as f:
            tokens = load(f)
            self.api = tokens["metadefender_key"]
            self.link = "https://api.metadefender.com/v2"
            self.headers = {"User-Agent":"Falcon Sandbox","apikey":self.api}

    @verbose(True,verbose_flag,verbose_timeout,"Getting hash details from MetaDefender")
    def get_hash_details(self,hash) -> dict:
        if self.api != "":
            return dumps(get("{}/hash/{}".format(self.link,hash),headers=self.headers).json(),indent=4)
        else:
            return "#Please add your MetaDefender api key in {} #To get an api key visit {}".format(self.file,"https://onlinehelp.opswat.com/vault/Generate_an_API_key_from_Metadefender_Core.html")

#print(metadefender().get_hash_details("b300a83ad84f844f68d6ca4ca4c4f3823ac0239ea227e33147737db5e4cab782"))
