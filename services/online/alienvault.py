__G__ = "(G)bd249ce4"

from requests import get
from ...logger.logger import verbose, verbose_flag, verbose_timeout
from json import load,dumps

class AlienVault:
    @verbose(True,verbose_flag,verbose_timeout,"Starting AlienVault module")
    def __init__(self,tokens_path,file):
        self.file = file
        with open(tokens_path,"r") as f:
            tokens = load(f)
            self.api = tokens["alienvault_key"]
            self.link = "https://otx.alienvault.com/api/v1"
            #self.headers = {'X-OTX-API-KEY': self.api,'Content-Type': 'application/json'}

    @verbose(True,verbose_flag,verbose_timeout,"Getting hash details from AlienVault")
    def get_hash_details(self,hash) -> dict:
        return dumps(get("{}/indicators/file/{}/analysis".format(self.link,hash)).json(),indent=4)
        #if self.api != "":
        #    return dumps(get("{}/indicators/file/{}/analysis".format(self.link,hash)).json(),indent=4)
        #else:
        #    return "#Please add your AlienVault api key in {} #To get an api key visit {}".format(self.file,"https://otx.alienvault.com/assets/static/external_api.html#api_v1_indicators")