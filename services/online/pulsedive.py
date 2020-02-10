__G__ = "(G)bd249ce4"

from requests import get
from ...logger.logger import verbose, verbose_flag, verbose_timeout
from json import load,dumps

class PulseDive:
    @verbose(True,verbose_flag,verbose_timeout,"Starting AlienVault module")
    def __init__(self,tokens_path,file):
        self.file = file
        with open(tokens_path,"r") as f:
            tokens = load(f)
            self.api = tokens["pulsedive_key"]
            self.link = "https://pulsedive.com/api"

    @verbose(True,verbose_flag,verbose_timeout,"Getting hash details from AlienVault")
    def get_hash_details(self,hash) -> dict:
        if self.api != "":
            return dumps(get("{}/info.php".format(self.link,hash),{'indicator':hash,"key":self.api}).json(),indent=4)
        else:
            return "#Please add your PulseDive api key in {} #To get an api key visit {}".format(self.file,"https://pulsedive.com/api")