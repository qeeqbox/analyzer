from shutil import copyfileobj
from requests import get
from requests.packages.urllib3 import disable_warnings
from ...logger.logger import verbose, verbose_flag, verbose_timeout
from json import load,dumps

class MalShare:
    @verbose(True,verbose_flag,verbose_timeout,"Starting MalShare module")
    def __init__(self,tokens_path):
        with open(tokens_path,"r") as f:
            tokens = load(f)
            self.api = tokens["malshare_key"]
            self.link = "https://malshare.com/api.php?api_key={}".format(self.api)
            disable_warnings()

    def download_file(self,url,hash) -> bool:
        with get(url, stream=True,verify=False) as r:
            with open(hash, 'wb') as f:
                copyfileobj(r.raw, f)
            return True

    @verbose(True,verbose_flag,5,"Getting hash details from MalShare")
    def get_hash_details(self,hash) -> str:
        return dumps(get("{}&action=details&hash={}".format(self.link,hash),verify=False).json(),indent=4)

    @verbose(True,verbose_flag,5,"Getting hash details from MalShare")
    def get_file(self,hash) -> bool:
        return self.download_file("{}&action=getfile&hash={}".format(self.link,hash),hash)

#print(malshare().get_hash_details("63c29e8b364b208c806e8687c57c82f4ca10c359"))