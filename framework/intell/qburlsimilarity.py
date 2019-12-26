__G__ = "(G)bd249ce4"

from ..logger.logger import verbose, verbose_flag, verbose_timeout
from re import compile, findall,I
from tld import get_fld,get_tld
from nltk import edit_distance
from requests import get
from io import BytesIO
from zipfile import ZipFile
from shutil import copyfileobj
from os import path
from itertools import islice
from csv import reader
from copy import deepcopy

class QBURLSimilarity:
    @verbose(True,verbose_flag,verbose_timeout,"Starting QBURLSimilarity")
    def __init__(self):
        self.datastruct = {"URLs":[],
                           "_URLs":["Distance","URL","Similar"]}

        self.refs = path.abspath(path.join(path.dirname( __file__ ),"..", 'refs'))
        if not self.refs.endswith(path.sep): self.refs = self.refs+path.sep
        self.links = compile(r"((?:(http|https|ftp):\/\/)?[a-zA-Z0-9]+(\.[a-zA-Z0-9-]+)+([a-zA-Z0-9_\,\'\/\+&amp;%#\$\?\=~\.\-]*[a-zA-Z0-9_\,\'\/\+&amp;%#\$\?\=~\.\-])?)",I)
        self.top = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
        self.topsliced = None
        self.topdomains = None
        self.setup(self.refs)
        #update_tld_names()

    @verbose(True,verbose_flag,verbose_timeout,None)
    def setup(self,_path):
        '''
        check if top-1m.csv exists or not, if not then download load
        it and unzip it and take the top 10000 only
        '''
        if not path.exists(_path+'top-1m.csv'):
            zip_file = ZipFile(BytesIO(get(self.top).content))
            with zip_file.open('top-1m.csv') as zf, open(_path+'top-1m.csv', 'wb') as f:
                copyfileobj(zf, f)
        with open(_path+'top-1m.csv', 'r') as f:
            self.topsliced = islice(reader(f), 10000)
            self.topdomains = [x[1] for x in self.topsliced]

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_urls(self,data):
        '''
        check if root domain exists in the top 10000 or not
        if yes appened it to list 
        '''
        roots = []
        _x =  list(set(findall(self.links,self.wordsstripped)))
        for _ in _x:
            url = ""
            if not _[0].startswith(("http://","https://","ftp://")):
                url = "http://"+_[0]
            if get_tld(url, fail_silently=True):
                root = None
                try:
                    root = get_fld(url,fix_protocol=True)
                except:
                    pass
                if root:
                    roots.append(root)
        if roots:
            for domain in self.topdomains:
                dist = edit_distance(domain,root)
                if dist <= 2:
                    data.append({"Distance":dist,"URL":root,"Similar":domain})


    @verbose(True,verbose_flag,verbose_timeout,"Analyzing URLs")
    def analyze(self,data):
        '''
        start finding urls in top 10000 list 
        '''
        data["URLs"] = deepcopy(self.datastruct)
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.get_urls(data["URLs"]["URLs"])