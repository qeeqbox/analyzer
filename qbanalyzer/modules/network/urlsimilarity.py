__version__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from re import compile, findall,I
from tld import get_fld,get_tld
from tld.utils import update_tld_names
from nltk import edit_distance
from requests import get
from io import BytesIO
from zipfile import ZipFile
from shutil import copyfileobj
from os import path,mkdir
from itertools import islice
from csv import reader

#need refactoring

class URLSimilarity:
    @verbose(verbose_flag)
    @progressbar(True,"Starting URLSimilarity")
    def __init__(self):
        '''
        initialize class and get top 1m.csv from umbrella
        '''
        self.topurl = path.abspath(path.join(path.dirname( __file__ ),'topurls'))
        if not self.topurl.endswith(path.sep): self.topurl = self.topurl+path.sep
        if not path.isdir(self.topurl): mkdir(self.topurl)
        self.top = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
        self.topsliced = None
        self.topdomains = None
        self.setup(self.topurl)
        update_tld_names()

    @verbose(verbose_flag)
    def setup(self,_path):
        '''
        check if top-1m.csv exists or not, if not then download load
        it and unzip it and take the top 10000 only

        Args:
            _path to topurls folder
        '''
        if not path.exists(_path+'top-1m.csv'):
            zip_file = ZipFile(BytesIO(get(self.top).content))
            with zip_file.open('top-1m.csv') as zf, open(_path+'top-1m.csv', 'wb') as f:
                copyfileobj(zf, f)
        with open(_path+'top-1m.csv', 'r') as f:
            self.topsliced = islice(reader(f), 10000)
            self.topdomains = [x[1] for x in self.topsliced]

    @verbose(verbose_flag)
    def geturls(self,data):
        '''
        check if root domain exists in the top 10000 or not
        if yes appened it to list 

        Args:
            data: data dict
        '''
        roots = []
        _x =  list(set(findall(compile(r"((http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(:[a-zA-Z0-9]*)?\/?([a-zA-Z0-9_\,\'/\+&amp;%#\$\?\=~\.\-])*)",I),self.wordsstripped)))
        for _ in _x:
            if get_tld(_[0], fail_silently=True):
                root = None
                try:
                    root = get_fld(_[0],fix_protocol=True)
                except:
                    pass
                if root:
                    roots.append(root)
        if roots:
            for domain in self.topdomains:
                dist = edit_distance(domain,root)
                if dist <= 2:
                    data.append({"Distance":dist,"URL":root,"Similar":domain})

    @verbose(verbose_flag)
    @progressbar(True,"Analyze URLs")
    def checkwithurls(self,data):
        '''
        start finding urls in top 10000 list 

        Args:
            data: data dict
        '''
        self.words = data["StringsRAW"]["words"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        data["URLs"] = {"URLs":[],
                          "_URLs":["Distance","URL","Similar"]}
        self.geturls(data["URLs"]["URLs"])