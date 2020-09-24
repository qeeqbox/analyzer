'''
    __G__ = "(G)bd249ce4"
    connection ->  url similarity
'''

from os import path
from io import BytesIO
from re import findall, I
from re import compile as recompile
from itertools import islice
from csv import reader
from copy import deepcopy
from shutil import copyfileobj
from zipfile import ZipFile
from requests import get
from tld import get_fld, get_tld
from nltk import edit_distance
from analyzer.logger.logger import ignore_excpetion, verbose

class QBURLSimilarity:
    '''
    QBURLSimilarity for url similarity
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBURLSimilarity")
    def __init__(self):
        '''
        Initialize QBURLSimilarity, this has to pass
        '''
        self.datastruct = {"URLs":[],
                           "_URLs":["Distance", "URL", "Similar"]}

        self.refs = path.abspath(path.join(path.dirname(__file__), 'refs'))
        if not self.refs.endswith(path.sep):
            self.refs = self.refs+path.sep
        self.links = recompile(r"((?:(http|https|ftp):\/\/)?[a-zA-Z0-9]+(\.[a-zA-Z0-9-]+)+([a-zA-Z0-9_\,\'\/\+&amp;%#\$\?\=~\.\-]*[a-zA-Z0-9_\,\'\/\+&amp;%#\$\?\=~\.\-])?)", I)
        self.top = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
        self.topsliced = None
        self.topdomains = None
        self.setup(self.refs)
        self.words = []
        self.wordsstripped = ""
        #update_tld_names()

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def setup(self, _path):
        '''
        check if top-1m.csv exists or not, if not then download load
        it and unzip it and take the top 10000 only
        '''
        if not path.exists(_path+'top-1m.csv'):
            zip_file = ZipFile(BytesIO(get(self.top).content))
            with zip_file.open('top-1m.csv') as temp_zip_file, open(_path+'top-1m.csv', 'wb') as file:
                copyfileobj(temp_zip_file, file)
        with open(_path+'top-1m.csv', 'r') as file:
            self.topsliced = islice(reader(file), 10000)
            self.topdomains = [x[1] for x in self.topsliced]

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_urls(self, data):
        '''
        check if root domain exists in the top 10000 or not
        if yes appened it to list
        '''
        roots = []
        temp_var = list(set(findall(self.links, self.wordsstripped)))
        for _ in temp_var:
            url = ""
            if not _[0].startswith(("http://", "https://", "ftp://")):
                url = "http://"+_[0]
            if get_tld(url, fail_silently=True):
                root = None
                with ignore_excpetion(Exception):
                    root = get_fld(url, fix_protocol=True)

                if root:
                    roots.append(root)
        if roots:
            for domain in self.topdomains:
                dist = edit_distance(domain, root)
                if dist <= 2:
                    data.append({"Distance":dist, "URL":root, "Similar":domain})


    @verbose(True, verbose_output=False, timeout=None, _str="Analyzing URLs")
    def analyze(self, data):
        '''
        start finding urls in top 10000 list
        '''
        data["URLs"] = deepcopy(self.datastruct)
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.get_urls(data["URLs"]["URLs"])
