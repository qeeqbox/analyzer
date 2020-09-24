'''
    __G__ = "(G)bd249ce4"
    connection ->  suspicious strings
'''

from re import I, findall
from re import compile as recompile
from copy import deepcopy
from analyzer.logger.logger import verbose

class QBSuspicious:
    '''
    QBSuspicious for extracting suspicious words
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBSuspicious")
    def __init__(self):
        '''
        Initialize QBSuspicious, this has to pass
        '''
        self.datastruct = {"Strings":[],
                           "_Strings":["Count", "Detected"]}

        self.suspicious = ["crypt", "==", "ransom", "+tcp", "pool.", "bitcoin", "encrypt", "decrypt", "mail", "ftp", "http", "https", "btc", "address", "sudo", "password", "pass", "admin", "payment"]
        self.words = []
        self.wordsstripped = ""

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def find_suspicious_regex(self, data):
        '''
        Not used
        '''
        for sus in self.suspicious:
            temp_list = []
            temp_var = findall(recompile(r'(([^\n]+)?({})([^\n]+)?)'.format(sus), I), self.wordsstripped)
            if len(temp_var) > 0:
                for _ in temp_var:
                    temp_list.append(_[0])
            for temp_var in set(temp_list):
                data.append({"Count":temp_list.count(temp_var), "Detected":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def find_suspicious(self, data):
        '''
        I think this was faster than regex
        '''
        for sus in self.suspicious:
            temp_list = []
            for _ in self.words:
                if sus in _:
                    temp_list.append(_)
            for temp_var in set(temp_list):
                data.append({"Count":temp_list.count(temp_var), "Detected":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding suspicious strings")
    def analyze(self, data):
        '''
        start pattern analysis for words and wordsstripped
        '''
        data["Suspicious"] = deepcopy(self.datastruct)
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.find_suspicious(data["Suspicious"]["Strings"])
