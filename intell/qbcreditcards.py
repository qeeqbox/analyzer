'''
    __G__ = "(G)bd249ce4"
    connection -> cards
'''

from re import I, findall
from re import compile as rcompile
from copy import deepcopy
from analyzer.logger.logger import verbose


class QBCreditcards:
    '''
    QBCreditcards extracts some PII
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBCreditcards")
    def __init__(self):
        '''
        Initialize QBCreditcards, this has to pass
        '''
        self.datastruct = {"AMERICANEXPRESS": [],
                           "VISA": [],
                           "MASTERCARD": [],
                           "DISCOVER": [],
                           "JCB": [],
                           "DINERSCLUB": [],
                           "_AMERICANEXPRESS": ["Count", "AmericanExpress"],
                           "_VISA": ["Count", "Visa"],
                           "_MASTERCARD": ["Count", "MasterCard"],
                           "_DISCOVER": ["Count", "Discover"],
                           "_JCB": ["Count", "JCB"],
                           "_DINERSCLUB": ["Count", "DinersClub"]}
        self.detectionamericanexpress = rcompile(r'\b(?:3[47][0-9]{13})\b', I)
        self.detectionvisa = rcompile(r'\b(?:4[0-9]{12})(?:[0-9]{3})?\b', I)
        self.detectionmastercard = rcompile(r'\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b', I)
        self.detectiondiscover = rcompile(r'\b(?:6011\d{12})|(?:65\d{14})\b', I)
        self.detectionjcb = rcompile(r'\b(?:2131|1800|35[0-9]{3})[0-9]{11}?\b', I)
        self.detectiondinersclub = rcompile(r'\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b', I)
        self.words = []
        self.wordsstripped = ""

    @verbose(True, verbose_output=False, timeout=None, _str="Finding American Express Card patterns")
    def americanexpress(self, data):
        '''
        check if buffer contains american express card number 371642190784801
        '''
        temp_list = []
        temp_var = findall(self.detectionamericanexpress, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count": temp_list.count(temp_var), "AmericanExpress": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Visa Card patterns")
    def visa(self, data):
        '''
        check if buffer contains Visa card number 4035300539804083
        '''
        temp_list = []
        temp_var = findall(self.detectionvisa, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count": temp_list.count(temp_var), "Visa": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Master Card patterns")
    def mastercard(self, data):
        '''
        check if buffer contains master card number 5168441223630339
        '''
        temp_list = []
        temp_var = findall(self.detectionmastercard, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count": temp_list.count(temp_var), "MasterCard": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Discover Card patterns")
    def discover(self, data):
        '''
        check if buffer contains Visa card number 6011988461284820
        '''
        temp_list = []
        temp_var = findall(self.detectiondiscover, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count": temp_list.count(temp_var), "Discover": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Jcb Card patterns")
    def jcb(self, data):
        '''
        check if buffer contains Jcb card number 3538684728624673
        '''
        temp_list = []
        temp_var = findall(self.detectionjcb, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count": temp_list.count(temp_var), "JCB": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Diners Club Card patterns")
    def dinersclub(self, data):
        '''
        check if buffer contains Diners Club card number 30043277253249
        '''
        temp_list = []
        temp_var = findall(self.detectiondinersclub, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count": temp_list.count(temp_var), "DinersClub": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def analyze(self, data):
        '''
        start pattern analysis for words and wordsstripped
        '''
        data["CARDS"] = deepcopy(self.datastruct)
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.americanexpress(data["CARDS"]["AMERICANEXPRESS"])
        self.visa(data["CARDS"]["VISA"])
        self.mastercard(data["CARDS"]["MASTERCARD"])
        self.discover(data["CARDS"]["DISCOVER"])
        self.jcb(data["CARDS"]["JCB"])
        self.dinersclub(data["CARDS"]["DINERSCLUB"])
