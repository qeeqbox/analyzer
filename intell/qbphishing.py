'''
    __G__ = "(G)bd249ce4"
    connection ->  similarity images
'''

from re import findall
from re import compile as rcompile
from copy import deepcopy
from analyzer.logger.logger import verbose
from analyzer.intell.qblanguage import check_spelling

class QBPhishing:
    '''
    QBPhishing for detecting phishing
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBPhishing")
    def __init__(self):
        '''
        Initialize QBPhishing, this has to pass
        '''
        self.datastruct = {"Suspicious":[],
                           "Spelling count":[],
                           "Spelling":[],
                           "Symbols":[],
                           "_Spelling count":["Total", "Misspelled"],
                           "_Spelling":["Count", "Word", "Misspelled"],
                           "_Suspicious":["Count", "Words"],
                           "_Symbols":["Count", "Symbol"]}

        self.suspiciouswords = rcompile(r"uniq|18\+|action|act|additional income|affordable|amazed|apply|avoid|babe|be amazed|beneficiary|billing|billion|bonus|boss|buy|call|cancel|cash|casino|certified|cheap|claim|clearance|click|collect|compare rates|confirm|congrat|congratulations|credit|cures|customer|deal|dear|debt|direct email|discount|don\'t delete|don\'t hesitate|double your income|earn|experience|expire|extra|fantastic|fgift|free|freedom|friend|get it|great|guarantee|hello|income|increase |instant|investment|iphone|junk|limited|lose|log|lowest price|lucky|luxury|make money|medicine|mobile|money|msg|name|no credit check|now|obligation|offer|only|open|order|password|please|presently|problem|promise|purchase|quote|rates|refinance|refund|remove|reply|request|risk-free|sales|satisfaction|save|score|serious|sex|sexy|sign|sms|spam|special|subscription|success|supplies|take action|terms|text|ticket|traffic|trial|txt|unlimited|update|urgent|weight|win|winner|won")
        self.wordsstripped = ""

    @verbose(True, verbose_output=False, timeout=None, _str="Checking suspicious words")
    def check_suspicious_words(self, data):
        '''
        check if target contains suspicious words
        '''
        temp_list = []
        temp_var = findall(self.suspiciouswords, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        if len(temp_list) > 0:
            data.append({"Count":len(temp_list), "Words":", ".join(temp_list)})

    @verbose(True, verbose_output=False, timeout=None, _str="Checking question marks and exclamation marks")
    def chcek_questionmarks_exclamationmarks(self, data):
        '''
        check if target contains ? or !
        '''
        for symbol in ("!", "?"):
            if self.wordsstripped.count(symbol) > 0:
                data.append({"Count":self.wordsstripped.count(symbol), "Symbol":symbol})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding phishing patterns")
    def analyze(self, data, parsed):
        '''
        start pattern analysis for wordsstripped
        '''
        if parsed.type in ("email", "text"):
            data["PHISHING"] = deepcopy(self.datastruct)
            if parsed.type == "email":
                self.wordsstripped = data["EMAIL"]["Parsed"]
            else:
                self.wordsstripped = data["StringsRAW"]["wordsstripped"]
            self.check_suspicious_words(data["PHISHING"]["Suspicious"])
            self.chcek_questionmarks_exclamationmarks(data["PHISHING"]["Symbols"])
            check_spelling(data["PHISHING"], self.wordsstripped)
