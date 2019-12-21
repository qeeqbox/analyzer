__G__ = "(G)bd249ce4"

from ..logger.logger import log_string,verbose,verbose_flag,verbose_timeout
from nltk.corpus import words
from copy import deepcopy

class QBLanguage:
    @verbose(True,verbose_flag,verbose_timeout,"Starting QBLanguage")
    def __init__(self):
        self.datastruct = {  "English":[],
                             "UnKnown":[],
                             "Partly English":[],
                             "_English":["Count","Word"],
                             "_UnKnown":["Count","Word"],
                             "_Partly English":["Count","Word"]}
        self.english_words = set(words.words())

    @verbose(True,verbose_flag,verbose_timeout,"Finding english strings")
    def check_with_english(self,_data):
        '''
        check if words are english words or not
        '''
        _dict = {"UnKnown":[],"English":[],"Partly English":[],"Suspicious":[]}
        if len(self.words) > 0:
            for _word in set(self.words).intersection(self.english_words):
                _data["English"].append({"Count":"Unavailable","Word":_word})
            for _word in (set(self.words) - (self.english_words)):
                _data["UnKnown"].append({"Count":"Unavailable","Word":_word})

    @verbose(True,verbose_flag,verbose_timeout,None)
    def sort_by_len(self,_dict):
        return sorted(_dict, key=lambda l: (len(str(l))))

    @verbose(True,verbose_flag,verbose_timeout,None)
    def analyze(self,data):
        '''
        start pattern analysis for words and wordsstripped
        '''
        data["Language"] = deepcopy(self.datastruct)
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.check_with_english(data["Language"])
