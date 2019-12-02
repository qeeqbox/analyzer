__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.funcs import iptolong
from ..intell.qbdescription import adddescription
from nltk.corpus import words
from nltk.tokenize import word_tokenize
from binascii import unhexlify

class QBLanguage:
    @verbose(True,verbose_flag,"Starting QBLanguage")
    def __init__(self):
        '''
        initialize class and make refs path that contains References.db
        get english words from corpus and open connection with References.db
        '''
        self.english_words = set(words.words())

    @verbose(True,verbose_flag,"Finding english strings")
    def checkwithenglish(self,_data):
        '''
        check if words are english words or not
        '''
        _dict = {"UnKnown":[],"English":[],"Partly English":[],"Suspicious":[]}
        if len(self.words) > 0:
            for _word in set(self.words).intersection(self.english_words):
                _data["English"].append({"Count":"Unavailable","Word":_word})
            for _word in (set(self.words) - (self.english_words)):
                _data["UnKnown"].append({"Count":"Unavailable","Word":_word})

    @verbose(True,verbose_flag,None)
    def sortbylen(self,_dict):
        return sorted(_dict, key=lambda l: (len(str(l))))

    @verbose(True,verbose_flag,None)
    def checkwithstring(self,data):
        '''
        start pattern analysis for words and wordsstripped
        '''
        data["Language"] = {  "English":[],
                             "UnKnown":[],
                             "Partly English":[],
                             "_English":["Count","Word"],
                             "_UnKnown":["Count","Word"],
                             "_Partly English":["Count","Word"]}

        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.checkwithenglish(data["Language"])
