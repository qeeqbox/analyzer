__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from ..mics.funcs import iptolong
from ..intell.qbdescription import adddescription
from re import sub
from nltk.corpus import words
from nltk.tokenize import word_tokenize
from binascii import unhexlify

#this module needs some optimization

class QBStrings:
    @progressbar(True,"Starting QBStrings")
    def __init__(self):
        '''
        initialize class and make refs path that contains References.db
        get english words from corpus and open connection with References.db
        '''

        self.english_words = set(words.words())
        self.dic_dict = None #set([line.lower().strip() for line in open(_path+"dic_four.text", 'r')])
        self.sus = ["crypt","==","ransom","+tcp","pool.","bitcoin","encrypt","decrypt","mail","ftp","http","https","btc","address","sudo","password","pass","admin","payment"]
        self.way = 5
        self.mitreusedict = None

    @verbose(verbose_flag)
    @progressbar(True,"Finding english strings")
    def checkwithenglish(self,_data):
        '''
        check if words are english words or not

        Args:
            _data: data dict
        '''
        _dict = {"UnKnown":[],"English":[],"Partly English":[],"Suspicious":[]}
        if len(self.words) > 0:
            for _word in self.words:
                temp = "UnKnown"
                if _word in self.english_words:
                    temp = "English"
                else:
                    if self.way == 1:
                        if len(_word) > 3:
                            str = sub('[^0-9a-zA-Z]',' ', _word)
                            if bool(set(str.split(" ")) & self.dic_dict):
                                temp = "Partly English"
                    elif self.way ==2:
                        #AI module removed
                        pass

                for _ in self.sus:
                    if _ in _word.lower():
                        _word = _word.lower()
                        temp = "Suspicious"

                _dict[temp].append(_word)

        for key in _dict.keys():
            for x in set(_dict[key]):
                _data[key].append({"Count":_dict[key].count(x),"Word":x})


    @verbose(verbose_flag)
    def sortbylen(self,_dict):
        return sorted(_dict, key=lambda l: (len(str(l))))

    @verbose(verbose_flag)
    def checkwithstring(self,data):
        '''
        start pattern analysis for words and wordsstripped

        Args:
            data: data dict
        '''
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        data["Strings"] = {  "English":[],
                             "UnKnown":[],
                             "Partly English":[],
                             "Suspicious":[],
                             "_English":["Count","Word"],
                             "_UnKnown":["Count","Word"],
                             "_Suspicious":["Count","Word"],
                             "_Partly English":["Count","Word"]}
        #engsorted = self.sortbylen(self.checkwithenglish()["English"])
        #unksorted = self.sortbylen(self.checkwithenglish()["UnKnown"])
        #b64 = self.checkbase64()
        self.checkwithenglish(data["Strings"])
