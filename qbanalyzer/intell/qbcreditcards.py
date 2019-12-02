__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from re import I, compile, findall

class QBCreditcards:
    @verbose(True,verbose_flag,"Starting QBCreditcards")
    def __init__(self):
        '''
        initialize class
        '''
        self.detectionamericanexpress = compile(r'\b(?:3[47][0-9]{13})\b',I)
        self.detectionvisa = compile(r'\b(?:4[0-9]{12})(?:[0-9]{3})?\b',I)
        self.detectionmastercard = compile(r'\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b',I)
        self.detectiondiscover = compile(r'\b(?:6011\d{12})|(?:65\d{14})\b',I)
        self.detectionjcb = compile(r'\b(?:2131|1800|35[0-9]{3})[0-9]{11}?\b',I)
        self.detectiondinersclub = compile(r'\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b',I)


    @verbose(True,verbose_flag,"Finding American Express Card patterns")
    def americanexpress(self,data):
        '''
        check if buffer contains american express card number 371642190784801
        '''
        _List = []
        x = findall(self.detectionamericanexpress,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            data.append({"Count":_List.count(x),"AmericanExpress":x})


    @verbose(True,verbose_flag,"Finding Visa Card patterns")
    def visa(self,data):
        '''
        check if buffer contains Visa card number 4035300539804083
        '''
        _List = []
        x = findall(self.detectionvisa,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            data.append({"Count":_List.count(x),"Visa":x})



    @verbose(True,verbose_flag,"Finding Master Card patterns")
    def mastercard(self,data):
        '''
        check if buffer contains master card number 5168441223630339
        '''
        _List = []
        x = findall(self.detectionmastercard,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            data.append({"Count":_List.count(x),"MasterCard":x})


    @verbose(True,verbose_flag,"Finding Discover Card patterns")
    def discover(self,data):
        '''
        check if buffer contains Visa card number 6011988461284820
        '''
        _List = []
        x = findall(self.detectiondiscover,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            data.append({"Count":_List.count(x),"Discover":x})


    @verbose(True,verbose_flag,"Finding Jcb Card patterns")
    def jcb(self,data):
        '''
        check if buffer contains Jcb card number 3538684728624673
        '''
        _List = []
        x = findall(self.detectionjcb,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            data.append({"Count":_List.count(x),"JCB":x})


    @verbose(True,verbose_flag,"Finding Diners Club Card patterns")
    def dinersclub(self,data):
        '''
        check if buffer contains Diners Club card number 30043277253249
        '''
        _List = []
        x = findall(self.detectiondinersclub,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            data.append({"Count":_List.count(x),"DinersClub":x})

    @verbose(True,verbose_flag,None)
    def checkcreditcards(self,data):
        '''
        start pattern analysis for words and wordsstripped
        '''
        data["CARDS"] = {   "AMERICANEXPRESS":[],
                            "VISA":[],
                            "MASTERCARD":[],
                            "DISCOVER":[],
                            "JCB":[],
                            "DINERSCLUB":[],
                            "_AMERICANEXPRESS":["Count","AmericanExpress"],
                            "_VISA":["Count","Visa"],
                            "_MASTERCARD":["Count","MasterCard"],
                            "_DISCOVER":["Count","Discover"],
                            "_JCB":["Count","JCB"],
                            "_DINERSCLUB":["Count","DinersClub"]}

        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.americanexpress(data["CARDS"]["AMERICANEXPRESS"])
        self.visa(data["CARDS"]["VISA"])
        self.mastercard(data["CARDS"]["MASTERCARD"])
        self.discover(data["CARDS"]["DISCOVER"])
        self.jcb(data["CARDS"]["JCB"])
        self.dinersclub(data["CARDS"]["DINERSCLUB"])





