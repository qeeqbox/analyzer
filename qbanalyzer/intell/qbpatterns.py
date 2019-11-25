__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from ..mics.funcs import iptolong
from ..intell.qbdescription import adddescription
from re import I, compile, findall
from nltk.corpus import words
from nltk.tokenize import word_tokenize
from binascii import unhexlify
from ipaddress import ip_address

#this module needs some optimization

class QBPatterns:
    @progressbar(True,"Starting QBPatterns")
    def __init__(self):
        '''
        initialize class and make refs path that contains References.db
        get english words from corpus and open connection with References.db
        '''

    @verbose(verbose_flag)
    @progressbar(True,"Finding URLs patterns")
    def checklink(self,_data):
        '''
        check if buffer contains ips xxx://xxxxxxxxxxxxx.xxx
        
        Args:
            _data: data dict
        '''
        _List = []
        x = list(set(findall(compile(r"((http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(:[a-zA-Z0-9]*)?\/?([a-zA-Z0-9_\,\'/\+&amp;%#\$\?\=~\.\-])*)",I),self.wordsstripped)))
        if len(x) > 0:
            for _ in x:
                try:
                    ip_address(_)
                    _List.append(_)
                except ValueError:
                    pass
        for x in set(_List):
            _data.append({"Count":_List.count(x),"Link":x})

    @verbose(verbose_flag)
    @progressbar(True,"Finding IP4s patterns")
    def checkip4(self,_data):
        '''
        check if buffer contains ips x.x.x.x

        Args:
            _data: data dict
        '''
        _List = []
        ip = compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\b',I)
        x = findall(ip,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                try:
                    ip = ip_address(_)
                    _List.append(_)
                except ValueError:
                    pass
        for x in set(_List):
            _data.append({"Count":_List.count(x),"IP":x,"Code":"","Alpha2":"","Description":""})

    @verbose(verbose_flag)
    @progressbar(True,"Finding IP6s patterns")
    def checkip6(self,_data):
        '''
        check if buffer contains ips x.x.x.x

        Args:
            _data: data dict
        '''
        _List = []
        ip = compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',I)
        x = findall(ip,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"IP":x,"Code":"","Alpha2":"","Description":""})

    @verbose(verbose_flag)
    @progressbar(True,"Finding Emails patterns")
    def checkemail(self,_data):
        '''
        check if buffer contains email xxxxxxx@xxxxxxx.xxx

        Args:
            _data: data dict
        '''
        _List = []
        email = compile(r'(\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*)',I)
        x = findall(email,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_[0])
        for x in set(_List):
            _data.append({"Count":_List.count(x),"EMAIL":x})

    @verbose(verbose_flag)
    @progressbar(True,"Finding TELs patterns")
    def checkphonenumber(self,_data):
        '''
        check if buffer contains tel numbers 012 1234 567

        Args:
            _data: data dict
        '''
        _List = []
        tel = compile(r'(\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*)',I)
        x = findall(tel,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"TEL":x})

    @verbose(verbose_flag)
    @progressbar(True,"Finding tags patterns")
    def checktags(self,_data):
        '''
        check if buffer contains tags <>

        Args:
            _data: data dict
        '''
        _List = []
        html = compile(r'>([^<]*)<\/',I)
        x = findall(html,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"TAG":x})

    @verbose(verbose_flag)
    @progressbar(True,"Finding HEX patterns")
    def checkhex(self,_data):
        '''
        check if buffer contains tags <>

        Args:
            _data: data dict
        '''
        _List = []
        _hex = compile(r'([0-9a-fA-F]{4,})',I)
        x = findall(_hex,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            parsed = unhexlify(x)
            _data.append({"Count":_List.count(x),"HEX":x,"Parsed":parsed.decode('utf-8',errors="ignore")})


    @verbose(verbose_flag)
    def checkpatterns(self,data):
        '''
        start pattern analysis for words and wordsstripped

        Args:
            data: data dict
        '''
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        data["Patterns"] = { "IP4S":[],
                             "IP6S":[],
                             "LINKS":[],
                             "EMAILS":[],
                             "TELS":[],
                             "TAGS":[],
                             "HEX":[],
                             "_IP4S":["Count","IP","Code","Alpha2","Description"],
                             "_IP6S":["Count","IP","Code","Alpha2","Description"],
                             "_LINKS":["Count","Link"],
                             "_EMAILS":["Count","EMAIL","Description"],
                             "_TELS":["Count","TEL","Description"],
                             "_TAGS":["Count","TAG","Description"],
                             "_HEX":["Count","HEX","Parsed"]}
        #engsorted = self.sortbylen(self.checkwithenglish()["English"])
        #unksorted = self.sortbylen(self.checkwithenglish()["UnKnown"])
        #b64 = self.checkbase64()
        self.checklink(data["Patterns"]["LINKS"])
        self.checkip4(data["Patterns"]["IP4S"])
        self.checkip6(data["Patterns"]["IP6S"])
        self.checkemail(data["Patterns"]["EMAILS"])
        self.checktags(data["Patterns"]["TAGS"])
        self.checkhex(data["Patterns"]["HEX"])
        #self.checkphonenumber(data["Strings"]["TELS"])
        adddescription("DNS",data["Patterns"]["IP4S"],"IP")
        adddescription("IPs",data["Patterns"]["IP4S"],"IP")
        adddescription("IPPrivate",data["Patterns"]["IP4S"],"IP")
        #self.checkmitre(data["Strings"])
