__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from ..mics.funcs import iptolong
from re import I, compile, findall
from base64 import b64decode,b64encode

#each encryption has a function for further customization 

class QBEncryption:
    @progressbar(True,"Starting QBEncryption")
    def __init__(self):
        '''
        initialize class
        '''

    @verbose(verbose_flag)
    def checkbase64(self,_data):
        '''
        check if words are possible base64 or not 

        Args:
            data: data dict
        '''
        _List = []
        if len(self.words) > 0:
            for word in self.words:
                if  word.endswith(b"="):  #needs to include all options
                    b = self.testbase64(word)
                    if b != None and b != False:
                        _List.append(word)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"Base64":x,"Decoded":b64decode(x)})

    @verbose(verbose_flag)
    def testbase64(self,w):
        '''
        match decoding base64 then encoding means most likely base64 

        Args:
            data: data dict
        '''
        try:
            y = b64decode(w)
            if b64encode(y) == w:
                return y
        except:
            return False

    @verbose(verbose_flag)
    @progressbar(True,"Check MD5 hash patterns")
    def checkmd5(self,_data):
        '''
        check if buffer contains MD5 098F6BCD4621D373CADE4E832627B4F6

        Args:
            _data: data dict
        '''
        _List = []
        detection = compile(r'\b[0-9a-fA-F]{32}\b',I)
        x = findall(detection,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"MD5":x})

    @verbose(verbose_flag)
    @progressbar(True,"Check SHA1 hash patterns")
    def checksha1(self,_data):
        '''
        check if buffer contains SHA1 A94A8FE5CCB19BA61C4C0873D391E987982FBBD3

        Args:
            _data: data dict
        '''
        _List = []
        detection = compile(r'\b[0-9a-fA-F]{40}\b',I)
        x = findall(detection,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"SHA1":x})

    @verbose(verbose_flag)
    @progressbar(True,"Check SHA256 hash patterns")
    def checksha256(self,_data):
        '''
        check if buffer contains SHA256 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08

        Args:
            _data: data dict
        '''
        _List = []
        detection = compile(r'\b[0-9a-fA-F]{64}\b',I)
        x = findall(detection,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"SHA256":x})


    @verbose(verbose_flag)
    @progressbar(True,"Check SHA512 hash patterns")
    def checksha512(self,_data):
        '''
        check if buffer contains SHA512 EE26B0DD4AF7E749AA1A8EE3C10AE9923F618980772E473F8819A5D4940E0DB27AC185F8A0E1D5F84F88BC887FD67B143732C304CC5FA9AD8E6F57F50028A8FF

        Args:
            _data: data dict
        '''
        _List = []
        detection = compile(r'\b[0-9a-fA-F]{128}\b',I)
        x = findall(detection,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"SHA512":x})

    @verbose(verbose_flag)
    @progressbar(True,"Check UUID patterns")
    def checkuuid(self,_data):
        '''
        check if buffer contains UUID 1,2,3,4,5 and undefined ones
        5c10f566-2963-1311-bde5-f367e8bc6e17
        5c10f566-2963-2311-bde5-f367e8bc6e17
        5c10f566-2963-3311-bde5-f367e8bc6e17
        5c10f566-2963-4311-bde5-f367e8bc6e17
        5c10f566-2963-5311-bde5-f367e8bc6e17

        Args:
            _data: data dict
        '''

        detections =[("UUID type 1",compile(r'\b[0-9A-F]{8}-[0-9A-F]{4}-[1][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\b',I)),
                    ("UUID type 2",compile(r'\b[0-9A-F]{8}-[0-9A-F]{4}-[2][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\b',I)),
                    ("UUID type 3",compile(r'\b[0-9A-F]{8}-[0-9A-F]{4}-[3][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\b',I)),
                    ("UUID type 4",compile(r'\b[0-9A-F]{8}-[0-9A-F]{4}-[4][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\b',I)),
                    ("UUID type 5",compile(r'\b[0-9A-F]{8}-[0-9A-F]{4}-[5][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\b',I))]
        for detection in detections:
            _List = []
            x = findall(detection[1],self.wordsstripped)
            if len(x) > 0:
                for _ in x:
                    _List.append(_)
            for x in set(_List):
                _data.append({"Count":_List.count(x),"Description":detection[0],"UUID":x})

    @verbose(verbose_flag)
    @progressbar(True,"Check CRC patterns")
    def checkcrc(self,_data):
        '''
        check if buffer contains CRC a94a8fe5ccb19ba61c4c0873d391e987982fbbd3

        Args:
            _data: data dict
        '''
        _List = []
        detection = compile(r'\b0x[0-9a-fA-F]{1,16}\b',I)
        x = findall(detection,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"CRC":x})

    @verbose(verbose_flag)
    @progressbar(True,"Check JWT patterns")
    def checkjwt(self,_data):
        '''
        check if buffer contains JWT a94a8fe5ccb19ba61c4c0873d391e987982fbbd3

        Args:
            _data: data dict
        '''
        _List = []
        detection = compile(r'\b[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?\b',I)
        x = findall(detection,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"JWT":x})

    @verbose(verbose_flag)
    def checkencryption(self,data):
        '''
        start pattern analysis for words and wordsstripped

        Args:
            data: data dict
        '''
        self.words = data["StringsRAW"]["words"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        data["Encryption"] = {  "MD5s":[],
                                "SHA1s":[],
                                "SHA256s":[],
                                "SHA512s":[],
                                "UUIDs":[],
                                "CRCs":[],
                                "JWTs":[],
                                "BASE64s":[],
                                "_MD5s":["Count","MD5","Description"],
                                "_SHA1s":["Count","SHA1","Description"],
                                "_SHA256s":["Count","SHA256","Description"],
                                "_SHA512s":["Count","SHA512","Description"],
                                "_UUIDs":["Count","Description","UUID"],
                                "_CRCs":["Count","CRC","Description"],
                                "_JWTs":["Count","JWT","Description"],
                                "_BASE64s":["Count","Base64","Decoded"]}
        self.checkmd5(data["Encryption"]["MD5s"])
        self.checksha1(data["Encryption"]["SHA1s"])
        self.checksha256(data["Encryption"]["SHA256s"])
        self.checksha512(data["Encryption"]["SHA512s"])
        self.checkcrc(data["Encryption"]["CRCs"])
        self.checkjwt(data["Encryption"]["JWTs"])
        self.checkbase64(data["Encryption"]["BASE64s"])
        self.checkuuid(data["Encryption"]["UUIDs"])


