'''
    __G__ = "(G)bd249ce4"
    connection -> encryption
'''

from re import I, findall
from re import compile as rcompile
from base64 import b64decode, b64encode
from copy import deepcopy
from analyzer.logger.logger import ignore_excpetion, verbose

class QBEncryption:
    '''
    QBEncryption finds common encryption patterns (could be slow)
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBEncryption")
    def __init__(self):
        '''
        Initialize QBEncryption, this has to pass
        '''
        self.datastruct = {"MD5s":[],
                           "SHA1s":[],
                           "SHA256s":[],
                           "SHA512s":[],
                           "UUIDs":[],
                           "CRCs":[],
                           "JWTs":[],
                           "BASE64s":[],
                           "Logics":[],
                           "_MD5s":["Count", "MD5", "Description"],
                           "_SHA1s":["Count", "SHA1", "Description"],
                           "_SHA256s":["Count", "SHA256", "Description"],
                           "_SHA512s":["Count", "SHA512", "Description"],
                           "_UUIDs":["Count", "Description", "UUID"],
                           "_CRCs":["Count", "CRC", "Description"],
                           "_JWTs":["Count", "JWT", "Description"],
                           "_BASE64s":["Count", "Base64", "Decoded"],
                           "_Logics":["Count", "Logic"]}

        self.detectioncheckmd5 = rcompile(r'\b[0-9a-fA-F]{32}\b', I)
        self.detectionchecksha1 = rcompile(r'\b[0-9a-fA-F]{40}\b', I)
        self.detectionchecksha256 = rcompile(r'\b[0-9a-fA-F]{64}\b', I)
        self.detectionchecksha512 = rcompile(r'\b[0-9a-fA-F]{128}\b', I)
        self.detectionscheckuuid = [("UUID type 1", rcompile(r'\b[0-9A-F]{8}-[0-9A-F]{4}-[1][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\b', I)),
                                    ("UUID type 2", rcompile(r'\b[0-9A-F]{8}-[0-9A-F]{4}-[2][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\b', I)),
                                    ("UUID type 3", rcompile(r'\b[0-9A-F]{8}-[0-9A-F]{4}-[3][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\b', I)),
                                    ("UUID type 4", rcompile(r'\b[0-9A-F]{8}-[0-9A-F]{4}-[4][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\b', I)),
                                    ("UUID type 5", rcompile(r'\b[0-9A-F]{8}-[0-9A-F]{4}-[5][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\b', I))]
        self.detectioncheckcrc = rcompile(r'\b0x[0-9a-fA-F]{1,16}\b', I)
        self.detectioncheckjwt = rcompile(r'\b[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?\b', I)
        self.wordsinsensitive = []
        self.wordssensitive = []
        self.wordsstripped = ""
        self.buffer = ""

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_base64(self, data):
        '''
        check if words are possible base64 or not
        '''
        temp_list = []
        if len(self.wordssensitive) > 0:
            for _word in self.wordssensitive:
                word = _word.encode()
                if  word.endswith(b"="): #needs to include all options
                    temp_var = self.test_base64(word)
                    if temp_var != "":
                        temp_list.append(word)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "Base64":temp_var.decode('utf-8', errors="ignore"), "Decoded":b64decode(temp_var).decode('utf-8', errors="ignore")})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def test_base64(self, _str) -> str:
        '''
        match decoding base64 then encoding means most likely base64
        '''
        with ignore_excpetion(Exception):
            temp_str = b64decode(_str)
            if b64encode(temp_str) == _str:
                return temp_str
        return ""


    @verbose(True, verbose_output=False, timeout=None, _str="Finding MD5 patterns")
    def check_md5(self, data):
        '''
        check if buffer contains MD5 098F6BCD4621D373CADE4E832627B4F6
        '''
        temp_list = []
        temp_var = findall(self.detectioncheckmd5, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "MD5":temp_var})


    @verbose(True, verbose_output=False, timeout=None, _str="Finding SHA1 patterns")
    def check_sha1(self, data):
        '''
        check if buffer contains SHA1 A94A8FE5CCB19BA61C4C0873D391E987982FBBD3
        '''
        temp_list = []
        temp_var = findall(self.detectionchecksha1, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "SHA1":temp_var})


    @verbose(True, verbose_output=False, timeout=None, _str="Finding SHA256 patterns")
    def check_sha256(self, data):
        '''
        check if buffer contains SHA256 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
        '''
        temp_list = []
        temp_var = findall(self.detectionchecksha256, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "SHA256":temp_var})



    @verbose(True, verbose_output=False, timeout=None, _str="Finding SHA512 patterns")
    def check_sha512(self, data):
        '''
        check if buffer contains SHA512 EE26B0DD4AF7E749AA1A8EE3C10AE9923F618980772E473F8819A5D4940E0DB27AC185F8A0E1D5F84F88BC887FD67B143732C304CC5FA9AD8E6F57F50028A8FF
        '''
        temp_list = []
        temp_var = findall(self.detectionchecksha512, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "SHA512":temp_var})


    @verbose(True, verbose_output=False, timeout=None, _str="Finding UUID patterns")
    def check_uuid(self, data):
        '''
        check if buffer contains UUID 1, 2, 3, 4, 5 and undefined ones
        5c10f566-2963-1311-bde5-f367e8bc6e17
        5c10f566-2963-2311-bde5-f367e8bc6e17
        5c10f566-2963-3311-bde5-f367e8bc6e17
        5c10f566-2963-4311-bde5-f367e8bc6e17
        5c10f566-2963-5311-bde5-f367e8bc6e17
        '''

        for detection in self.detectionscheckuuid:
            temp_list = []
            temp_var = findall(detection[1], self.wordsstripped)
            if len(temp_var) > 0:
                for _ in temp_var:
                    temp_list.append(_)
            for temp_var in set(temp_list):
                data.append({"Count":temp_list.count(temp_var), "Description":detection[0], "UUID":temp_var})


    @verbose(True, verbose_output=False, timeout=None, _str="Finding CRC patterns")
    def check_crc(self, data):
        '''
        check if buffer contains CRC a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
        '''
        temp_list = []
        temp_var = findall(self.detectioncheckcrc, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "CRC":temp_var})


    @verbose(True, verbose_output=False, timeout=None, _str="Finding JWT patterns")
    def check_jwt(self, data):
        '''
        check if buffer contains JWT
        '''
        temp_list = []
        temp_var = findall(self.detectioncheckjwt, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "JWT":temp_var})


    @verbose(True, verbose_output=False, timeout=None, _str="Finding encryptions")
    def get_logics(self, data):
        '''
        check if buffer contains encryption logic
        '''
        temp_list = []
        detections = {"MD2":rb"\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10",
                      "MD5":rb"\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
                      "SHA1" :rb"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
                      "SHA256":rb"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
                      "SHA512":rb"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
                      "RC4":rb"\x96\x30\x07\x77\x2C\x61\x0E\xEE",
                      "AEC":rb"\x63\x7C\x77\x7B\xF2\x6B\x6F\xC5|\x52\x09\x6A\xD5\x30\x36\xA5\x38"}
        for logic in detections:
            temp_var = findall(detections[logic], self.buffer)
            if len(temp_var) > 0:
                for _ in temp_var:
                    temp_list.append(_)
            for temp_var in set(temp_list):
                data.append({"Count":temp_list.count(temp_var), "Logic":logic})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def analyze(self, data):
        '''
        start pattern analysis for words and wordsstripped
        '''
        data["Encryption"] = deepcopy(self.datastruct)
        self.wordsinsensitive = data["StringsRAW"]["wordsinsensitive"]
        self.wordssensitive = data["StringsRAW"]["wordssensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.buffer = data["FilesDumps"][data["Location"]["File"]]
        self.check_md5(data["Encryption"]["MD5s"])
        self.check_sha1(data["Encryption"]["SHA1s"])
        self.check_sha256(data["Encryption"]["SHA256s"])
        self.check_sha512(data["Encryption"]["SHA512s"])
        self.check_crc(data["Encryption"]["CRCs"])
        #self.checkjwt(data["Encryption"]["JWTs"])
        self.check_base64(data["Encryption"]["BASE64s"])
        self.check_uuid(data["Encryption"]["UUIDs"])
        self.get_logics(data["Encryption"]["Logics"])
