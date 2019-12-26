__G__ = "(G)bd249ce4"

from ..logger.logger import verbose, verbose_flag, verbose_timeout
from re import I, compile, findall
from copy import deepcopy

class QBCredentials:
    @verbose(True,verbose_flag,verbose_timeout,"Starting QBCredentials")
    def __init__(self):
        self.datastruct = {  "SNNs":[],
                             "SPs":[],
                             "Users":[],
                             "Logins":[],
                             "_SNNs":["Count","SSN"],
                             "_SPs":["Count","PASS"],
                             "_Users":["Count","USER"],
                             "_Logins":["Count","UserPass"]}

        self.ssn = compile(r"(\d{3}-\d{2}-\d{4})",I)
        self.strongpasswords = compile(r"((?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[ \!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\]\^\_\`\{\|\}\~])[A-Za-z\d \!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\]\^\_\`\{\|\}\~]{10,24})")
        self.username = compile(r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,24}")
        self.logins = compile(r"((user|pass|login|sign)(.*)[^A-Za-z\d \!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\]\^\_\`\{\|\}\~])")

    @verbose(True,verbose_flag,verbose_timeout,"Finding SSN patterns")
    def check_ssn(self,_data):
        '''
        check if buffer contains ssn 123-45-6789
        '''
        _List = []
        x = findall(self.ssn,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_[0])
        for x in set(_List):
            _data.append({"Count":_List.count(x),"SSN":x})


    @verbose(True,verbose_flag,verbose_timeout,"Finding strong passwords patterns")
    def check_strong_password(self,_data):
        '''
        check if buffer contains strong passwords
        '''
        _List = []
        x = findall(self.strongpasswords,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_[0])
        for x in set(_List):
            _data.append({"Count":_List.count(x),"StrongPassword":x})

    @verbose(True,verbose_flag,verbose_timeout,"Finding strong usernames")
    def check_usernames(self,_data):
        '''
        check if buffer contains usernames
        '''
        _List = []
        x = findall(self.username,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"USER":x})

    @verbose(True,verbose_flag,verbose_timeout,"Finding logins")
    def check_logins(self,_data):
        '''
        check if buffer contains login
        '''
        _List = []
        x = findall(self.logins,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_[0])
        for x in set(_List):
            _data.append({"Count":_List.count(x),"UserPass":x})

    @verbose(True,verbose_flag,verbose_timeout,None)
    def analyze(self,data):
        '''
        start pattern analysis for words and wordsstripped
        '''
        data["Creds"] = deepcopy(self.datastruct)
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.check_ssn(data["Creds"]["SNNs"])
        #self.checkstrongpassword(data["Creds"]["SPs"])
        #self.checkusernames(data["Creds"]["Users"])
        self.check_logins(data["Creds"]["Logins"])
