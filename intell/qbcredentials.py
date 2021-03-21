'''
    __G__ = "(G)bd249ce4"
    connection -> creds
'''

from re import I, findall
from re import compile as rcompile
from copy import deepcopy
from analyzer.logger.logger import verbose


class QBCredentials:
    '''
    QBCredentials extracts some PII
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBCredentials")
    def __init__(self):
        '''
        Initialize QBCredentials, this has to pass
        '''
        self.datastruct = {"SNNs": [],
                           "SPs": [],
                           "Users": [],
                           "Logins": [],
                           "_SNNs": ["Count", "SSN"],
                           "_SPs": ["Count", "PASS"],
                           "_Users": ["Count", "USER"],
                           "_Logins": ["Count", "UserPass"]}

        self.ssn = rcompile(r"(\d{3}-\d{2}-\d{4})", I)
        self.strongpasswords = rcompile(r"((?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[ \!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\]\^\_\`\{\|\}\~])[A-Za-z\d \!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\]\^\_\`\{\|\}\~]{10,24})")
        self.username = rcompile(r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,24}")
        self.logins = rcompile(r"((user|pass|login|sign)(.*)[^A-Za-z\d \!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\]\^\_\`\{\|\}\~])")
        self.words = []
        self.wordsstripped = ""

    @verbose(True, verbose_output=False, timeout=None, _str="Finding SSN patterns")
    def check_ssn(self, _data):
        '''
        check if buffer contains ssn 123-45-6789
        '''
        temp_list = []
        temp_var = findall(self.ssn, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            _data.append({"Count": temp_list.count(temp_var), "SSN": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding strong passwords patterns")
    def check_strong_password(self, _data):
        '''
        check if buffer contains strong passwords
        '''
        temp_list = []
        temp_var = findall(self.strongpasswords, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_[0])
        for temp_var in set(temp_list):
            _data.append({"Count": temp_list.count(temp_var), "StrongPassword": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding strong usernames")
    def check_usernames(self, _data):
        '''
        check if buffer contains usernames
        '''
        temp_list = []
        temp_var = findall(self.username, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            _data.append({"Count": temp_list.count(temp_var), "USER": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding logins")
    def check_logins(self, _data):
        '''
        check if buffer contains login
        '''
        temp_list = []
        temp_var = findall(self.logins, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_[0])
        for temp_var in set(temp_list):
            _data.append({"Count": temp_list.count(temp_var), "UserPass": temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def analyze(self, data):
        '''
        start pattern analysis for words and wordsstripped
        '''
        data["Creds"] = deepcopy(self.datastruct)
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.check_ssn(data["Creds"]["SNNs"])
        # self.checkstrongpassword(data["Creds"]["SPs"])
        # self.checkusernames(data["Creds"]["Users"])
        self.check_logins(data["Creds"]["Logins"])
