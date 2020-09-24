'''
    __G__ = "(G)bd249ce4"
    connection ->  similarity images
'''

from re import I, findall
from re import compile as rcompile
from copy import deepcopy
from analyzer.logger.logger import verbose

class QBSecrets:
    '''
    QBSecrets for common API keys/secrets
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBSecrets")
    def __init__(self):
        '''
        Initialize QBSecrets, this has to pass
        '''
        self.datastruct = {"AWSCLIENTID":[],
                           "AMAZONMWSAUTHTOKEN":[],
                           "AMAZONAWS":[],
                           "AMAZONGENERIC":[],
                           "ALIYUNOSS":[],
                           "AZURESTORAGE":[],
                           "FACEBOOKACCESSTOKEN":[],
                           "GITHUBTOKEN":[],
                           "GOOGLEAPIKEY":[],
                           "GOOGLECAPTCHA":[],
                           "GOOGLEOAUTH":[],
                           "GOOGLESECRET":[],
                           "GOOGLEOAUTHACCESSTOKEN":[],
                           "MAILGUNAPIKEY":[],
                           "MAILCHAMPAPI":[],
                           "PICATICAPI":[],
                           "SLACKTOKEN":[],
                           "SQUAREACCESSTOKEN":[],
                           "SQUAREOAUTHSECRET":[],
                           "STRIPESAPI":[],
                           "TWILIOAPIKEY":[],
                           "TWILIOSID":[],
                           "_AWSCLIENTID":["Count", "AWSCLIENTID"],
                           "_AMAZONMWSAUTHTOKEN":["Count", "AMAZONMWSAUTHTOKEN"],
                           "_AMAZONAWS":["Count", "AMAZONAWS"],
                           "_AMAZONGENERIC":["Count", "AMAZONGENERIC"],
                           "_ALIYUNOSS":["Count", "ALIYUNOSS"],
                           "_AZURESTORAGE":["Count", "AZURESTORAGE"],
                           "_FACEBOOKACCESSTOKEN":["Count", "FACEBOOKACCESSTOKEN"],
                           "_GITHUBTOKEN":["Count", "GITHUBTOKEN"],
                           "_GOOGLEAPIKEY":["Count", "GOOGLEAPIKEY"],
                           "_GOOGLECAPTCHA":["Count", "GOOGLECAPTCHA"],
                           "_GOOGLEOAUTH":["Count", "GOOGLEOAUTH"],
                           "_GOOGLESECRET":["Count", "GOOGLESECRET"],
                           "_GOOGLEOAUTHACCESSTOKEN":["Count", "GOOGLEOAUTHACCESSTOKEN"],
                           "_MAILGUNAPIKEY":["Count", "MAILGUNAPIKEY"],
                           "_MAILCHAMPAPI":["Count", "MAILCHAMPAPI"],
                           "_PICATICAPI":["Count", "PICATICAPI"],
                           "_SLACKTOKEN":["Count", "SLACKTOKEN"],
                           "_SQUAREACCESSTOKEN":["Count", "SQUAREACCESSTOKEN"],
                           "_SQUAREOAUTHSECRET":["Count", "SQUAREOAUTHSECRET"],
                           "_STRIPESAPI":["Count", "STRIPESAPI"],
                           "_TWILIOAPIKEY":["Count", "TWILIOAPIKEY"],
                           "_TWILIOSID":["Count", "TWILIOSID"]}

        self.detectionawsclientid = rcompile(r'\b((A3T[A-Z0-9]|ABIA|ACCA|AGPA|AIDA|AIPA|AKIA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16})\b', I)
        self.detectionamazonmwsauthtoken = rcompile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', I)
        self.detectionamazonaws = rcompile(r's3\.amazonaws\.com', I)
        self.detectionamazongeneric = rcompile(r'aws_access_key_id|aws_secret_access_key.*\b', I)
        self.detectionaliyunoss = rcompile(r'\.oss.aliyuncs.com', I)
        self.detectionazurestorage = rcompile(r'\.file.core.windows.net', I)
        self.detectionfacebookaccesstoken = rcompile(r'EAACEdEose0cBA[0-9a-zA-Z]+', I)
        self.detectiongithubtoken = rcompile(r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github.com*', I)
        self.detectiongoogleapikey = rcompile(r'\bAIza[0-9a-zA-Z\-_]{35}\b', I)
        self.detectiongooglecaptcha = rcompile(r'\b6L[0-9A-Za-z-_]{38}|6[0-9a-zA-Z_-]{39}\b', I)
        self.detectiongoogleoauth = rcompile(r'-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', I)
        self.detectiongooglesecret = rcompile(r'client_secret\"\:', I)
        self.detectiongoogleoauthaccesstoken = rcompile(r'ya29\.[0-9A-Za-z\-_]+', I)
        self.detectionmailgunapikey = rcompile(r'\bkey-[0-9a-zA-Z]{32}\b', I)
        self.detectionmailchampapi = rcompile(r'[0-9a-f]{32}-us[0-9]{1,2}', I)
        self.detectionpicaticapi = rcompile(r'sk_live_[0-9a-z]{32}', I)
        self.detectionslacktoken = rcompile(r'\b(xox[abrps]-([0-9a-zA-Z]{10,48})?)\b', I)
        self.detectionsquareaccesstoken = rcompile(r'sq0atp-[0-9a-zA-Z\-_]{22}', I)
        self.detectionsquareoauthsecret = rcompile(r'sq0csp-[0-9a-zA-Z\-_]{43}', I)
        self.detectionstripesapi = rcompile(r'[s|r]k_live_[0-9a-zA-Z]{24}', I)
        self.detectiontwilioapikey = rcompile(r'\bSK[0-9a-fA-F]{32}\b', I)
        self.detectiontwiliosid = rcompile(r'\bA[P|C][a-zA-Z0-9_-]{32}\b', I)
        self.words = []
        self.wordsstripped = ""

    @verbose(True, verbose_output=False, timeout=None, _str="Finding AWS Clint ID patterns")
    def awsclientid(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionawsclientid, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_[0])
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "AWSCLIENTID":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Amazon MWS Auth Token patterns")
    def amazonmwsauthtoken(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionamazonmwsauthtoken, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "AMAZONMWSAUTHTOKEN":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Amazon S3 patterns")
    def amazonaws(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionamazonaws, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "AMAZONAWS":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Amazon Generic patterns")
    def amazongeneric(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionamazongeneric, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "AMAZONGENERIC":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding ALIYUN OSS patterns")
    def aliyunoss(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionaliyunoss, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "ALIYUNOSS":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding AZURE Storage patterns")
    def azurestorage(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionazurestorage, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "AZURESTORAGE":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Facebook Access Token patterns")
    def facebookaccesstoken(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionfacebookaccesstoken, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "FACEBOOKACCESSTOKEN":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Github Token patterns")
    def githubtoken(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectiongithubtoken, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "GITHUBTOKEN":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Goole API Key patterns")
    def googleapikey(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectiongoogleapikey, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "GOOGLEAPIKEY":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Google CAPTCHA patterns")
    def googlecaptcha(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectiongooglecaptcha, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "GOOGLECAPTCHA":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Google OAuth patterns")
    def googleoauth(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectiongoogleoauth, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "GOOGLEOAUTH":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Google Secret patterns")
    def googlesecret(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectiongooglesecret, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "GOOGLESECRET":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Google OAuth Access Token patterns")
    def googleoauthaccesstoken(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectiongoogleoauthaccesstoken, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "GOOGLEOAUTHACCESSTOKEN":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Mailgun API Key patterns")
    def mailgunapikey(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionmailgunapikey, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "MAILGUNAPIKEY":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding MailChimp API patterns")
    def mailchampapi(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionmailchampapi, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "MAILCHAMPAPI":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Picatic API patterns")
    def picaticapi(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionpicaticapi, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "PICATICAPI":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Slack Token patterns")
    def slacktoken(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionslacktoken, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_[0])
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "SLACKTOKEN":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Square Access Token patterns")
    def squareaccesstoken(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionsquareaccesstoken, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "SQUAREACCESSTOKEN":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Square OAuth Secret patterns")
    def squareoauthsecret(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionsquareoauthsecret, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "SQUAREOAUTHSECRET":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Stripe API patterns")
    def stripesapi(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectionstripesapi, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "STRIPESAPI":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Twilio API patterns")
    def twilioapikey(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectiontwilioapikey, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "TWILIOAPIKEY":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Twilio SID patterns")
    def twiliosid(self, data):
        '''
        need example for testing
        '''
        temp_list = []
        temp_var = findall(self.detectiontwiliosid, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data.append({"Count":temp_list.count(temp_var), "TWILIOSID":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def analyze(self, data):
        '''
        start pattern analysis for words and wordsstripped
        '''
        data["SECRETS"] = deepcopy(self.datastruct)
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.awsclientid(data["SECRETS"]["AWSCLIENTID"])
        self.amazonmwsauthtoken(data["SECRETS"]["AMAZONMWSAUTHTOKEN"])
        self.amazonaws(data["SECRETS"]["AMAZONAWS"])
        self.amazongeneric(data["SECRETS"]["AMAZONGENERIC"])
        self.aliyunoss(data["SECRETS"]["ALIYUNOSS"])
        self.azurestorage(data["SECRETS"]["AZURESTORAGE"])
        self.facebookaccesstoken(data["SECRETS"]["FACEBOOKACCESSTOKEN"])
        self.githubtoken(data["SECRETS"]["GITHUBTOKEN"])
        self.googleapikey(data["SECRETS"]["GOOGLEAPIKEY"])
        #self.googlecaptcha(data["SECRETS"]["GOOGLECAPTCHA"])
        self.googleoauth(data["SECRETS"]["GOOGLEOAUTH"])
        self.googlesecret(data["SECRETS"]["GOOGLESECRET"])
        self.googleoauthaccesstoken(data["SECRETS"]["GOOGLEOAUTHACCESSTOKEN"])
        self.mailgunapikey(data["SECRETS"]["MAILGUNAPIKEY"])
        self.mailchampapi(data["SECRETS"]["MAILCHAMPAPI"])
        self.picaticapi(data["SECRETS"]["PICATICAPI"])
        self.slacktoken(data["SECRETS"]["SLACKTOKEN"])
        self.squareaccesstoken(data["SECRETS"]["SQUAREACCESSTOKEN"])
        self.squareoauthsecret(data["SECRETS"]["SQUAREOAUTHSECRET"])
        self.stripesapi(data["SECRETS"]["STRIPESAPI"])
        self.twilioapikey(data["SECRETS"]["TWILIOAPIKEY"])
        self.twiliosid(data["SECRETS"]["TWILIOSID"])
