__G__ = "(G)bd249ce4"

from re import I, compile, findall
from copy import deepcopy
from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout

class QBSecrets:
	@verbose(True, verbose_flag, verbose_timeout, "Starting QBSecrets")
	def __init__(self):
		self.datastruct = { "AWSCLIENTID":[], 
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

		self.detectionawsclientid = compile(r'\b((A3T[A-Z0-9]|ABIA|ACCA|AGPA|AIDA|AIPA|AKIA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16})\b', I)
		self.detectionamazonmwsauthtoken = compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', I)
		self.detectionamazonaws = compile(r's3\.amazonaws\.com', I)
		self.detectionamazongeneric = compile(r'aws_access_key_id|aws_secret_access_key.*\b', I)
		self.detectionaliyunoss = compile(r'\.oss.aliyuncs.com', I)
		self.detectionazurestorage = compile(r'\.file.core.windows.net', I)
		self.detectionfacebookaccesstoken = compile(r'EAACEdEose0cBA[0-9a-zA-Z]+', I)
		self.detectiongithubtoken = compile(r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github.com*', I)
		self.detectiongoogleapikey = compile(r'\bAIza[0-9a-zA-Z\-_]{35}\b', I)
		self.detectiongooglecaptcha = compile(r'\b6L[0-9A-Za-z-_]{38}|6[0-9a-zA-Z_-]{39}\b', I)
		self.detectiongoogleoauth = compile(r'-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', I)
		self.detectiongooglesecret= compile(r'client_secret\"\:', I)
		self.detectiongoogleoauthaccesstoken= compile(r'ya29\.[0-9A-Za-z\-_]+', I)
		self.detectionmailgunapikey = compile(r'\bkey-[0-9a-zA-Z]{32}\b', I)
		self.detectionmailchampapi = compile(r'[0-9a-f]{32}-us[0-9]{1,2}', I)
		self.detectionpicaticapi = compile(r'sk_live_[0-9a-z]{32}', I)
		self.detectionslacktoken = compile(r'\b(xox[abrps]-([0-9a-zA-Z]{10,48})?)\b', I)
		self.detectionsquareaccesstoken = compile(r'sq0atp-[0-9a-zA-Z\-_]{22}', I)
		self.detectionsquareoauthsecret = compile(r'sq0csp-[0-9a-zA-Z\-_]{43}', I)
		self.detectionstripesapi = compile(r'[s|r]k_live_[0-9a-zA-Z]{24}', I)
		self.detectiontwilioapikey = compile(r'\bSK[0-9a-fA-F]{32}\b', I)
		self.detectiontwiliosid = compile(r'\bA[P|C][a-zA-Z0-9_-]{32}\b', I)

	@verbose(True, verbose_flag, verbose_timeout, "Finding AWS Clint ID patterns")
	def awsclientid(self, data):

		_List = []
		x = findall(self.detectionawsclientid, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_[0])
		for x in set(_List):
			data.append({"Count":_List.count(x), "AWSCLIENTID":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Amazon MWS Auth Token patterns")
	def amazonmwsauthtoken(self, data):

		_List = []
		x = findall(self.detectionamazonmwsauthtoken, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "AMAZONMWSAUTHTOKEN":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Amazon S3 patterns")
	def amazonaws(self, data):

		_List = []
		x = findall(self.detectionamazonaws, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "AMAZONAWS":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Amazon Generic patterns")
	def amazongeneric(self, data):

		_List = []
		x = findall(self.detectionamazongeneric, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "AMAZONGENERIC":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding ALIYUN OSS patterns")
	def aliyunoss(self, data):

		_List = []
		x = findall(self.detectionaliyunoss, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "ALIYUNOSS":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding AZURE Storage patterns")
	def azurestorage(self, data):

		_List = []
		x = findall(self.detectionazurestorage, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "AZURESTORAGE":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Facebook Access Token patterns")
	def facebookaccesstoken(self, data):

		_List = []
		x = findall(self.detectionfacebookaccesstoken, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "FACEBOOKACCESSTOKEN":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Github Token patterns")
	def githubtoken(self, data):

		_List = []
		x = findall(self.detectiongithubtoken, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "GITHUBTOKEN":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Goole API Key patterns")
	def googleapikey(self, data):

		_List = []
		x = findall(self.detectiongoogleapikey, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "GOOGLEAPIKEY":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Google CAPTCHA patterns")
	def googlecaptcha(self, data):

		_List = []
		x = findall(self.detectiongooglecaptcha, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "GOOGLECAPTCHA":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Google OAuth patterns")
	def googleoauth(self, data):

		_List = []
		x = findall(self.detectiongoogleoauth, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "GOOGLEOAUTH":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Google Secret patterns")
	def googlesecret(self, data):

		_List = []
		x = findall(self.detectiongooglesecret, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "GOOGLESECRET":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Google OAuth Access Token patterns")
	def googleoauthaccesstoken(self, data):

		_List = []
		x = findall(self.detectiongoogleoauthaccesstoken, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "GOOGLEOAUTHACCESSTOKEN":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Mailgun API Key patterns")
	def mailgunapikey(self, data):

		_List = []
		x = findall(self.detectionmailgunapikey, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "MAILGUNAPIKEY":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding MailChimp API patterns")
	def mailchampapi(self, data):

		_List = []
		x = findall(self.detectionmailchampapi, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "MAILCHAMPAPI":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Picatic API patterns")
	def picaticapi(self, data):

		_List = []
		x = findall(self.detectionpicaticapi, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "PICATICAPI":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Slack Token patterns")
	def slacktoken(self, data):

		_List = []
		x = findall(self.detectionslacktoken, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_[0])
		for x in set(_List):
			data.append({"Count":_List.count(x), "SLACKTOKEN":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Square Access Token patterns")
	def squareaccesstoken(self, data):

		_List = []
		x = findall(self.detectionsquareaccesstoken, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "SQUAREACCESSTOKEN":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Square OAuth Secret patterns")
	def squareoauthsecret(self, data):

		_List = []
		x = findall(self.detectionsquareoauthsecret, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "SQUAREOAUTHSECRET":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Stripe API patterns")
	def stripesapi(self, data):

		_List = []
		x = findall(self.detectionstripesapi, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "STRIPESAPI":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Twilio API patterns")
	def twilioapikey(self, data):

		_List = []
		x = findall(self.detectiontwilioapikey, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "TWILIOAPIKEY":x})

	@verbose(True, verbose_flag, verbose_timeout, "Finding Twilio SID patterns")
	def twiliosid(self, data):

		_List = []
		x = findall(self.detectiontwiliosid, self.wordsstripped)
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data.append({"Count":_List.count(x), "TWILIOSID":x})

	@verbose(True, verbose_flag, verbose_timeout, None)
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