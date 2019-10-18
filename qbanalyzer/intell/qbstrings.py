__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from ..mics.funcs import iptolong
from re import findall,compile,I,sub
from nltk.corpus import words
from base64 import b64decode,b64encode
from nltk.tokenize import word_tokenize
from sqlite3 import connect
from os import mkdir, path

#this module need some optimization

verbose_flag = False

class QBStrings:
    @progressbar(True,"Starting QBStrings")
    def __init__(self):
        '''
        initialize object with the path of refs that contains References.db
        Connect to References.db sqlite3 database, get english words from nltk.corpus
        initialize some suspicious words to detect on
        '''
        self.refs = path.abspath(path.join(path.dirname( __file__ ),"..", 'refs'))
        if not self.refs.endswith(path.sep): self.refs = self.refs+path.sep
        if not path.isdir(self.refs): mkdir(self.refs)
        self.english_words = set(words.words())
        self.dic_dict = None #set([line.lower().strip() for line in open(_path+"dic_four.text", 'r')])
        self.cursor = connect(self.refs+'References.db').cursor()
        self.sus = ["crypt","==","ransom","+tcp","pool.","bitcoin","encrypt","decrypt","mail","ftp","http","https","btc","address","sudo","password","pass","admin","payment"]
        self.way = 5
        self.mitreusedict = None

    @verbose(verbose_flag)
    @progressbar(True,"Detecing english strings")
    def checkwithenglish(self,_data):
        '''
        Check if words are UnKnown, english, Partly English or Suspicious
        
        Args:
            _data: data dict
        '''
        _List = {"UnKnown":[],"English":[],"Partly English":[],"Suspicious":[]}
        if len(self.words) > 0:
            for word in self.words:
                _word = word.decode('utf-8',"ignore")
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

                _List[temp].append(_word)

        for key in _List.keys():
            for x in set(_List[key]):
                _data[key].append({"Count":_List[key].count(x),"Buffer":x})

    @verbose(verbose_flag)
    def checkbase64(self):
        _data = []
        if len(self.words) > 0:
            for word in self.words:
                b = self.testbase64(word)
                if b != None and b != False:
                    _data.append({"Base64":word.decode('ascii',"ignore")})
            return _data
        return False

    @verbose(verbose_flag)
    def testbase64(self,w):
        try:
            y = b64decode(w)
            if b64encode(y) == w:
                return y
        except:
            return False

    @verbose(verbose_flag)
    @progressbar(True,"Check for IPS")
    def checkip(self,_data):
        '''
        Check if wordsstripped contains ip or not
        
        Args:
            _data: data dict
        '''
        _List = []
        ip = compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',I)
        x = findall(ip,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"IP":x})
        return True

    @verbose(verbose_flag)
    @progressbar(True,"Check for Emails")
    def checkemail(self,_data):
        '''
        Check if wordsstripped contains emails or not
        
        Args:
            _data: data dict
        '''
        _List = []
        email = compile('(\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*)',I)
        x = findall(email,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_[0])
        for x in set(_List):
            _data.append({"Count":_List.count(x),"EMAIL":x})
        return True

    @verbose(verbose_flag)
    @progressbar(True,"Check for phone numbers")
    def checkphonenumber(self,_data):
        '''
        Check if wordsstripped contains phone numbers or not
        
        Args:
            _data: data dict
        '''
        _List = []
        tel = compile('(\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*)',I)
        x = findall(tel,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"TEL":x})
        return True

    @verbose(verbose_flag)
    @progressbar(True,"Check for tags")
    def checktags(self,_data):
        '''
        Check if wordsstripped contains tags or not
        
        Args:
            _data: data dict
        '''
        _List = []
        html = compile('>([^<]*)<\/',I)
        x = findall(html,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"TAG":x})
        return True

    @verbose(verbose_flag)
    @progressbar(True,"Added descriptions to strings")
    def adddescription(self,_type,data,keyword):
        '''
        Check if word has description in References.db or not
        
        Args:
            _data: data dict
            keyword: type of description (pretty much the db table)
        '''
        if len(data) > 0:
            for x in data:
                try:
                    if x[keyword]:
                        word = x[keyword].lower()
                        description = ""
                        if _type == "ManHelp":
                            result = self.cursor.execute('SELECT * FROM ManHelp WHERE cmd= ? OR cmd =?',(word,word.rstrip("_").lstrip("_"),)).fetchone()
                            if result:
                                description = result[2]
                        elif _type == "WinApis":
                            result = self.cursor.execute('SELECT * FROM WinApis WHERE api= ? OR api = ? OR api =?',(word,word[:-1],word.rstrip("_").lstrip("_")),).fetchone()
                            if result:
                                description = result[2]
                        elif _type == "WinDlls":
                            result = self.cursor.execute('SELECT * FROM WinDlls WHERE dll= ?',(word,)).fetchone()
                            if result:
                                description = result[2]
                        elif _type == "WinSections":
                            result = self.cursor.execute('SELECT * FROM WinSections WHERE section= ?',(word,)).fetchone()
                            if result:
                                description = result[2]
                        elif _type == "DNS":
                            result = self.cursor.execute('SELECT * FROM DNSServers WHERE dns= ?',(word,)).fetchone()
                            if result:
                                description = result[2] + " DNS Server"
                        elif _type == "LinuxSections":
                            result = self.cursor.execute('SELECT * FROM LinuxSections WHERE section= ?',(word,)).fetchone()
                            if result:
                                description = result[2]
                        elif _type == "WinResources":
                            result = self.cursor.execute('SELECT * FROM WinResources WHERE resource= ?',(word,)).fetchone()
                            if result:
                                description = result[2]
                        elif _type == "AndroidPermissions":
                            result = self.cursor.execute('SELECT * FROM AndroidPermissions WHERE permission= ?',(word.split("android.permission.")[1],)).fetchone()
                            if result:
                                description = result[3]
                        elif _type == "Ports":
                            result = self.cursor.execute('SELECT * FROM Ports WHERE port= ?',(word,)).fetchone()
                            if result:
                                if keyword == "SourcePort":
                                    x.update({"SPDescription":result[3]})
                                elif keyword == "DestinationPort":
                                    x.update({"DPDescription":result[3]})
                                elif keyword == "Port":
                                    x.update({"Description":result[4]})
                            continue
                        elif _type == "IPs":
                            if len(x["Description"]) > 0:
                                continue
                            lip = iptolong(word)
                            result = self.cursor.execute('SELECT * FROM CountriesIPs WHERE ipto >= ? AND ipfrom <= ?', (lip,lip,)).fetchone()
                            if result:
                                _result = self.cursor.execute('SELECT * FROM CountriesIDs WHERE ctry= ?', (result[5],)).fetchone()
                                if _result:
                                    x.update({"Code":_result[4],"Description":result[7]})
                                    continue
                        elif _type == "IPPrivate":
                            lip = iptolong(word)
                            result = self.cursor.execute('SELECT * FROM ReservedIP WHERE ipto >= ? AND ipfrom <= ?', (lip,lip,)).fetchone()
                            if result:
                                description = result[3]
                        if "Description" in x:
                            if len(x["Description"]) > 0:
                                continue
                        x.update({"Description":description})
                except:
                    pass
        return False

    @verbose(verbose_flag)
    def sortbylen(self,_dict):
        return sorted(_dict, key=lambda l: (len(str(l))))

    @verbose(verbose_flag)
    def checkwithstring(self,data):
        '''
        Setup words, wordsstripped, and add new keys in the data dict 
        
        Args:
            data: main dict object
        '''
        self.words = data["StringsRAW"]["words"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        data["Strings"] = {  "English":[],
                             "UnKnown":[],
                             "Partly English":[],
                             "IPS":[],
                             "EMAILS":[],
                             "TELS":[],
                             "TAGS":[],
                             "Suspicious":[],
                             "_English":["Count","Buffer"],
                             "_UnKnown":["Count","Buffer"],
                             "_Suspicious":["Count","Buffer"],
                             "_Partly English":["Count","Buffer"],
                             "_IPS":["Count","IP","Code","Description"],
                             "_EMAILS":["Count","EMAIL","Description"],
                             "_TELS":["Count","TEL","Description"],
                             "_TAGS":["Count","TAG","Description"]}
        #engsorted = self.sortbylen(self.checkwithenglish()["English"])
        #unksorted = self.sortbylen(self.checkwithenglish()["UnKnown"])
        #b64 = self.checkbase64()
        self.checkwithenglish(data["Strings"])
        self.checkip(data["Strings"]["IPS"])
        self.checkemail(data["Strings"]["EMAILS"])
        self.checktags(data["Strings"]["TAGS"])
        #self.checkphonenumber(data["Strings"]["TELS"])
        self.adddescription("DNS",data["Strings"]["IPS"],"IP")
        self.adddescription("IPs",data["Strings"]["IPS"],"IP")
        self.adddescription("IPPrivate",data["Strings"]["IPS"],"IP")
        #self.checkmitre(data["Strings"])
