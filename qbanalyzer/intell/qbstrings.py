__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from ..mics.funcs import iptolong
from re import findall,compile,I,sub
from nltk.corpus import words
from nltk.tokenize import word_tokenize
from sqlite3 import connect
from os import mkdir, path
from binascii import unhexlify

#this module needs some optimization

class QBStrings:
    @progressbar(True,"Starting QBStrings")
    def __init__(self):
        '''
        initialize class and make refs path that contains References.db
        get english words from corpus and open connection with References.db
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
        check if words are english words or not

        Args:
            _data: data dict
        '''
        _dict = {"UnKnown":[],"English":[],"Partly English":[],"Suspicious":[]}
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

                _dict[temp].append(_word)

        for key in _dict.keys():
            for x in set(_dict[key]):
                _data[key].append({"Count":_dict[key].count(x),"Buffer":x})

    @verbose(verbose_flag)
    @progressbar(True,"check urls")
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
                _List.append(_[0])
        for x in set(_List):
            _data.append({"Count":_List.count(x),"Link":x})

    @verbose(verbose_flag)
    @progressbar(True,"check ips")
    def checkip(self,_data):
        '''
        check if buffer contains ips x.x.x.x

        Args:
            _data: data dict
        '''
        _List = []
        ip = compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',I)
        x = findall(ip,self.wordsstripped)
        if len(x) > 0:
            for _ in x:
                _List.append(_)
        for x in set(_List):
            _data.append({"Count":_List.count(x),"IP":x})

    @verbose(verbose_flag)
    @progressbar(True,"check emails")
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
    @progressbar(True,"Check tel numbers")
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
    @progressbar(True,"Check tags")
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
    @progressbar(True,"Check Hex")
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
    @progressbar(True,"Added descriptions to strings")
    def adddescription(self,_type,data,keyword):
        '''
        add description to buffer

        Args:
            _type: type of description
            data: data dict
            keyword: target key to check (Ex. IP)
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
        self.words = data["StringsRAW"]["words"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        data["Strings"] = {  "English":[],
                             "UnKnown":[],
                             "Partly English":[],
                             "IPS":[],
                             "LINKS":[],
                             "EMAILS":[],
                             "TELS":[],
                             "TAGS":[],
                             "Suspicious":[],
                             "HEX":[],
                             "_English":["Count","Buffer"],
                             "_UnKnown":["Count","Buffer"],
                             "_Suspicious":["Count","Buffer"],
                             "_Partly English":["Count","Buffer"],
                             "_IPS":["Count","IP","Code","Description"],
                             "_LINKS":["Count","Link"],
                             "_EMAILS":["Count","EMAIL","Description"],
                             "_TELS":["Count","TEL","Description"],
                             "_TAGS":["Count","TAG","Description"],
                             "_HEX":["Count","HEX","Parsed"]}
        #engsorted = self.sortbylen(self.checkwithenglish()["English"])
        #unksorted = self.sortbylen(self.checkwithenglish()["UnKnown"])
        #b64 = self.checkbase64()
        self.checkwithenglish(data["Strings"])
        self.checklink(data["Strings"]["LINKS"])
        self.checkip(data["Strings"]["IPS"])
        self.checkemail(data["Strings"]["EMAILS"])
        self.checktags(data["Strings"]["TAGS"])
        self.checkhex(data["Strings"]["HEX"])
        #self.checkphonenumber(data["Strings"]["TELS"])
        self.adddescription("DNS",data["Strings"]["IPS"],"IP")
        self.adddescription("IPs",data["Strings"]["IPS"],"IP")
        self.adddescription("IPPrivate",data["Strings"]["IPS"],"IP")
        #self.checkmitre(data["Strings"])
