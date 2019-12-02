__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from ..mics.funcs import iptolong
from nltk.corpus import words
from nltk.tokenize import word_tokenize
from json import loads
from os import mkdir, path

#this module need some optimization

class QBMitresearch:
    @verbose(verbose_flag)
    @progressbar(True,"Starting QBMitresearch")
    def __init__(self,mitre):
        '''
        initialize class, make mitrefiles path
        '''
        self.mitrepath = path.abspath(path.join(path.dirname( __file__ ),'mitrefiles'))
        if not self.mitrepath.endswith(path.sep): self.mitrepath = self.mitrepath+path.sep
        if not path.isdir(self.mitrepath): mkdir(self.mitrepath)
        self.mitre = mitre
        self.parsediocs = self.mitrepath+"parsediocs.json"

    @verbose(verbose_flag)
    def searchinmitreandreturn(self,s,attack):
        '''
        get attack info from fulldict
        '''
        for x in s:
            if "id" in x and "attack-pattern" in x["id"]:
                if x['external_references'][0]['external_id'].lower() == attack:
                    return x
        return None

    @progressbar(True,"Finding attack patterns")
    @verbose(verbose_flag)
    def checkmitresimilarity(self,data):
        '''
        check detections from parsediocs.json against wordsstripped, if yes bring attack info
        '''
        _list = []
        f = loads(open(self.parsediocs).read())
        for attack in f:
            for ioc in f[attack]:
                if ioc.lower() in self.wordsstripped and len(ioc.lower()) > 3: # added > 3 less FB 
                    _list.append(ioc.lower())
            if len(_list) > 0:
                x = self.searchinmitreandreturn(self.mitre.fulldict,attack)
                if x:
                    data["Attack"].append({ "Id":attack,
                                            "Name":x["name"],
                                            "Detected":','.join(_list),
                                            "Description":x["description"]})
                else:
                    data["Attack"].append({ "Id":attack,
                                            "Name":"None",
                                            "Detected":','.join(_list),
                                            "Description":"None"})
            _list = []

    @progressbar(True,"Finding mitre artifacts")
    @verbose(verbose_flag)
    def checkmitre(self,data):
        '''
        check if words are tools or malware listed in mitre 
        '''
        for _word in self.words:
            toolrecords = self.mitre.findtool(_word)
            if toolrecords:
                for record in toolrecords:
                    data["Binary"].append({  "Word":_word,
                                            "Name":record["name"],
                                            "Description":record["description"]})
            malwarerecords = self.mitre.findmalware(_word)
            if malwarerecords:
                for record in malwarerecords:
                    data["Binary"].append({  "Word":_word,
                                            "Name":record["name"],
                                            "Description":record["description"]})
        return True

    @progressbar(True,"Analyzing with mitre")
    @verbose(verbose_flag)
    def checkwithmitre(self,data):
        '''
        start mitre analysis for words and wordsstripped
        '''
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        data["MITRE"] = {"Binary":[],
                         "Attack":[],
                         "_Binary":["Word","Name","Description"],
                         "_Attack":["Id","Name","Detected","Description"]}
        self.checkmitre(data["MITRE"])
        self.checkmitresimilarity(data["MITRE"])