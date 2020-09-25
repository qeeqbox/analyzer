'''
    __G__ = "(G)bd249ce4"
    mitre -> qbmitre
'''

from os import mkdir, path
from json import loads
from analyzer.logger.logger import ignore_excpetion, verbose

class QBMitresearch():
    '''
    this module will use parsediocs for detection
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBMitresearch")
    def __init__(self, MitreParser):
        '''
        initialize class, make mitrefiles path
        '''
        self.mitre = MitreParser()
        self.mitrepath = path.abspath(path.join(path.dirname(__file__), 'mitrefiles'))
        if not self.mitrepath.endswith(path.sep):
            self.mitrepath = self.mitrepath+path.sep
        if not path.isdir(self.mitrepath):
            mkdir(self.mitrepath)
        self.parsediocs = self.mitrepath+"parsediocs.json"
        self.words = []
        self.wordsstripped = ""

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def search_in_mitre_and_return(self, temp_s, attack):
        '''
        get attack info from fulldict
        '''
        for temp_x in temp_s:
            if "id" in temp_x and "attack-pattern" in temp_x["id"]:
                if temp_x['external_references'][0]['external_id'].lower() == attack:
                    return temp_x
        return None

    @verbose(True, verbose_output=False, timeout=None, _str="Finding attack patterns")
    def check_mitre_similarity(self, data):
        '''
        check detections from parsediocs.json against wordsstripped, if yes bring attack info (added > 3 less FB )
        '''
        _list = []
        file_buffer = loads(open(self.parsediocs).read())
        for attack in file_buffer:
            for ioc in file_buffer[attack]:
                if ioc.lower() in self.wordsstripped and len(ioc.lower()) > 3:
                    _list.append(ioc.lower())
            if len(_list) > 0:
                temp_x = self.search_in_mitre_and_return(self.mitre.fulldict, attack)
                temp_dict = {"Id":attack,
                             "Name":"None",
                             "Detected":', '.join(_list),
                             "Description":"None"}
                if temp_x:
                    with ignore_excpetion(Exception): 
                        temp_dict = {"Id":attack,
                                     "Name":temp_x["name"],
                                     "Detected":', '.join(_list),
                                     "Description":temp_x["description"]}
                data["Attack"].append(temp_dict)
            _list = []

    @verbose(True, verbose_output=False, timeout=None, _str="Finding mitre artifacts")
    def check_mitre(self, data):
        '''
        check if words are tools or malware listed in mitre
        '''
        for _word in self.words:
            toolrecords = self.mitre.findtool(_word)
            if toolrecords:
                for record in toolrecords:
                    data["Binary"].append({"Word":_word,
                                           "Name":record["name"],
                                           "Description":record["description"]})
            malwarerecords = self.mitre.findmalware(_word)
            if malwarerecords:
                for record in malwarerecords:
                    data["Binary"].append({"Word":_word,
                                           "Name":record["name"],
                                           "Description":record["description"]})
        return True

    @verbose(True, verbose_output=False, timeout=None, _str="Analyzing with mitre")
    def analyze(self, data):
        '''
        start mitre analysis for words and wordsstripped
        '''
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        data["MITRE"] = {"Binary":[],
                         "Attack":[],
                         "_Binary":["Word", "Name", "Description"],
                         "_Attack":["Id", "Name", "Detected", "Description"]}
        self.check_mitre(data["MITRE"])
        self.check_mitre_similarity(data["MITRE"])
