__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from re import compile, search
from codecs import open as copen
from json import loads
from os import mkdir, path

class QBIntell:
    @verbose(True,verbose_flag,"Starting QBIntell")
    def __init__(self):
        '''
        initialize class and make detections path 
        '''
        self.intell = path.abspath(path.join(path.dirname( __file__ ),'detections'))
        if not self.intell.endswith(path.sep): self.intell = self.intell+path.sep
        if not path.isdir(self.intell): mkdir(self.intell)

    @verbose(True,verbose_flag,None)
    def compileandfind(self,data,filename):
        '''
        parse the detections and check them against wordsstripped
        '''
        with copen(filename,"r",encoding='utf8') as f:
            for _ in loads(f.read()):
                try:
                    if "Type" in _ and "QREGEX" in _["Type"]:
                        _list = []
                        tempmatches = 0
                        for item in _["Detection"]:
                            if _["Options"]["Word"] == "Normal":
                                x = search(compile(r"{}".format(item),_["Options"]["Flag"]),self.wordsstripped)
                            elif _["Options"]["Word"] != "Normal":
                                    #Functions end with A,W do not match using "Word" option
                                x = search(compile(r"\b{}\b".format(item),_["Options"]["Flag"]),self.wordsstripped)
                            if x is not None:
                                _list.append(x.group())
                                tempmatches += 1
                        if _list and tempmatches >= _["Options"]["Required"]:
                            data.append({"Matched":tempmatches,"Required":_["Options"]["Required"],"Behavior":_["Name"],"Detected":','.join(_list)})
                except:
                    pass

    @verbose(True,verbose_flag,"Analyzing behaviors")
    def checkwithqbintell(self,data,filename):
        '''
        start checking logic and setup words and wordsstripped
        '''
        data["Intell"] = {"API":[],
                          "_API":["Matched","Required","Behavior","Detected"]}
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.compileandfind(data["Intell"]["API"],self.intell+filename)
