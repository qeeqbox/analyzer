__G__ = "(G)bd249ce4"

from ..logger.logger import verbose, verbose_flag, verbose_timeout
from re import compile, search
from codecs import open as copen
from json import loads
from os import mkdir, path
from copy import deepcopy

class QBBehavior:
    @verbose(True,verbose_flag,verbose_timeout,"Starting QBBehavior")
    def __init__(self):
        self.datastruct = {"Intell":[],
                          "_Intell":["Matched","Required","Behavior","Detected"]}

        self.intell = path.abspath(path.join(path.dirname( __file__ ),'detections'))
        if not self.intell.endswith(path.sep): self.intell = self.intell+path.sep
        if not path.isdir(self.intell): mkdir(self.intell)

    @verbose(True,verbose_flag,verbose_timeout,None)
    def compile_and_find(self,data,filename):
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

    @verbose(True,verbose_flag,verbose_timeout,"Analyzing behaviors")
    def analyze(self,data,filename):
        '''
        start checking logic and setup words and wordsstripped
        '''
        if "Behavior" not in data:
            data["Behavior"] = deepcopy(self.datastruct)
        temp = []
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.compile_and_find(temp,self.intell+filename)
        if len(temp) > 0:
            data["Behavior"]["Intell"].extend(temp)
