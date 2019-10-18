__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from re import compile, search
from codecs import open as copen
from json import loads
from os import mkdir, path

#this module need some optimization

class QBIntell:
    @verbose(verbose_flag)
    @progressbar(True,"Starting QBIntell")
    def __init__(self):
        '''
        initialize object with the path of detections that contains json files
        '''
        self.intell = path.abspath(path.join(path.dirname( __file__ ),'detections'))
        if not self.intell.endswith(path.sep): self.intell = self.intell+path.sep
        if not path.isdir(self.intell): mkdir(self.intell)

    @verbose(verbose_flag)
    def compileandfind(self,data,filename):
        '''
        Compile regex detection from json and find matches
        
        Args:
            data: main dict object
            filename: name of json file ex (android.json)
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

    @verbose(verbose_flag)
    @progressbar(True,"Analyze file behavior")
    def checkwithqbintell(self,data,filename):
        '''
        Setup words, wordsstripped, and add new keys in the data dict 
        
        Args:
            data: main dict object
            filename: name of json file ex (android.json)
        '''
        self.words = data["StringsRAW"]["words"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        data["Intell"] = {"WinAPI":[],
                          "_WinAPI":["Matched","Required","Behavior","Detected"]}
        self.compileandfind(data["Intell"]["WinAPI"],self.intell+filename)
