'''
    __G__ = "(G)bd249ce4"
    intell -> Behavior
'''
from re import compile as rcompile
from re import search as rsearch
from codecs import open as copen
from json import loads
from os import mkdir, path
from copy import deepcopy
from analyzer.logger.logger import ignore_excpetion, verbose


class QBBehavior:
    '''
    QBBehavior uses detections folder
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBBehavior")
    def __init__(self):
        '''
        Initialize QBBehavior, this has to pass
        '''
        self.datastruct = {"Intell": [],
                           "_Intell": ["Matched", "Required", "Behavior", "Detected"]}
        self.intell = path.abspath(path.join(path.dirname(__file__), 'detections'))
        if not self.intell.endswith(path.sep):
            self.intell = self.intell + path.sep
        if not path.isdir(self.intell):
            mkdir(self.intell)
        self.words = []
        self.wordsstripped = ""

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def rcompile_and_find(self, data, filename):
        '''
        parse the detections and check them against wordsstripped
        '''
        with copen(filename, "r", encoding='utf8') as file:
            for _ in loads(file.read()):
                with ignore_excpetion(Exception):
                    if "Type" in _ and "QREGEX" in _["Type"]:
                        _list = []
                        tempmatches = 0
                        for item in _["Detection"]:
                            if _["Options"]["Word"] == "Normal":
                                temp_value = rsearch(rcompile(r"{}".format(item), _["Options"]["Flag"]), self.wordsstripped)
                            elif _["Options"]["Word"] != "Normal":
                                temp_value = rsearch(rcompile(r"\b{}\b".format(item), _["Options"]["Flag"]), self.wordsstripped)
                            if temp_value is not None:
                                _list.append(temp_value.group())
                                tempmatches += 1
                        if _list and tempmatches >= _["Options"]["Required"]:
                            data.append({"Matched": tempmatches, "Required": _["Options"]["Required"], "Behavior": _["Name"], "Detected": ', '.join(_list)})

    @verbose(True, verbose_output=False, timeout=None, _str="Analyzing behaviors")
    def analyze(self, data, filename):
        '''
        start checking logic and setup words and wordsstripped
        '''
        if "Behavior" not in data:
            data["Behavior"] = deepcopy(self.datastruct)
        temp = []
        self.words = data["StringsRAW"]["wordsinsensitive"]
        self.wordsstripped = data["StringsRAW"]["wordsstripped"]
        self.rcompile_and_find(temp, self.intell + filename)
        if len(temp) > 0:
            data["Behavior"]["Intell"].extend(temp)
