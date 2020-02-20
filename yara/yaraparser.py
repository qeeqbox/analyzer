__G__ = "(G)bd249ce4"

from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout
from yara import compile
from glob import glob
from os import mkdir, path
from copy import deepcopy

class YaraParser:
    @verbose(True,verbose_flag,verbose_timeout,"Starting YaraParser")
    def __init__(self):
        self.datastruct = { "Matches":[],
                            "_Matches":["Count","Offset","Rule","Patteren","Parsed","Condition"]}

        self.yarapath = path.abspath(path.join(path.dirname( __file__ ),'rules'))
        if not self.yarapath.endswith(path.sep): self.yarapath = self.yarapath+path.sep
        if not path.isdir(self.yarapath): mkdir(self.yarapath)
        self.yararules = [x for x in glob(self.yarapath+"*.yar")]
        self.yararulenamelist = {}
        self._set = {}
        for rule in self.yararules:
            head, tail = path.split(rule)
            self._set.update({tail.split(".")[0]:rule})
        self.rules = compile(filepaths=self._set)
        for rule in self.yararules:
            x = [line.strip() for line in open(rule, 'r')]
            for i in range(len(x)):
                if x[i].startswith("rule ") and x[i+1] == "{":
                    rule = x[i].split(" ")[1]
                elif x[i] == "condition:" and rule != "":
                    self.yararulenamelist.update({rule:x[i+1]})
                    rule =""

    @verbose(True,verbose_flag,verbose_timeout,"Checking with yara rules")
    def checkwithyara(self,data,check=""):
        '''
        check file with compiled yara detection and append results into list
        '''
        data["Yara"] = deepcopy(self.datastruct)
        matches = self.rules.match(data["Location"]["File"])
        if len(matches) > 0:
            for match in matches:
                temp = {}
                for _match in match.strings:
                    key = "{}:{}".format(match.namespace,match)
                    try:
                        pattern =  _match[2].decode("utf-8",errors="ignore")
                        ppattern = "None"
                    except:
                        pattern = ''.join('\\x{:02x}'.format(x) for x in _match[2])
                        ppattern =  _match[2].decode("ascii","replace")

                    if pattern in temp:
                        temp[pattern][0] += 1
                        temp[pattern][1].append(hex(_match[0]))
                    else:
                        temp.update( {  pattern: [0,[hex(_match[0])],str(match),ppattern,self.yararulenamelist[match.rule]]})
                for item in temp:
                    data["Yara"]["Matches"].append( {   "Count": temp[item][0],
                                                        "Offset":" ".join(temp[item][1]),
                                                        "Rule":temp[item][2],
                                                        "Patteren":item,
                                                        "Parsed":temp[item][3],
                                                        "Condition":temp[item][4]})
