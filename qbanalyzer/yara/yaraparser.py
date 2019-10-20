__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from yara import compile
from glob import glob
from os import mkdir, path

class YaraParser:
    @verbose(verbose_flag)
    @progressbar(True,"Starting YaraParser")
    def __init__(self):
        '''
        initialize class and make rules folder, get all conditions from .yar
        '''
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

    @verbose(verbose_flag)
    @progressbar(True,"Checking with yara rules")
    def checkwithyara(self,data,check=""):
        '''
        check file with compiled yara detection and append results into list

        Args:
            data: data dict
            check not used
        '''
        data["Yara"] = {"Matches":[],
                        "_Matches":["Offset","Rule","Patteren","Parsed","Condition"]}
        matches = self.rules.match(data["Location"]["File"])
        if len(matches) > 0:
            for match in matches:
                for _match in match.strings:
                    key = "{}:{}".format(match.namespace,match)
                    try:
                        pattern =  _match[2].decode("utf-8")
                        ppattern = "None"
                    except:
                        pattern = ''.join('\\x{:02x}'.format(x) for x in _match[2])
                        ppattern =  _match[2].decode("ascii","replace")
                    #val = "{}:{} -> {}".format(basename,hex(_match[0]),pattern)
                    #_list.append([match.namespace,match,pattern,ppattern,hex(_match[0]),self.yararulenamelist[match.rule]])
                    data["Yara"]["Matches"].append( {  "Offset":hex(_match[0]),
                                                        "Rule":str(match),
                                                        "Patteren":pattern,
                                                        "Parsed":ppattern,
                                                        "Condition":self.yararulenamelist[match.rule]})
                    #_list.append({key:val})