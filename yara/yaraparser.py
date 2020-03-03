__G__ = "(G)bd249ce4"

from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout,log_string
from analyzer.settings import default_colors
from yara import compile
from glob import glob
from os import path
from copy import deepcopy

class YaraParser:
    @verbose(True,verbose_flag,verbose_timeout,"Starting YaraParser")
    def __init__(self):
        self.datastruct = { "Matches":[],
                            "Tags":[],
                            "_Matches":["Count","Offset","Rule","Patteren","Parsed","Condition"],
                            "__Tags":["namespace","rule","meta"]}

        self.yarapath = path.abspath(path.join(path.dirname( __file__ ),'rules'))
        if not self.yarapath.endswith(path.sep): self.yarapath = self.yarapath+path.sep
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

        self.yara_path_tags = path.abspath(path.join(path.dirname( __file__ ),'rules-master'))
        if not self.yara_path_tags.endswith(path.sep): self.yara_path_tags = self.yara_path_tags+path.sep
        self.yara_rules_tags = [x for x in glob(self.yara_path_tags+"*.yar")]
        self._set_tags = {}
        for rule in self.yara_rules_tags:
            head, tail = path.split(rule)
            self._set_tags.update({tail.split(".")[0]:rule})
        self.rules_tags = compile(filepaths=self._set_tags)

    @verbose(True,verbose_flag,verbose_timeout,"Checking with yara rules")
    def checkwithyara(self,data,parsed,check=""):
        '''
        check file with compiled yara detection and append results into list
        '''
        data["Yara"] = deepcopy(self.datastruct)
        if parsed.full or parsed.tags:
            log_string("Finding yara tags", "Green")
            matches = self.rules_tags.match(data["Location"]["File"])
            list_of_matches = []
            if len(matches) > 0:
                for match in matches:
                    full_rule = "{}:{}".format(match.namespace,match.rule)
                    if full_rule not in list_of_matches:
                        list_of_matches.append(full_rule)
                        color = None
                        try:
                            color = default_colors[match.namespace]
                        finally:
                            data["Yara"]["Tags"].append( { "fullrule": full_rule,
                                                              "namespace": match.namespace,
                                                              "color":color,
                                                              "rule":match.rule,
                                                              "meta":'\n'.join("{}: {}".format(key, match.meta[key]) for key in match.meta)})

        if parsed.full or parsed.yara:
            matches = self.rules.match(data["Location"]["File"])
            log_string("Finding yara matches", "Green")
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
                            if match.rule in self.yararulenamelist:
                                temp.update( {  pattern: [0,[hex(_match[0])],str(match),ppattern,self.yararulenamelist[match.rule]]})
                    for item in temp:
                        data["Yara"]["Matches"].append( {   "Count": temp[item][0],
                                                            "Offset":" ".join(temp[item][1]),
                                                            "Rule":temp[item][2],
                                                            "Patteren":item,
                                                            "Parsed":temp[item][3],
                                                            "Condition":temp[item][4]})