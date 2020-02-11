__G__ = "(G)bd249ce4"

from ..logger.logger import verbose, verbose_flag, verbose_timeout
from re import compile, findall
from copy import deepcopy
from subprocess import PIPE,Popen
from datetime import datetime

class QBSnort:
    @verbose(True,verbose_flag,verbose_timeout,"Starting QBSnort")
    def __init__(self):
        self.datastruct = {"Snort":[],
                          "_Snort":["time","sid","revision","class","priority","protocol","src","dest","msg"]}

        self.snortpattern = compile(r'(\d{2}\/\d{2}\/\d{2}\-\d{2}\:\d{2}\:\d{2}\.\d{6})\s+\[\*\*\]\s+\[(\d+)\:([\d]+)\:(\d+)\]\s+(.+)\s+\[\*\*\]\s+\[(.+)\]\s+\[(.+)\]\s+\{(.+)\}\s+([\d.:]+)\s+\-\>\s+([\d.:]+)')

    def run_snort(self,filename):
        output = ""
        p = Popen(['snort','-A','console','-N','-y','-c','/etc/snort/snort.conf','-r',filename], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        output = output.decode("utf-8",errors="ignore")
        return output

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_snort_output(self,data,filename):
        '''
        parse snort output
        '''
        _List = []
        ret = self.run_snort(filename)
        if len(ret) > 0:
            items = findall(self.snortpattern,ret)
            for item in items:
                _List.append({"time":item[0],"sid":item[2],"revision":item[3],"msg":item[4],"class":item[5],"priority":item[6],"protocol":item[7],"src":item[8],"dest":item[9]})
        if len(_List) > 0:
            data["Snort"] = deepcopy(sorted(_List, key = lambda i: datetime.strptime(i["time"], "%m/%d/%y-%H:%M:%S.%f")))

    @verbose(True,verbose_flag,verbose_timeout,"Analyzing with snort")
    def analyze(self,data):
        '''
        start checking logic and setup words and wordsstripped
        '''
        data["Snort"] = deepcopy(self.datastruct)
        self.get_snort_output(data["Snort"],data["Location"]["File"])