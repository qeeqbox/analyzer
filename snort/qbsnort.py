'''
    __G__ = "(G)bd249ce4"
    reports -> snort
'''

from re import findall
from re import compile as rcompile
from copy import deepcopy
from subprocess import PIPE, Popen
from datetime import datetime
from analyzer.logger.logger import verbose


class QBSnort:
    '''
    QBSnort for parsing snort output
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBSnort")
    def __init__(self):
        '''
        initialize class and datastruct, this has to pass
        '''
        self.datastruct = {"Snort": [],
                           "_Snort": ["time", "sid", "revision", "class", "priority", "protocol", "src", "dest", "msg"]}

        self.snortpattern = rcompile(r'(\d{2}\/\d{2}\/\d{2}\-\d{2}\:\d{2}\:\d{2}\.\d{6})\s+\[\*\*\]\s+\[(\d+)\:([\d]+)\:(\d+)\]\s+(.+)\s+\[\*\*\]\s+\[(.+)\]\s+\[(.+)\]\s+\{(.+)\}\s+([\d.:]+)\s+\-\>\s+([\d.:]+)')

    def run_snort(self, filename):
        '''
        run snort app
        '''
        output = ""
        process = Popen(['snort', '-A', 'console', '-N', '-y', '-c', '/etc/snort/snort.conf', '-r', filename], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = process.communicate()
        output = output.decode("utf-8", errors="ignore")
        return output

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_snort_output(self, data, filename):
        '''
        parse snort output
        '''
        temp_list = []
        ret = self.run_snort(filename)
        if len(ret) > 0:
            items = findall(self.snortpattern, ret)
            for item in items:
                temp_list.append({"time": item[0], "sid": item[2], "revision": item[3], "msg": item[4], "class": item[5], "priority": item[6], "protocol": item[7], "src": item[8], "dest": item[9]})
        if len(temp_list) > 0:
            data["Snort"] = deepcopy(sorted(temp_list, key=lambda i: datetime.strptime(i["time"], "%m/%d/%y-%H:%M:%S.%f")))

    @verbose(True, verbose_output=False, timeout=None, _str="Analyzing with snort")
    def analyze(self, data):
        '''
        start checking logic and setup words and wordsstripped
        '''
        data["Snort"] = deepcopy(self.datastruct)
        self.get_snort_output(data["Snort"], data["Location"]["File"])
