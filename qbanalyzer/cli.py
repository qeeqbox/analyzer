__G__ = "(G)bd249ce4"
__V__ = "2019.V.01.02"

from .staticanalyzer import StaticAnalyzer
from .logger.logger import logstring,verbose,verbose_flag
from cmd import Cmd
from os import path
from argparse import ArgumentParser
from shlex import split as ssplit
from requests import get

print("                                                                            ")
print(" _____   _____   _____  __   _  _____        \\   / ______  ______  _____   ")
print("|     | |_____] |_____| | \\  | |_____| |      \\_/   ____/ |______ |_____/")
print("|____\\| |_____] |     | |  \\_| |     | |_____  |   /_____ |______ |    \\ ∞")
print("                                               |                         ")
print("                                                                           ")

class QBAnalyzer(Cmd):

    _analyze_parser = ArgumentParser(prog="analyze")
    _analyze_parser._action_groups.pop()
    _analyze_parsergroupreq= _analyze_parser.add_argument_group('required arguments')
    _analyze_parsergroupreq.add_argument('--file', help="path of file/dump", required=True)
    _analyze_parsergroupreq.add_argument('--output', help="path of output folder", required=True)
    _analyze_parsergroupdef= _analyze_parser.add_argument_group('default arguments')
    _analyze_parsergroupdef.add_argument('--intel',action='store_true', help="check with generic detections", required=False)
    _analyze_parsergroupdef.add_argument('--xref',action='store_true', help="get cross references", required=False)
    _analyze_parsergroupdef.add_argument('--yara',action='store_true', help="analyze with yara module (Disable this for big files)", required=False)
    _analyze_parsergroupdef.add_argument('--string',action='store_true', help="analyze strings", required=False)
    _analyze_parsergroupdef.add_argument('--mitre',action='store_true', help="map strings to mitre", required=False)
    _analyze_parsergroupdef.add_argument('--topurl',action='store_true', help="get urls and check them against top 10000", required=False)
    _analyze_parsergroupdef.add_argument('--ocr',action='store_true', help="get all ocr text", required=False)
    _analyze_parsergroupdef.add_argument('--json',action='store_true', help="make json record", required=False)
    _analyze_parsergroupdef.add_argument('--open',action='store_true', help="open the report in webbroswer", required=False)
    _analyze_parsergroupdef.add_argument('--enc',action='store_true', help="open the report in webbroswer", required=False)
    _analyze_parsergroupdef.add_argument('--plugins',action='store_true', help="scan with external plugins", required=False)
    _analyze_parsergroupdef.add_argument('--visualize',action='store_true', help="visualize some artifacts", required=False)
    _analyze_parsergroupdef.add_argument('--full',action='store_true', help="analyze using all modules", required=False)

    def __init__(self):
        super(QBAnalyzer, self).__init__()
        try:
            ver = get("https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/version")
            if ver.ok and ver.text.strip() != __V__:
                logstring("New version {} available, please update.. ".format(ver),"Red")
        except:
            logstring("Update failed","Red")
        self.san = StaticAnalyzer()

    def help_analyze(self):
        self._analyze_parser.print_help()

    @verbose(verbose_flag)
    def do_analyze(self,line):
        try:
            parsed = self._analyze_parser.parse_args(ssplit(line))
        except SystemExit:
            return
        if not path.exists(parsed.file) or not path.isdir(parsed.output):
            logstring("File/dump or folder is wrong..","Red")
        else:
            self.san.analyze(parsed)

    def do_exit(self, line):
        exit()

    def do_EOF(self, line):
        exit()

if __name__ == '__main__':
    QBAnalyzer().cmdloop()
