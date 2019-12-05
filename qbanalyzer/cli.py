__G__ = "(G)bd249ce4"
__V__ = "2019.V.01.08"

from .staticanalyzer import StaticAnalyzer
from .logger.logger import logstring,verbose,verbose_flag
from cmd import Cmd
from os import path,listdir
from argparse import ArgumentParser
from shlex import split as ssplit
from requests import get

print("                                                                            ")
print(" _____   _____   _____  __   _  _____        \\   / ______  ______  _____   ")
print("|     | |_____] |_____| | \\  | |_____| |      \\_/   ____/ |______ |_____/")
print("|____\\| |_____] |     | |  \\_| |     | |_____  |   /_____ |______ |    \\")
print("      \\ V.01.08                                |                         ")
print("                                   https://github.com/bd249ce4/QBAnalyzer")
print("                                                                            ")

class QBAnalyzer(Cmd):
    _analyze_parser = ArgumentParser(prog="analyze")
    _analyze_parser._action_groups.pop()
    _analyze_parsergroupreq = _analyze_parser.add_argument_group('required arguments')
    _analyze_parsergroupreq.add_argument('--file', help="path to file/dump")
    _analyze_parsergroupreq.add_argument('--output', help="path of output folder")
    _analyze_parsergroupreq.add_argument('--folder', help="path to folder")
    _analyze_parsergroupdef = _analyze_parser.add_argument_group('default arguments')
    _analyze_parsergroupdef.add_argument('--intel',action='store_true', help="check with generic detections", required=False)
    _analyze_parsergroupdef.add_argument('--xref',action='store_true', help="get cross references", required=False)
    _analyze_parsergroupdef.add_argument('--yara',action='store_true', help="analyze with yara module (Disable this for big files)", required=False)
    _analyze_parsergroupdef.add_argument('--language',action='store_true', help="analyze words against english language", required=False)
    _analyze_parsergroupdef.add_argument('--mitre',action='store_true', help="map strings to mitre", required=False)
    _analyze_parsergroupdef.add_argument('--topurl',action='store_true', help="get urls and check them against top 10000", required=False)
    _analyze_parsergroupdef.add_argument('--ocr',action='store_true', help="get all ocr text", required=False)
    _analyze_parsergroupdef.add_argument('--json',action='store_true', help="make json record", required=False)
    _analyze_parsergroupdef.add_argument('--open',action='store_true', help="open the report in webbroswer", required=False)
    _analyze_parsergroupdef.add_argument('--enc',action='store_true', help="find encryptions", required=False)
    _analyze_parsergroupdef.add_argument('--cards',action='store_true', help="find credit cards", required=False)
    _analyze_parsergroupdef.add_argument('--patterns',action='store_true', help="find common patterns", required=False)
    _analyze_parsergroupdef.add_argument('--suspicious',action='store_true', help="find suspicious strings", required=False)
    _analyze_parsergroupdef.add_argument('--dga',action='store_true', help="find Domain generation algorithms", required=False)
    _analyze_parsergroupdef.add_argument('--plugins',action='store_true', help="scan with external plugins", required=False)
    _analyze_parsergroupdef.add_argument('--visualize',action='store_true', help="visualize some artifacts", required=False)
    _analyze_parsergroupdef.add_argument('--flags',action='store_true', help="add countries flags to html", required=False)
    _analyze_parsergroupdef.add_argument('--worldmap',action='store_true', help="add world map to html", required=False)
    _analyze_parsergroupdef.add_argument('--full',action='store_true', help="analyze using all modules", required=False)

    def __init__(self):
        super(QBAnalyzer, self).__init__()
        try:
            ver = get("https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/version")
            if ver.ok and ver.text.strip() != __V__:
                logstring("New version {} available, please update.. ".format(ver.text.strip()),"Red")
        except:
            logstring("Update failed","Red")
        self.san = StaticAnalyzer()

    def help_analyze(self):
        self._analyze_parser.print_help()
    	
    def do_analyze(self,line):
        try:
            parsed = self._analyze_parser.parse_args(ssplit(line))
        except SystemExit:
            return
        if parsed.file:
            if not path.exists(parsed.file) or not path.isdir(parsed.output):
                logstring("Target File/dump or output folder is wrong..","Red")
            else:
                self.san.analyze(parsed)
        elif parsed.folder:
            if not path.exists(parsed.folder) or not path.isdir(parsed.output):
                logstring("Target folder or output folder is wrong..","Red")
            else:
                self.do_folder(parsed.folder)

    def do_folder(self,_path):
        _List = []
        for f in listdir(_path):
            fullpath = path.join(_path, f)
            if path.isfile(fullpath):
                _List.append("--file {} --output {} --full".format(fullpath,_path))
        for i in _List:
            self.do_analyze(i)

    def do_exit(self, line):
        return True

    def do_EOF(self, line):
        return True

if __name__ == '__main__':
    QBAnalyzer().cmdloop()
