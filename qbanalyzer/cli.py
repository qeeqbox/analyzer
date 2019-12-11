__G__ = "(G)bd249ce4"
__V__ = "2019.V.01.11"

from .staticanalyzer import StaticAnalyzer
from .mics.funcs import killpythoncli,killprocessandsubs
from .logger.logger import logstring,verbose,verbose_flag,setuplogger
from cmd import Cmd
from os import path,listdir
from argparse import ArgumentParser
from shlex import split as ssplit
from requests import get
from tempfile import NamedTemporaryFile,gettempdir
from sys import stdout
from signal import signal,SIGTSTP,SIGINT

def ctrlhandler(signum, frame):
    stdout.write("\n")
    logstring("Terminating..","Red")
    killprocessandsubs()

print("                                                                            ")
print(" _____   _____   _____  __   _  _____        \\   / ______  ______  _____   ")
print("|     | |_____] |_____| | \\  | |_____| |      \\_/   ____/ |______ |_____/")
print("|____\\| |_____] |     | |  \\_| |     | |_____  |   /_____ |______ |    \\")
print("      \\ {}                           |                        ".format(__V__))
print("                                   https://github.com/bd249ce4/QBAnalyzer")
print("                                                                            ")

class QBAnalyzer(Cmd):
    killpythoncli()
    setuplogger()
    signal(SIGTSTP, ctrlhandler)
    signal(SIGINT, ctrlhandler)
    _analyze_parser = ArgumentParser(prog="analyze")
    _analyze_parser._action_groups.pop()
    _analyze_parsergroupreq = _analyze_parser.add_argument_group('Input arguments')
    _analyze_parsergroupreq.add_argument('--file', help="path to file or dump")
    _analyze_parsergroupreq.add_argument('--folder', help="path to folder")
    _analyze_parsergroupreq.add_argument('--buffer', help="input buffer")
    _analyze_parsergroupdef = _analyze_parser.add_argument_group('Analysis arguments')
    _analyze_parsergroupdef.add_argument('--behavior',action='store_true', help="check with generic detections", required=False)
    _analyze_parsergroupdef.add_argument('--xref',action='store_true', help="get cross references", required=False)
    _analyze_parsergroupdef.add_argument('--yara',action='store_true', help="analyze with yara module (Disable this for big files)", required=False)
    _analyze_parsergroupdef.add_argument('--language',action='store_true', help="analyze words against english language", required=False)
    _analyze_parsergroupdef.add_argument('--mitre',action='store_true', help="map strings to mitre", required=False)
    _analyze_parsergroupdef.add_argument('--topurl',action='store_true', help="get urls and check them against top 10000", required=False)
    _analyze_parsergroupdef.add_argument('--ocr',action='store_true', help="get all ocr text", required=False)
    _analyze_parsergroupdef.add_argument('--enc',action='store_true', help="find encryptions", required=False)
    _analyze_parsergroupdef.add_argument('--cards',action='store_true', help="find credit cards", required=False)
    _analyze_parsergroupdef.add_argument('--creds',action='store_true', help="find credit cards", required=False)
    _analyze_parsergroupdef.add_argument('--patterns',action='store_true', help="find common patterns", required=False)
    _analyze_parsergroupdef.add_argument('--suspicious',action='store_true', help="find suspicious strings", required=False)
    _analyze_parsergroupdef.add_argument('--dga',action='store_true', help="find Domain generation algorithms", required=False)
    _analyze_parsergroupdef.add_argument('--plugins',action='store_true', help="scan with external plugins", required=False)
    _analyze_parsergroupdef.add_argument('--visualize',action='store_true', help="visualize some artifacts", required=False)
    _analyze_parsergroupdef.add_argument('--flags',action='store_true', help="add countries flags to html", required=False)
    _analyze_parsergroupdef.add_argument('--icons',action='store_true', help="add executable icons to html", required=False)
    _analyze_parsergroupdef.add_argument('--print',action='store_true', help="print output to terminal", required=False)
    _analyze_parsergroupdef.add_argument('--worldmap',action='store_true', help="add world map to html", required=False)
    _analyze_parsergroupdef.add_argument('--image',action='store_true', help="add similarity image to html", required=False)
    _analyze_parsergroupdef.add_argument('--full',action='store_true', help="analyze using all modules", required=False)
    _analyze_parsergroupdeb = _analyze_parser.add_argument_group('Force analysis arguments')
    _analyze_parsergroupdeb.add_argument('--unicode',action='store_true', help="force extracting ascii", required=False)
    _analyze_parsergroupdeb.add_argument('--bigfile',action='store_true', help="force analyze big files", required=False)
    _analyze_parsergroupdeo = _analyze_parser.add_argument_group('Output arguments')
    _analyze_parsergroupdeo.add_argument('--output', help="path of output folder", required=False)
    _analyze_parsergroupdeo.add_argument('--html',action='store_true', help="make html record", required=False)
    _analyze_parsergroupdeo.add_argument('--json',action='store_true', help="make json record", required=False)
    _analyze_parsergroupdeo.add_argument('--open',action='store_true', help="open the report in webbroswer", required=False)

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
        example = '''\nExamples:
    analyze --file /malware/GoziBankerISFB.exe --full --html --json --print --open
    analyze --file /malware/BrRAT.apk --full --json --print
    analyze --folder /malware --full --json --open
    analyze --folder /malware --output /outputfolder --yara --mitre --ocr --json --open
    analyze --buffer "google.com bit.ly" --topurl --html --open
    analyze --buffer "google.com bit.ly" --full --json --print
    '''
        print(example)
    	
    def do_analyze(self,line):
        try:
            parsed = self._analyze_parser.parse_args(ssplit(line))
        except SystemExit:
            return

        if not parsed.output:
            parsed.output = gettempdir()
        if parsed.file or parsed.folder or parsed.buffer:
            if parsed.file:
                self.analyzefile(parsed)
            elif parsed.folder:
                self.analyzefolder(parsed)
            elif parsed.buffer:
                self.analyzebuffer(parsed)
        else:
            logstring("File, Folder or Buffer is missing","Red")

    def analyzefile(self,parsed):
        if path.exists(parsed.file) and path.isfile(parsed.file):
            self.san.analyze(parsed)
        else:
            logstring("Target File/dump is wrong..","Red")

    def analyzefolder(self,parsed):
        if path.exists(parsed.folder) and path.isdir(parsed.folder):
            for f in listdir(parsed.folder):
                fullpath = path.join(parsed.folder, f)
                if path.isfile(fullpath):
                    parsed.file = fullpath
                    self.san.analyze(parsed)
        else:
            logstring("Target folder is wrong..","Red")

    def analyzebuffer(self,parsed):
        if parsed.buffer != "":
            tempname = NamedTemporaryFile().name
            with open(tempname,"w") as tempfile:
                tempfile.write(parsed.buffer)
            parsed.file = tempname
            self.san.analyze(parsed)
        else:
            logstring("Target buffer is empty..","Red")

    def do_exit(self, line):
        return True
        exit()

if __name__ == '__main__':
    QBAnalyzer().cmdloop()