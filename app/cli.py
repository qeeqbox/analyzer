__G__ = "(G)bd249ce4"
__V__ = "2020.V.02.02"

from .staticanalyzer import StaticAnalyzer
from .mics.funcs import killpythoncli,killprocessandsubs
from .queue.mongoqueue import qbjobqueue
from .queue.mongoworker import qbworker
from .logger.logger import logstring,verbose,verbose_flag,verbose_timeout,setuplogger
from .report.reporthandler import ReportHandler
from cmd import Cmd
from os import path,listdir
from argparse import ArgumentParser
from shlex import split as ssplit
from requests import get
from tempfile import NamedTemporaryFile,gettempdir
from sys import stdout,argv
from signal import signal,SIGTSTP,SIGINT

def ctrlhandler(signum, frame):
    stdout.write("\n")
    logstring("Terminating..","Red")
    killprocessandsubs()

print("                                                            ")
print(" _____  __   _  _____        \\   / ______  ______  _____   ")
print("|_____| | \\  | |_____| |      \\_/   ____/ |______ |_____/")
print("|     | |  \\_| |     | |_____  |   /_____ |______ |    \\ {}".format(__V__))
print("                               |  https://github.com/QeeqBox/Analyzer")
print("                                                            ")

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
    _analyze_parsergroupdef = _analyze_parser.add_argument_group('Analysis switches')
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
    _analyze_parsergroupdeb = _analyze_parser.add_argument_group('Force analysis switches')
    _analyze_parsergroupdeb.add_argument('--unicode',action='store_true', help="force extracting ascii", required=False)
    _analyze_parsergroupdeb.add_argument('--bigfile',action='store_true', help="force analyze big files", required=False)
    _analyze_parsergroupdew = _analyze_parser.add_argument_group('Whitelist switches')
    _analyze_parsergroupdew.add_argument('--w_internal',action='store_true', help="find it in white list by internal name", required=False)
    _analyze_parsergroupdew.add_argument('--w_original',action='store_true', help="find it in white list by original name", required=False)
    _analyze_parsergroupdew.add_argument('--w_hash',action='store_true', help="find it in white list by hash", required=False)
    _analyze_parsergroupdew.add_argument('--w_words',action='store_true', help="check extracted words against whitelist", required=False)
    _analyze_parsergroupdew.add_argument('--w_all',action='store_true', help="find it in white list", required=False)
    _analyze_parsergroupdeo = _analyze_parser.add_argument_group('Output arguments and switches')
    _analyze_parsergroupdeo.add_argument('--output', help="path of output folder", required=False)
    _analyze_parsergroupdeo.add_argument('--html',action='store_true', help="make html record", required=False)
    _analyze_parsergroupdeo.add_argument('--json',action='store_true', help="make json record", required=False)
    _analyze_parsergroupdeo.add_argument('--open',action='store_true', help="open the report in webbroswer", required=False)
    _analyze_parsergroupded = _analyze_parser.add_argument_group('Database options')
    _analyze_parsergroupded.add_argument('--db_result',action='store_true', help="turn on database option", required=False)
    _analyze_parsergroupded.add_argument('--db_dump',action='store_true', help="turn on database option", required=False)

    def __init__(self,mode):
        super(QBAnalyzer, self).__init__()
        try:
            logstring("Checking updates","Green")
            ver = get("https://raw.githubusercontent.com/qeeqbox/analyzer/master/version")
            if ver.ok and ver.text.strip() != __V__:
                logstring("New version {} available, please update.. ".format(ver.text.strip()),"Red")
        except:
            logstring("Update failed","Red")

        self.san = StaticAnalyzer()
        self.rep = ReportHandler()

        self.do_analyze("--file /home/a8b2bd81cf1e/malware/hello.exe --full --json --db_dump --open")

        if mode == "--silent":
            qbjobqueue("jobsqueue",True)
            qbworker("jobsqueue",self.do_analyze,3)
            killprocessandsubs()
        else:
            self.prompt = "(interactive) "

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
            data = self.san.analyze(parsed)
            self.rep.checkoutput(data,parsed)
        else:
            logstring("Target File/dump is wrong..","Red")

    def analyzefolder(self,parsed):
        if path.exists(parsed.folder) and path.isdir(parsed.folder):
            for f in listdir(parsed.folder):
                fullpath = path.join(parsed.folder, f)
                if path.isfile(fullpath):
                    parsed.file = fullpath
                    data = self.san.analyze(parsed)
                    self.rep.checkoutput(data,parsed)
        else:
            logstring("Target folder is wrong..","Red")

    def analyzebuffer(self,parsed):
        if parsed.buffer != None:
            tempname = NamedTemporaryFile().name
            with open(tempname,"w") as tempfile:
                tempfile.write(parsed.buffer)
            parsed.file = tempname
            data = self.san.analyze(parsed)
            self.rep.checkoutput(data,parsed)
        else:
            logstring("Target buffer is empty..","Red")

    def do_exit(self, line):
        exit()

if __name__ == '__main__':
    if len(argv) == 2:
        if argv[1] == "--interactive" or argv[1] == "--silent": 
            QBAnalyzer(argv[1]).cmdloop()

    print("Please choose a mode:")
    print("--interactive         Run this framework as an application")
    print("--silent              Run this framework as service (Required an interface for interaction)")
    print()
    print("Examples:")
    print("python3 -m app.cli --interactive")
    print("python3 -m app.cli --silent\n")
