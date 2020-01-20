__G__ = "(G)bd249ce4"
__V__ = "2020.V.02.12"

print("                                                            ")
print(" _____  __   _  _____        \\   / ______  ______  _____   ")
print("|_____| | \\  | |_____| |      \\_/   ____/ |______ |_____/")
print("|     | |  \\_| |     | |_____  |   /_____ |______ |    \\ {}".format(__V__))
print("                               |  https://github.com/QeeqBox/Analyzer")
print("                                                            ")

from sys import stdout,argv
from os import path,listdir,environ

if __name__ == '__main__':
    if len(argv) == 3:
        if argv[2] == "--local" or argv[2] == "--docker":
            environ["analyzer_env"] = argv[2][2:]
        if argv[1] == "--interactive" or argv[1] == "--silent":
            pass
    else:
        print("Please choose a mode:")
        print("--interactive         Run this framework as an application")
        print("--silent              Run this framework as service (Required an interface for interaction)")
        print()
        print("--local               Use local mongodb")
        print("--docker              Use remote mongodb)")
        print()
        print("Examples:")
        print("python3 -m app.cli --interactive --local")
        print("python3 -m app.cli --silent --docker\n")
        exit()
else:
    exit()

from .analyzer import Analyzer
from .mics.funcs import kill_python_cli,kill_process_and_subs
from .queue.mongoqueue import qbjobqueue
from .queue.mongoworker import qbworker
from .logger.logger import log_string, setup_logger,setup_task_logger,cancel_task_logger
from .report.reporthandler import ReportHandler
from cmd import Cmd
from os import path,listdir,environ
from argparse import ArgumentParser
from shlex import split as ssplit
from requests import get
from tempfile import NamedTemporaryFile,gettempdir
from sys import stdout,argv
from signal import SIGTSTP, signal
from uuid import uuid4
from .settings import json_settings

def ctrlhandler(signum, frame):
    stdout.write("\n")
    log_string("Terminating..","Red")
    kill_process_and_subs()

class Namespace:
    def __init__(self, kwargs):
        self.__dict__.update(kwargs)

class QBAnalyzer(Cmd):
    kill_python_cli()
    setup_logger()
    signal(SIGTSTP, ctrlhandler)
    #signal(SIGINT, ctrlhandler)
    _analyze_parser = ArgumentParser(prog="analyze")
    _analyze_parser._action_groups.pop()
    _analyze_parsergroupreq = _analyze_parser.add_argument_group('Input arguments')
    _analyze_parsergroupreq.add_argument('--file', help="path to file or dump")
    _analyze_parsergroupreq.add_argument('--folder', help="path to folder")
    _analyze_parsergroupreq.add_argument('--buffer', help="input buffer")
    _analyze_parsergroupreq.add_argument('--type', help="force input type")
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
    _analyze_parsergroupdef.add_argument('--worldmap',action='store_true', help="add world map to html", required=False)
    _analyze_parsergroupdef.add_argument('--spelling',action='store_true', help="force spelling check", required=False)
    _analyze_parsergroupdef.add_argument('--image',action='store_true', help="add similarity image to html", required=False)
    _analyze_parsergroupdef.add_argument('--full',action='store_true', help="analyze using all modules", required=False)
    _analyze_parsergroupdef.add_argument('--phishing',action='store_true', help="analyze phishing content", required=False)
    _analyze_parsergroupdef.add_argument('--uuid',help="task id", required=False)
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
    _analyze_parsergroupdeo.add_argument('--disk_dump_html',action='store_true', help="save html record to disk", required=False)
    _analyze_parsergroupdeo.add_argument('--disk_dump_json',action='store_true', help="save json record to disk", required=False)
    _analyze_parsergroupdeo.add_argument('--open',action='store_true', help="open the report in webbroswer", required=False)
    _analyze_parsergroupdef.add_argument('--print_json',action='store_true', help="print output to terminal", required=False)
    _analyze_parsergroupded = _analyze_parser.add_argument_group('Database options')
    _analyze_parsergroupded.add_argument('--db_result',action='store_true',help='save results to db (<16mg)', required=False)
    _analyze_parsergroupded.add_argument('--db_dump_html',action='store_true', help="save html dump tp db", required=False)
    _analyze_parsergroupded.add_argument('--db_dump_json',action='store_true', help="save json dump tp db", required=False)
    _analyze_parsergroupded = _analyze_parser.add_argument_group('Online multiscanner options')
    _analyze_parsergroupded.add_argument('--ms_all',action='store_true', help="check hash in different multiscanner platforms(require API keys)", required=False)
    _analyze_parsergroupdea = _analyze_parser.add_argument_group('Analyzer settings')
    _analyze_parsergroupdea.add_argument('--function_timeout', type=int, help="function logic timeout")
    _analyze_parsergroupdea.add_argument('--analyzer_timeout', type=int, help="analyzer logic timeout")

    def __init__(self,mode):
        super(QBAnalyzer, self).__init__()
        try:
            log_string("Checking updates","Green")
            ver = get("https://raw.githubusercontent.com/qeeqbox/analyzer/master/info")
            if ver.ok and ver.json()["version"] != __V__:
                log_string("New version {} available, please update.. ".format(ver.json()["version"]),"Red")
        except:
            log_string("Update failed","Red")

        self.san = Analyzer()
        self.rep = ReportHandler()

        if mode == "--silent":
            qbjobqueue("jobsqueue",True)
            qbworker("jobsqueue",self.do_analyze,3)
            kill_process_and_subs()
        else:
            self.prompt = "(interactive) "

        #self.do_analyze("--file /home/a8b2bd81cf1e/malware/cmd.exe --full --disk_dump_html --open")

    def help_analyze(self):
        self._analyze_parser.print_help()
        example = '''\nExamples:
    analyze --folder /home/malware --full --disk_dump_html --disk_dump_json --db_dump_html --db_dump_json --open
    analyze --file /malware/2019-12-20-Word-doc-with-macro-for-Emotet.doc --full --db_dump_json --print_json
    analyze --folder /malware --full --db_dump_json --open
    analyze --folder /malware --output /outputfolder --yara --mitre --ocr --disk_dump_json --open
    analyze --buffer "google.com bit.ly" --topurl --db_dump_html --open
    analyze --buffer "google.com bit.ly" --full --print_json
    '''
        print(example)

    def do_analyze(self,line,silent=False):
        try:
            if silent:
                parsed_args = vars(self._analyze_parser.parse_args(""))
                parsed = Namespace({**parsed_args,**line})
                if parsed.uuid:
                    parsed.disk_dump_html = False
                    parsed.disk_dump_json = False
                    parsed.open = False
                    parsed.print = False
                    if not parsed.db_dump_json and not parsed.db_dump_html:
                        parsed.db_dump_json = True
                        parsed.db_dump_html = True
                else:
                    return
            else:
                parsed = self._analyze_parser.parse_args(ssplit(line))
                parsed.uuid = str(uuid4())

            try:
                if int(parsed.analyzer_timeout) > 0 and int(parsed.analyzer_timeout) < 240:
                    json_settings["analyzer_timeout"] = int(parsed.analyzer_timeout)
            except:
                pass
            try:
                if int(parsed.function_timeout) > 0 and int(parsed.function_timeout) < 240:
                    json_settings["function_timeout"] = int(parsed.function_timeout)
            except:
                pass

            log_string("Default timeout {}s for the task, and {}s for each logic".format(json_settings["analyzer_timeout"], json_settings["function_timeout"]),"Yellow")
        except:
            log_string("Parsing failed, something went wrong..","Red")
            return

        log_string("Task {} (Started)".format(parsed.uuid),"Yellow")

        if not parsed.output:
            parsed.output = gettempdir()
        if parsed.file or parsed.folder or parsed.buffer:
            try:
                setup_task_logger(parsed.uuid)
                if parsed.file:
                    self.analyzefile(parsed)
                elif parsed.folder:
                    self.analyzefolder(parsed)
                elif parsed.buffer:
                    self.analyzebuffer(parsed)
            finally:
                cancel_task_logger(parsed.uuid)
        else:
            log_string("File, Folder or Buffer is missing","Red")

        log_string("Task {} (Finished)".format(parsed.uuid),"Green")

    def analyzefile(self,parsed):
        if path.exists(parsed.file) and path.isfile(parsed.file):
            data = self.san.analyze(parsed)
            self.rep.check_output(data,parsed)
        else:
            log_string("Target File/dump is wrong..","Red")

    def analyzefolder(self,parsed):
        if path.exists(parsed.folder) and path.isdir(parsed.folder):
            for f in listdir(parsed.folder):
                fullpath = path.join(parsed.folder, f)
                if path.isfile(fullpath):
                    parsed.file = fullpath
                    data = self.san.analyze(parsed)
                    self.rep.check_output(data,parsed)
                    parsed.extra = ""
        else:
            log_string("Target folder is wrong..","Red")

    def analyzebuffer(self,parsed):
        if parsed.buffer != None:
            tempname = NamedTemporaryFile().name
            with open(tempname,"w") as tempfile:
                tempfile.write(parsed.buffer)
            parsed.file = tempname
            data = self.san.analyze(parsed)
            self.rep.check_output(data,parsed)
        else:
            log_string("Target buffer is empty..","Red")

    def do_exit(self, line):
        exit()

QBAnalyzer(argv[1]).cmdloop()
