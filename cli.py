__G__ = "(G)bd249ce4"

from analyzer.settings import __V__

print("                                                            ")
print(" _____  __   _  _____        \\   / ______  ______  _____   ")
print("|_____| | \\  | |_____| |      \\_/   ____/ |______ |_____/")
print("|     | |  \\_| |     | |_____  |   /_____ |______ |    \\ {}".format(__V__))
print("                               |  https://github.com/QeeqBox/Analyzer")
print("                                                            ")

from sys import stdout,argv
from os import path,listdir,environ
from sys import setswitchinterval

setswitchinterval(0.0000001)

if __name__ == '__main__':
    if len(argv) == 3:
        if argv[2] == "--local" or argv[2] == "--docker":
            environ["analyzer_env"] = argv[2][2:]
    else:
        print("Please choose a mode:")
        print("--local               Use local settings")
        print("--docker              Use remote settings)")
        print()
        print("Examples:")
        print("python3 -m app.cli --silent --docker\n")
        exit()
else:
    exit()

from analyzer.analyzer_ import Analyzer
from analyzer.mics.funcs import kill_python_cli,kill_process_and_subs
from analyzer.redisqueue.qbqueue import QBQueue
from analyzer.logger.logger import log_string, setup_logger,setup_task_logger,cancel_task_logger,clear_pool
from analyzer.report.reporthandler import ReportHandler
from analyzer.settings import json_settings
from analyzer.connections.redisconn import put_cache
from cmd import Cmd
from argparse import ArgumentParser
from shlex import split as ssplit
from tempfile import NamedTemporaryFile,gettempdir
from signal import SIGTSTP, signal
from uuid import uuid4
from time import sleep
from contextlib import redirect_stdout
from io import StringIO
from gc import collect

def ctrlhandler(signum, frame):
    stdout.write("\n")
    log_string("Terminating..","Red")
    kill_process_and_subs()

class Namespace:
    def __init__(self, kwargs,disable_keys,enable_keys):
        for key in disable_keys:
            if key in kwargs:
                kwargs[key] = False
        for key in enable_keys:
            if key in kwargs:
                kwargs[key] = True
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
        self.san = Analyzer()
        self.rep = ReportHandler()
        self.do_cache_switches()

        if mode == "--silent":
            queue = QBQueue("analyzer", host=json_settings[environ["analyzer_env"]]["redis_host"], port=json_settings[environ["analyzer_env"]]["redis_port"], db=0)
            log_string("Waiting on tasks..","Green")
            while True:
                sleep(1)
                task = queue.get()
                if task != None:
                    self.do_analyze(task['data'],True)
                    log_string("Waiting on tasks..","Green")
                    collect()
            kill_process_and_subs()
        else:
            self.prompt = "(testing) " #no more interactive

    def help_analyze(self):
        self._analyze_parser.print_help()

    def do_cache_switches(self):
        try:
            with StringIO() as buf, redirect_stdout(buf):
                self._analyze_parser.print_help()
                output = buf.getvalue()
            #subbed = search(compile(r"Analysis switches\:.*",DOTALL),output).group(0)
            put_cache("switches",output)
            log_string("Dumped switches","Green")
        except:
            log_string("Dumping switches failed","Red")

    def do_analyze(self,line,silent=False):
        try:
            if silent:
                parsed_args = vars(self._analyze_parser.parse_args(""))
                parsed = Namespace({**parsed_args,**line},["disk_dump_html","disk_dump_json","open","print"],["db_dump_json","db_dump_html"])
                if not parsed.uuid:
                    return
            else:
                parsed = self._analyze_parser.parse_args(ssplit(line))
                parsed.uuid = str(uuid4())

            if int(parsed.analyzer_timeout) > 0 and int(parsed.analyzer_timeout) < 240:
                json_settings[environ["analyzer_env"]]["analyzer_timeout"] = int(parsed.analyzer_timeout)
            if int(parsed.function_timeout) > 0 and int(parsed.function_timeout) < 240:
               json_settings[environ["analyzer_env"]]["function_timeout"] = int(parsed.function_timeout)
            if not parsed.output:
                parsed.output = gettempdir()

            log_string("Default timeout {}s for the task, and {}s for each logic".format(json_settings[environ["analyzer_env"]]["analyzer_timeout"],json_settings[environ["analyzer_env"]]["function_timeout"]),"Yellow")
        except:
            log_string("Parsing failed, something went wrong..","Red")
            return

        log_string("Task {} (Started)".format(parsed.uuid),"Yellow")

        if parsed.file or parsed.folder or parsed.buffer:
            try:
                setup_task_logger(parsed.uuid)
                if parsed.file:
                    self.analyze_file(parsed)
                elif parsed.folder:
                    self.analyze_folder(parsed)
                elif parsed.buffer:
                    self.analyze_buffer(parsed)
            finally:
                cancel_task_logger(parsed.uuid)
        else:
            log_string("File, Folder or Buffer is missing","Red")

        log_string("Task {} (Finished)".format(parsed.uuid),"Green")

    def analyze_file(self,parsed):
        if path.exists(parsed.file) and path.isfile(parsed.file):
            clear_pool()
            data = self.san.analyze(parsed)
            clear_pool()
            self.rep.check_output(data,parsed)
            del data
        else:
            log_string("Target File/dump is wrong..","Red")

    def analyze_folder(self,parsed):
        if path.exists(parsed.folder) and path.isdir(parsed.folder):
            for f in listdir(parsed.folder):
                clear_pool()
                fullpath = path.join(parsed.folder, f)
                if path.isfile(fullpath):
                    parsed.file = fullpath
                    data = self.san.analyze(parsed)
                    clear_pool()
                    self.rep.check_output(data,parsed)
                    parsed.extra = ""
                    del data
        else:
            log_string("Target folder is wrong..","Red")

    def analyze_buffer(self,parsed):
        if parsed.buffer != None:
            clear_pool()
            tempname = NamedTemporaryFile().name
            with open(tempname,"w") as tempfile:
                tempfile.write(parsed.buffer)
            parsed.file = tempname
            data = self.san.analyze(parsed)
            clear_pool()
            self.rep.check_output(data,parsed)
            del data
        else:
            log_string("Target buffer is empty..","Red")

    def list_switches(self):
        for x in vars(self._analyze_parser.parse_args("")):
            print("(\'{}\',\'{}\'')".format(x,x))

    def do_exit(self, line):
        exit()

QBAnalyzer(argv[1]).cmdloop()