__G__ = "(G)bd249ce4"

from logging import DEBUG, ERROR, Handler, WARNING, getLogger
from os import path
from _thread import interrupt_main
from sys import stdout,stderr
from threading import Timer
from datetime import datetime
from ..settings import json_settings
from ..connections.mongodbconn import add_item_fs,add_item
from tempfile import gettempdir

logterminal,dynamic,verbose_flag,verbose_timeout = None,None, None, None

if dynamic == None:dynamic = getLogger("qbanalyzerdynamic")
if logterminal == None:logterminal = getLogger("qbanalyzerlogterminal")
if verbose_flag == None:verbose_flag = False
if verbose_timeout == None: verbose_timeout = json_settings["function_timeout"]

lock = False
chain = []

class colors:
    Restore = '\033[0m'
    Black="\033[030m"
    Red="\033[91m"
    Green="\033[32m"
    Yellow="\033[33m"
    Blue="\033[34m"
    Purple="\033[35m"
    Cyan="\033[36m"
    White="\033[37m"

green_x = '{}{}{}'.format(colors.Green,"X",colors.Restore)
exclamation_mark = '{}{}{}'.format(colors.Yellow,">",colors.Restore)
red_mark = '{}{}{}'.format(colors.Red,">",colors.Restore)
yellow_hashtag = '{}{}{}'.format(colors.Yellow,"#",colors.Restore)

class Unbuffered:
   def __init__(self, stream):
       self.stream = stream

   def write(self, data):
       self.stream.write(data)
       self.stream.flush()
       te.write(data)

class CustomHandler(Handler):
    def __init__(self,file):
        Handler.__init__(self)
        self.logsfile = open(file,'w')

    def emit(self, record):
        print("{} {} {}".format(record.msg[0], record.msg[2], record.msg[1]))
        stdout.flush()
        self.logsfile.write("{} {} {}\n".format(record.msg[0],record.msg[2],record.msg[1]))
        self.logsfile.flush()
        add_item("analyzer","alllogs",{'time':record.msg[0],'message': record.msg[1]})

class TaskHandler(Handler):
    def __init__(self,task):
        Handler.__init__(self)
        self.logsfile = open(path.join(gettempdir(),task),'w')
        self.task = task

    def emit(self, record):
        self.logsfile.write("{} {}\n".format(record.msg[0],record.msg[1]))
        self.logsfile.flush()
        add_item("analyzer","tasklogs",{'time':record.msg[0],"task":self.task,'message': record.msg[1]})

def setup_task_logger(task):
    log_string("Setting up task {} logger".format(task),"Yellow")
    dynamic.handlers.clear()
    dynamic.setLevel(DEBUG)
    dynamic.addHandler(TaskHandler(task))
    dynamic.disabled = False

def cancel_task_logger(task):
    log_string("Closing up task {} logger".format(task),"Yellow")
    dynamic.disabled = True
    logs = ""
    with open(path.join(gettempdir(),task),"rb") as f:
        logs = f.read()
    if len(logs) > 0:
        _id = add_item_fs("webinterface","logs",logs,"log",None,task,"text/plain",datetime.now())
        if _id:
            log_string("Logs result dumped into db","Yellow")
        else:
            log_string("Unable to dump logs result to db","Red")
    else:
        log_string("Unable to dump logs result to db","Red")

def log_string(_str,color):
    '''
    output str with color and symbol (they are all as info)
    '''
    ctime = datetime.now()
    if color == "Green":
        logterminal.info([ctime,_str,green_x])
        dynamic.info([ctime,_str,"X"])
    elif color == "Yellow":
        logterminal.info([ctime,_str,exclamation_mark])
        dynamic.info([ctime,_str,"!"])
    elif color == "Red":
        logterminal.info([ctime,_str,red_mark])
        dynamic.info([ctime,_str,"!"])
    elif color == "Yellow":
        logterminal.info([ctime,_str,yellow_hashtag])
        dynamic.info([ctime,_str,"#"])

def verbose(OnOff=False,Verb=False,timeout=30,str=None,extra=None):
    '''
    decorator functions for debugging (show basic args, kwargs)
    '''    
    def quite(fn,timeout):
        global lock
        stderr.flush()
        interrupt_main()
        lock = fn
        log_string("{} > {}s.. Timeout".format(fn,timeout), "Red")

    def decorator(func):
        def wrapper(*args, **kwargs):
            global lock
            global chain
            function_name = func.__module__+"."+func.__name__
            if lock:
                return None
            timer = None
            ret = None
            chain.append(function_name)
            try:
                if Verb:
                    log_string("Function '{0}', parameters : {1} and {2}".format(func.__name__, args, kwargs))
                if str:
                    log_string(str, "Green")
                if extra == "analyzer":
                    timer = Timer(json_settings["analyzer_timeout"], quite, args=[function_name,json_settings["analyzer_timeout"]])
                else:
                    timer = Timer(json_settings["function_timeout"], quite, args=[function_name,json_settings["function_timeout"]])
                timer._name = func.__module__+"."+func.__name__
                timer.start()
                ret = func(*args, **kwargs)
            except KeyboardInterrupt:
                pass
            except Exception as e:
                #print(e)
                log_string("{}.{} Failed -> {}".format(func.__module__, func.__name__,e),"Red")
            finally:
                if timer != None:
                    timer.cancel()
            if function_name == chain[-1]:
                if function_name == lock:
                    lock = False
                chain.remove(function_name)
            return ret
        return wrapper
    return decorator

def setup_logger():
    getLogger("scapy.runtime").setLevel(ERROR)
    getLogger("requests").setLevel(WARNING)
    getLogger("urllib3").setLevel(WARNING)
    getLogger("pytesseract").setLevel(WARNING)
    getLogger("PIL").setLevel(WARNING)
    getLogger("chardet").setLevel(WARNING)
    logterminal.setLevel(DEBUG)
    logterminal.addHandler(CustomHandler(path.join(gettempdir(),"alllogs")))
