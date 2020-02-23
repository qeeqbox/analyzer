__G__ = "(G)bd249ce4"

from logging import DEBUG, ERROR, Handler, WARNING, getLogger
from os import path,environ
from sys import stdout
from datetime import datetime
from analyzer.settings import json_settings, defaultdb
from analyzer.connections.mongodbconn import add_item_fs,add_item, update_task
from tempfile import gettempdir
import concurrent.futures as futures
from ctypes import py_object, c_long, pythonapi

logterminal,dynamic,verbose_flag,verbose_timeout = None,None, None, None
env_var = environ["analyzer_env"]
list_executor = []

if dynamic == None:dynamic = getLogger("qbanalyzerdynamic")
if logterminal == None:logterminal = getLogger("qbanalyzerlogterminal")
if verbose_flag == None:verbose_flag = False
if verbose_timeout == None: verbose_timeout = json_settings[env_var]["function_timeout"]

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
        add_item(defaultdb["dbname"],defaultdb["alllogscoll"],{'time':record.msg[0],'message': record.msg[1]})

class TaskHandler(Handler):
    def __init__(self,task):
        Handler.__init__(self)
        self.logsfile = open(path.join(gettempdir(),task),'w')
        self.task = task

    def emit(self, record):
        self.logsfile.write("{} {}\n".format(record.msg[0],record.msg[1]))
        self.logsfile.flush()
        update_task(defaultdb["dbname"],defaultdb["taskdblogscoll"],self.task,"{} {}".format(record.msg[0],record.msg[1]))

def setup_task_logger(task):
    log_string("Setting up task {} logger".format(task),"Yellow")
    add_item(defaultdb["dbname"],defaultdb["taskdblogscoll"],{"task":task,"logs":[]})
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
        _id = add_item_fs(defaultdb["dbname"],defaultdb["taskfileslogscoll"],logs,"log",None,task,"text/plain",datetime.now())
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
    ctime = datetime.utcnow()
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

def terminate_thread(thread):
    if not thread.isAlive():
        return
    res = pythonapi.PyThreadState_SetAsyncExc(c_long(thread.ident), py_object(SystemExit))
    if res == 0:
        raise ValueError("No thread ID")
    elif res > 1:
        pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)
        raise SystemError("Failed")

def verbose(OnOff=False,Verb=False,timeout=None,str=None,extra=None):
    '''
    decorator functions for debugging (show basic args, kwargs)
    '''    
    def decorator(func):
        def wrapper(*args, **kwargs):
            result = None
            executor_temp = None 
            global list_executor
            function_name = func.__module__+"."+func.__name__
            try:
                if Verb:
                    log_string("Function '{0}', parameters : {1} and {2}".format(func.__name__, args, kwargs))
                if str:
                    log_string(str, "Green")
                if extra == "analyzer":
                    time = json_settings[env_var]["analyzer_timeout"]
                else:
                    time = json_settings[env_var]["function_timeout"]
                with futures.ThreadPoolExecutor() as executor:
                    executor_temp = executor
                    list_executor.append(executor)
                    future = executor.submit(func, *args, **kwargs)
                    try:
                        result = future.result(time)
                        executor.shutdown(wait=False)
                        executor._threads.clear()
                        futures.thread._threads_queues.clear()
                    except futures.TimeoutError:
                        try:
                            log_string("{} > {}s.. Timeout".format(function_name,time), "Red")
                            for executor in list_executor:
                                #if executor_temp != executor:
                                #    for thread in executor._threads:    
                                #        terminate_thread(thread)
                                executor.shutdown(wait=False)
                                executor._threads.clear()
                                futures.thread._threads_queues.clear()
                            list_executor = []
                        except:
                            log_string("Wrapper failed..", "Red")
                if executor_temp in list_executor:
                    list_executor.remove(executor_temp)
            except Exception as e:
                log_string("{}.{} Failed -> {}".format(func.__module__, func.__name__,e),"Red")
            return result
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