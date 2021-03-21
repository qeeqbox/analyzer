'''
    __G__ = "(G)bd249ce4"
    logger -> main
'''

from os import path, environ
from contextlib import contextmanager
from sys import stdout
from datetime import datetime
from tempfile import gettempdir
from logging import DEBUG, Handler, WARNING, getLogger
from gevent import Timeout
from analyzer.settings import json_settings, defaultdb
from analyzer.connections.mongodbconn import add_item_fs, add_item, update_task

LOGTERMINAL, DYNAMIC, VERBOSE_FLAG, VERBOSE_TIMEOUT = None, None, None, None
ENV_VAR = environ["analyzer_env"]

if DYNAMIC is None:
    DYNAMIC = getLogger("analyzerDYNAMIC")
if LOGTERMINAL is None:
    LOGTERMINAL = getLogger("analyzerLOGTERMINAL")
if VERBOSE_FLAG is None:
    VERBOSE_FLAG = False
if VERBOSE_TIMEOUT is None:
    VERBOSE_TIMEOUT = json_settings[ENV_VAR]["function_timeout"]


class TerminalColors:
    '''
    Colors (add more)
    '''
    Restore = '\033[0m'
    Black = "\033[030m"
    Red = "\033[91m"
    Green = "\033[32m"
    Yellow = "\033[33m"
    Blue = "\033[34m"
    Purple = "\033[35m"
    Cyan = "\033[36m"
    White = "\033[37m"


GREEN_X = '{}{}{}'.format(TerminalColors.Green, "X", TerminalColors.Restore)
YELLOW_ARROW = '{}{}{}'.format(TerminalColors.Yellow, ">", TerminalColors.Restore)
EXCLAMATION_MARK = '{}{}{}'.format(TerminalColors.Yellow, "!", TerminalColors.Restore)
RED_ARROW = '{}{}{}'.format(TerminalColors.Red, ">", TerminalColors.Restore)


@contextmanager
def ignore_excpetion(*exceptions):
    '''
    catch excpetion
    '''
    try:
        yield
    except exceptions as error:
        #print("{} {} {}".format(datetime.utcnow(), EXCLAMATION_MARK, error))
        pass


class Unbuffered:
    '''
    unused
    '''

    def __init__(self, stream):
        '''
        unused
        '''
        self.stream = stream

    def write(self, data):
        '''
        write stream and flush (unbuffered)
        '''
        self.stream.write(data)
        self.stream.flush()
        # te.write(data)


class CustomHandler(Handler):
    '''
    custom log handler for adding logs to file as well
    '''

    def __init__(self, file):
        '''
        initialize and prepare the file
        '''
        Handler.__init__(self)
        self.logsfile = open(file, 'w')

    def emit(self, record):
        '''
        override emit
        '''
        print("{} {} {}".format(record.msg[0], record.msg[2], record.msg[1]))
        stdout.flush()
        self.logsfile.write("{} {} {}\n".format(record.msg[0], record.msg[2], record.msg[1]))
        self.logsfile.flush()
        add_item(defaultdb["dbname"], defaultdb["alllogscoll"], {'time': record.msg[0], 'message': record.msg[1]})


class TaskHandler(Handler):
    '''
    task log handler for adding logs to file as well
    '''

    def __init__(self, task):
        '''
        initialize and prepare the file
        '''
        Handler.__init__(self)
        self.logsfile = open(path.join(json_settings[ENV_VAR]["logs_folder"], task), 'w')
        self.task = task

    def emit(self, record):
        '''
        override emit
        '''
        self.logsfile.write("{} {}\n".format(record.msg[0], record.msg[1]))
        self.logsfile.flush()
        update_task(defaultdb["dbname"], defaultdb["taskdblogscoll"], self.task, "{} {}".format(record.msg[0], record.msg[1]))


def setup_task_logger(task):
    '''
    setup the dynamic logger for the task
    '''
    log_string("Setting up task {} logger".format(task), "Yellow")
    add_item(defaultdb["dbname"], defaultdb["taskdblogscoll"], {"task": task, "logs": []})
    DYNAMIC.handlers.clear()
    DYNAMIC.setLevel(DEBUG)
    DYNAMIC.addHandler(TaskHandler(task))
    DYNAMIC.disabled = False


def cancel_task_logger(task):
    '''
    cancel dynamic logger for the task
    '''
    log_string("Closing up task {} logger".format(task), "Yellow")
    DYNAMIC.disabled = True
    logs = ""
    with open(path.join(json_settings[ENV_VAR]["logs_folder"], task), "rb") as file:
        logs = file.read()
    if len(logs) > 0:
        _id = add_item_fs(defaultdb["dbname"], defaultdb["taskfileslogscoll"], logs, "log", None, task, "text/plain", datetime.now())
        if _id:
            log_string("Logs result dumped into db", "Yellow")
        else:
            log_string("Unable to dump logs result to db", "Red")
    else:
        log_string("Unable to dump logs result to db", "Red")


def log_string(_str, color, on_off=True):
    '''
    output str with color and symbol (they are all as info)
    '''
    ctime = datetime.utcnow()
    if color == "Green":
        LOGTERMINAL.info([ctime, _str, GREEN_X])
        DYNAMIC.info([ctime, _str, "X"])
    elif color == "Yellow":
        LOGTERMINAL.info([ctime, _str, YELLOW_ARROW])
        DYNAMIC.info([ctime, _str, ">"])
    elif color == "Red":
        LOGTERMINAL.info([ctime, _str, RED_ARROW])
        DYNAMIC.info([ctime, _str, ">"])
    elif color == "Yellow!":
        LOGTERMINAL.info([ctime, _str, EXCLAMATION_MARK])
        DYNAMIC.info([ctime, _str, "!"])


def verbose(on_off=False, verbose_output=False, timeout=None, _str=None):
    '''
    decorator functions for debugging (show basic args, kwargs)
    '''
    def decorator(func):
        def wrapper(*args, **kwargs):
            result = None
            #global pool
            function_name = func.__module__ + "." + func.__name__
            try:
                if not on_off:
                    log_string(function_name, "Yellow")
                if verbose_output:
                    log_string("Function '{0}', parameters :{1} and {2}".format(func.__name__, args, kwargs), "Yellow")
                if _str:
                    log_string(_str, "Green")
                if _str == "Starting Analyzer":
                    if timeout is None:
                        time = json_settings[ENV_VAR]["analyzer_timeout"]
                    else:
                        time = timeout
                else:
                    if timeout is None:
                        time = json_settings[ENV_VAR]["function_timeout"]
                    else:
                        time = timeout
                try:
                    with Timeout(time):
                        result = func(*args, **kwargs)
                except Timeout:
                    log_string("{} > {}s.. Timeout".format(function_name, time), "Red")
                except Exception as error:
                    log_string("{}.{} Failed -> {}".format(func.__module__, func.__name__, error), "Red")
            except Exception as error:
                log_string("{}.{} Failed -> {}".format(func.__module__, func.__name__, error), "Red")
            return result
        return wrapper
    return decorator


def setup_logger():
    '''
    main logger logic
    '''
    getLogger("requests").setLevel(WARNING)
    getLogger("urllib3").setLevel(WARNING)
    getLogger("PIL").setLevel(WARNING)
    getLogger("chardet").setLevel(WARNING)
    LOGTERMINAL.setLevel(DEBUG)
    LOGTERMINAL.addHandler(CustomHandler(path.join(gettempdir(), "alllogs")))
