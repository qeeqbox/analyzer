__G__ = "(G)bd249ce4"

from logging import DEBUG, ERROR, Formatter, StreamHandler, WARNING, getLogger, handlers
from sys import stdout
from os import path,mkdir
from _thread import interrupt_main
from logging import DEBUG, ERROR, Formatter, StreamHandler, WARNING, getLogger, handlers
from sys import stdout,stderr
from os import path,mkdir
from threading import Timer


logterminal,logfile,verbose_flag,verbose_timeout = None,None, None, None
if logterminal == None:logterminal = getLogger("qbanalyzerlogterminal")
if logfile == None:logfile = getLogger("qbanalyzerlogfile")
if verbose_flag == None:verbose_flag = False
if verbose_timeout == None: verbose_timeout = 30

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

def log_string(_str,color):
    '''
    output str with color and symbol (they are all as info)
    '''
    stdout.flush()
    if color == "Green": logterminal.info('{}{}{} {}'.format(colors.Green,"X",colors.Restore,_str))
    elif color == "Yellow": logterminal.info('{}{}{} {}'.format(colors.Yellow,">",colors.Restore,_str))
    elif color == "Red": logterminal.info('{}{}{} {}'.format(colors.Red,"!",colors.Restore,_str))
    elif color == "Yellow_#": logterminal.info('{}{}{} {}'.format(colors.Yellow,"#",colors.Restore,_str))

def verbose(OnOff=False,Verb=False,timeout=30,str=None):
    '''
    decorator functions for debugging (show basic args, kwargs)
    '''    
    def quite(fn,timeout):
        global lock
        stderr.flush()
        interrupt_main()
        lock = fn
        log_string("{} > {}s.. Timeout".format(fn,timeout), "Red")
        #print(">>>>>>>>>>>>>>>>>>" + lock)

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
            #print(chain)
            #print(tenumerate())
            try:
                if Verb:
                    log_string("Function '{0}', parameters : {1} and {2}".format(func.__name__, args, kwargs))
                if str:
                    log_string(str, "Green")
                timer = Timer(timeout, quite, args=[function_name,timeout])
                timer._name = func.__module__+"."+func.__name__
                timer.start()
                ret = func(*args, **kwargs)
            except KeyboardInterrupt:
                pass
            except Exception as e:
                #print(e)
                log_string("{}.{} Failed".format(func.__module__, func.__name__), "Red")
                logfile.info("{}.{} Failed -> {}".format(func.__module__, func.__name__,e))
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
    logterminalgerpath = path.abspath(path.join(path.dirname( __file__ ),'logs'))
    if not logterminalgerpath.endswith(path.sep): logterminalgerpath = logterminalgerpath+path.sep
    if not path.isdir(logterminalgerpath): mkdir(logterminalgerpath)
    getLogger("scapy.runtime").setLevel(ERROR)
    getLogger("requests").setLevel(WARNING)
    getLogger("urllib3").setLevel(WARNING)
    getLogger("pytesseract").setLevel(WARNING)
    getLogger("PIL").setLevel(WARNING)
    getLogger("chardet").setLevel(WARNING)
    logterminal.setLevel(DEBUG)
    format = Formatter('%(asctime)s %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
    shandler = StreamHandler(stdout)
    shandler.setFormatter(format)
    logterminal.addHandler(shandler)
    logfile.setLevel(DEBUG)
    fhandler = handlers.RotatingFileHandler(logterminalgerpath+"alllogterminals", maxBytes=(100*1024*1024), backupCount=3)
    fhandler.setFormatter(format)
    logfile.addHandler(fhandler)