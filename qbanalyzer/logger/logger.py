__G__ = "(G)bd249ce4"

from logging import DEBUG, ERROR, Formatter, StreamHandler, WARNING, getLogger, handlers
from sys import stdout
from os import path,mkdir

log,verbose_flag = None, None
if log == None:log = getLogger("qbanalyzerlogger")
if verbose_flag == None:verbose_flag = False

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

def logstring(_str,color):
    '''
    output str with color and symbol (they are all as info)
    '''
    stdout.flush()
    if color == "Green": log.info('{}{}{} {}'.format(colors.Green,"X",colors.Restore,_str))
    elif color == "Yellow": log.info('{}{}{} {}'.format(colors.Yellow,">",colors.Restore,_str))
    elif color == "Red": log.info('{}{}{} {}'.format(colors.Red,"!",colors.Restore,_str))

def verbose(OnOff=False,Verb=False,str=None):
    '''
    decorator functions for debugging (show basic args, kwargs)
    '''
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                if Verb:
                    log.info("Function '{0}', parameters : {1} and {2}".format(func.__name__, args, kwargs))
                if str:
                    logstring(str, "Green")
                return func(*args, **kwargs)
            except:
                logstring("{} failed..".format(func.__module__, func.__name__), "Red")
                return None
        return wrapper
    return decorator

def setuplogger():
    loggerpath = path.abspath(path.join(path.dirname( __file__ ),'logs'))
    if not loggerpath.endswith(path.sep): loggerpath = loggerpath+path.sep
    if not path.isdir(loggerpath): mkdir(loggerpath)
    getLogger("scapy.runtime").setLevel(ERROR)
    getLogger("requests").setLevel(WARNING)
    getLogger("urllib3").setLevel(WARNING)
    getLogger("pytesseract").setLevel(WARNING)
    getLogger("PIL").setLevel(WARNING)
    getLogger("chardet").setLevel(WARNING)
    log.setLevel(DEBUG)
    format = Formatter('%(asctime)s %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
    shandler = StreamHandler(stdout)
    shandler.setFormatter(format)
    log.addHandler(shandler)
    fhandler = handlers.RotatingFileHandler(loggerpath+"alllogs", maxBytes=(100*1024*1024), backupCount=3)
    fhandler.setFormatter(format)
    log.addHandler(fhandler)