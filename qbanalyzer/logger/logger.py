__G__ = "(G)bd249ce4"

from logging import DEBUG, ERROR, Formatter, StreamHandler, WARNING, getLogger
from sys import stdout

verbose_flag = False

getLogger("scapy.runtime").setLevel(ERROR)
getLogger("requests").setLevel(WARNING)
getLogger("urllib3").setLevel(WARNING)
getLogger("pytesseract").setLevel(WARNING)
getLogger("PIL").setLevel(WARNING)
getLogger("chardet").setLevel(WARNING)

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

#def exceptionhook(exc_type, exc_value, exc_traceback):
#    error(colors.Red + "Uncaught exception" + colors.Restore,exc_info=(exc_type, exc_value, exc_traceback))
#excepthook = exceptionhook

log = getLogger()
log.setLevel(DEBUG)
formatter = Formatter('%(asctime)s %(message)s')
SH = StreamHandler(stdout)
SH.setFormatter(formatter)
log.addHandler(SH)
