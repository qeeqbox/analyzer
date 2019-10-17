__G__ = "(G)bd249ce4"

from logging import DEBUG, ERROR, Formatter, StreamHandler, WARNING, getLogger
from sys import stdout
from traceback import format_exc

verbose_flag = False

getLogger("scapy.runtime").setLevel(ERROR)
getLogger("requests").setLevel(WARNING)
getLogger("urllib3").setLevel(WARNING)
getLogger("pytesseract").setLevel(WARNING)
getLogger("PIL").setLevel(WARNING)

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

def logstring(_str,type):
    stdout.flush()
    if type == "Green": log.info('{}{}{} {}'.format(colors.Green,"✓",colors.Restore,_str))
    elif type == "Yellow": log.info('{}{}{} {}'.format(colors.Yellow,"→",colors.Restore,_str))
    elif type == "Red": log.info('{}{}{} {}'.format(colors.Red,"!",colors.Restore,_str))

def verbose(OnOff=False):
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                if OnOff: log.info("Function '{0}', parameters : {1} and {2}".format(func.__name__, args, kwargs))
                x = func(*args, **kwargs)
                if x:
                    return x
            except Exception:
                #print(format_exc())
                logstring("{} failed..".format(func.__name__),"Red")
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
