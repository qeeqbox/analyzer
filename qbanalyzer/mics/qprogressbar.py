__G__ = "(G)bd249ce4"

from threading import Thread, currentThread, enumerate
from time import sleep
from itertools import cycle
from sys import stdout
from ..logger.logger import logstring,verbose,verbose_flag

t = None

def tprogressbar(str):
    '''
    start wheel in terminal

    Args:
        str: output string before wheel
    '''
    t = currentThread()
    spinner = cycle(['-', '/', '|','\\'])
    if str: logstring(str,"Green")
    while getattr(t,"running", True):
        stdout.write(next(spinner))
        stdout.flush()
        stdout.write('\b')
        sleep(.1)

def progressbar(OnOff=False,str=None):
    '''
    decorator for starting wheel and outputing message

    Args:
        OnOff: future use (not used currently)
        str: output string
    '''
    def decorator(func):
        def wrapper(*args, **kwargs):
            global t
            try:
                #just some hack.. needs to check later on
                if "Running" in [t.name for t in enumerate()]:
                    t.running = False
                    t.join()
                    t = Thread(target=tprogressbar,args=(str,),name="Running")
                    t.start()
                    ret = func(*args, **kwargs)
                    t.running = False
                    t.join()
                    t = Thread(target=tprogressbar,args=("",),name="Running")
                    t.start()
                else:
                    t = Thread(target=tprogressbar,args=(str,),name="Running")
                    t.start()
                    ret = func(*args, **kwargs)
                    t.running = False
                    t.join()
                return ret
            except Exception:
                if t:
                    t.running = False
                    t.join()
        return wrapper
    return decorator
