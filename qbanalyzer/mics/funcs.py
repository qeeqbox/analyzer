from ..logger.logger import logstring,verbose,verbose_flag
from math import log
from socket import inet_ntoa,inet_aton
from struct import pack,unpack
from re import findall

@verbose(verbose_flag)
def getentropy(data) -> str:
    '''
    get entropy of buffer

    Args:
        data: buffer
    '''
    entropy = 0
    if len(data) > 0:
        for x in range(0, 256):
            p_x = float(data.count(bytes(x))) / len(data)
            if p_x > 0:
                entropy += - p_x*log(p_x, 2)
        return "%f" % (entropy / 8)
    else:
        return "None"

@verbose(verbose_flag)
def longtoip(decimal) -> str:
    '''
    decimal to ip

    Args:
        decimal: ip in decimal

    Return:
        regular ip
    '''
    return inet_ntoa(pack("!L", decimal))

@verbose(verbose_flag)
def iptolong(ip) -> int:
    '''
    ip to decimal

    Args:
        ip: regular ip

    Return:
        decimal ip
    '''
    return unpack("!L", inet_aton(ip))[0]

@verbose(verbose_flag)
def getwords(data,_path) -> (list,str):
    '''
    get all words of file

    Args:
        _path: path of file

    '''
    words =[]
    wordsinsensitive = []
    wordssensitive = []
    wordsstripped = ""
    words = findall(b"[\x20-\x7e]{4,}",data["FilesDumps"][_path])
    for x in words:
        try:
            wordssensitive.append(x.decode('utf-8',errors="ignore"))
            wordsinsensitive.append(x.lower().decode('utf-8',errors="ignore"))
        except:
            pass
    wordsstripped = ' '.join(wordsinsensitive)
    data["StringsRAW"] = {  "wordssensitive": wordssensitive,
                            "wordsinsensitive": wordsinsensitive,
                            "wordsstripped": wordsstripped }

@verbose(verbose_flag)
def getwordsmultifiles(data,arr) -> (list,str):
    '''
    get all words of multi files

    Args:
        arr: dict contains Path keys
    '''
    words = []
    wordsstripped = ""
    wordsinsensitive = []
    wordssensitive = []
    for x in arr:
        #if x["Path"].endswith(".xml"):
        try:
            words.extend(findall(b"[\x20-\x7e]{4,}",data["FilesDumps"][x["Path"]]))
        except:
            pass
    for x in words:
        try:
            wordssensitive.append(x.decode('utf-8',errors="ignore"))
            wordsinsensitive.append(x.lower().decode('utf-8',errors="ignore"))
        except:
            pass
    wordsstripped = ' '.join(wordsinsensitive)
    data["StringsRAW"] = {  "wordssensitive": wordssensitive,
                            "wordsinsensitive": wordsinsensitive,
                            "wordsstripped": wordsstripped }

@verbose(verbose_flag)
def getwordsmultifilesarray(data,arr) -> (list,str):
    '''
    get all words of buffers in an array

    Args:
        arr: list contains buffer
    '''
    words = []
    wordsstripped = ""
    wordsinsensitive = []
    wordssensitive = []
    for x in arr:
        #if x["Path"].endswith(".xml"):
        try:
            words.extend(findall(b"[\x20-\x7e]{4,}",x))
        except:
            pass
    for x in words:
        try:
            wordssensitive.append(x.decode('utf-8',errors="ignore"))
            wordsinsensitive.append(x.lower().decode('utf-8',errors="ignore"))
        except:
            pass
    wordsstripped = ' '.join(wordsinsensitive)
    data["StringsRAW"] = {  "wordssensitive": wordssensitive,
                            "wordsinsensitive": wordsinsensitive,
                            "wordsstripped": wordsstripped }