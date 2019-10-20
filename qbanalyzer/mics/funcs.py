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
def getwords(_path) -> (list,str):
    '''
    get all words of file

    Args:
        _path: path of file

    Return:
        list of all words in the file
        buffer contains all the words separated by spaces
    '''
    words = []
    wordsstripped = ""
    with open(_path,"rb") as f:
        words = findall(b"[\x20-\x7e]{4,}",f.read())
        wordsstripped = ' '.join([x.lower().decode('utf-8') for x in words])
    return words,wordsstripped

@verbose(verbose_flag)
def getwordsmultifiles(arr) -> (list,str):
    '''
    get all words of multi files

    Args:
        arr: dict contains Path keys

    Return:
        list of all words in the file
        buffer contains all the words separated by spaces
    '''
    words = []
    _templist = []
    wordsstripped = ""
    for x in arr:
        #if x["Path"].endswith(".xml"):
        try:
            with open(x["Path"],"rb") as f:
                words.extend(findall(b"[\x20-\x7e]{4,}",f.read()))
        except:
            pass
    for x in words:
        try:
            _templist.append(x.lower().decode('utf-8'))
        except:
            pass
    wordsstripped = ' '.join(_templist)
    return words,wordsstripped

@verbose(verbose_flag)
def getwordsmultifilesarray(arr) -> (list,str):
    '''
    get all words of buffers in an array

    Args:
        arr: list contains buffer

    Return:
        list of all words in the file
        buffer contains all the words separated by spaces
    '''
    words = []
    _templist = []
    wordsstripped = ""
    for x in arr:
        #if x["Path"].endswith(".xml"):
        try:
            words.extend(findall(b"[\x20-\x7e]{4,}",x))
        except:
            pass
    for x in words:
        try:
            _templist.append(x.lower().decode('utf-8'))
        except:
            pass
    wordsstripped = ' '.join(_templist)
    return words,wordsstripped