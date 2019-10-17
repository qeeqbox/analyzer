from ..logger.logger import logstring,verbose,verbose_flag
from math import log
from socket import inet_ntoa,inet_aton
from struct import pack,unpack
from re import findall

@verbose(verbose_flag)
def getentropy(data):
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
def longtoip(ip):
    return inet_ntoa(pack("!L", ip))

@verbose(verbose_flag)
def iptolong(l):
    return unpack("!L", inet_aton(l))[0]

@verbose(verbose_flag)
def getwords(_path):
    words = []
    wordsstripped = ""
    with open(_path,"rb") as f:
        words = findall(b"[\x20-\x7e]{4,}",f.read())
        wordsstripped = ' '.join([x.lower().decode('utf-8') for x in words])
    return words,wordsstripped

@verbose(verbose_flag)
def getwordsmultifiles(arr):
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
def getwordsmultifilesarray(arr):
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