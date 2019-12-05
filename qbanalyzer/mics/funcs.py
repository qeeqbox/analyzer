from ..logger.logger import logstring,verbose,verbose_flag
from socket import inet_ntoa,inet_aton
from struct import pack,unpack
from re import findall
from collections import Counter
from math import log2

@verbose(True,verbose_flag,None)
def getentropy(data) -> str:
    '''
    get entropy of buffer
    '''
    try:
        if not data:
            return "0.0 (Minimum: 0.0, Max: 8.0)"
        entropy = 0
        counter = Counter(data)
        l = len(data)
        for count in counter.values():
            p_x = float(count) / l
            entropy += - p_x * log2(p_x)
        return "{} (Minimum: 0.0, Maximum: 8.0)".format(entropy)
    except:
        return "None"

@verbose(True,verbose_flag,None)
def getentropyfloatret(data) -> float:
    '''
    get entropy of buffer
    '''
    try:
        if not data:
            return 0.0
        entropy = 0
        counter = Counter(data)
        l = len(data)
        for count in counter.values():
            p_x = float(count) / l
            entropy += - p_x * log2(p_x)
        return entropy
    except:
        return 0.0

@verbose(True,verbose_flag,None)
def getentropyold(data):
    probabilities = [float(data.count(char)) / len(data) for char in dict.fromkeys(list(data))]
    entropy =- sum([probability * log2(probability) / log2(2.0) for probability in probabilities])
    return entropy

@verbose(True,verbose_flag,None)
def longtoip(decimal) -> str:
    '''
    decimal to ip
    '''
    return inet_ntoa(pack("!L", decimal))

@verbose(True,verbose_flag,None)
def iptolong(ip) -> int:
    '''
    ip to decimal
    '''
    return unpack("!L", inet_aton(ip))[0]

@verbose(True,verbose_flag,None)
def getwords(data,_path) -> (list,str):
    '''
    get all words of file
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
    wordsstripped = '\n'+'\n'.join(wordsinsensitive) + '\n'
    data["StringsRAW"] = {  "wordssensitive": wordssensitive,
                            "wordsinsensitive": wordsinsensitive,
                            "wordsstripped": wordsstripped }

@verbose(True,verbose_flag,None)
def getwordsmultifiles(data,arr) -> (list,str):
    '''
    get all words of multi files
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
    wordsstripped = '\n'.join(wordsinsensitive)
    data["StringsRAW"] = {  "wordssensitive": wordssensitive,
                            "wordsinsensitive": wordsinsensitive,
                            "wordsstripped": wordsstripped }

@verbose(True,verbose_flag,None)
def getwordsmultifilesarray(data,arr) -> (list,str):
    '''
    get all words of buffers in an array
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
    wordsstripped = '\n'.join(wordsinsensitive)
    data["StringsRAW"] = {  "wordssensitive": wordssensitive,
                            "wordsinsensitive": wordsinsensitive,
                            "wordsstripped": wordsstripped }