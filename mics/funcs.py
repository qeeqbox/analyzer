'''
    __G__ = "(G)bd249ce4"
    mics -> global functions
'''

from os import getpid
from socket import inet_ntoa, inet_aton
from struct import pack, unpack
from re import findall
from collections import Counter
from math import log2
from webbrowser import open_new_tab
from tld import get_fld, get_tld
from psutil import process_iter, Process, wait_procs
from analyzer.logger.logger import ignore_excpetion, verbose


def kill_process_and_subs():
    '''
    kill python app
    '''
    proc = Process(getpid())
    subprocs = proc.children()
    for subproc in subprocs:
        subproc.terminate()
    stillalive = wait_procs(subprocs, timeout=2)[1]
    for process in stillalive:
        process.kill()
    proc.kill()


@verbose(True, verbose_output=False, timeout=None, _str=None)
def kill_python_cli():
    '''
    kill python app (needs double check)
    '''
    current = getpid()
    for process in process_iter():
        cmdline = process.cmdline()
        if " ".join(cmdline) == "python3 -m qbanalyzer.cli" and process.pid != current:
            process.kill()


@verbose(True, verbose_output=False, timeout=None, _str=None)
def open_in_browser(_path):
    '''
    open html file in default browser
    '''
    open_new_tab(_path)


@verbose(True, verbose_output=False, timeout=None, _str=None)
def get_entropy(data) -> str:
    '''
    get entropy of buffer
    '''
    with ignore_excpetion(Exception):
        if not data:
            return "0.0 (Minimum: 0.0, Max: 8.0)"
        entropy = 0
        counter = Counter(data)
        temp_len = len(data)
        for count in counter.values():
            temp_var = float(count) / temp_len
            entropy += - temp_var * log2(temp_var)
        return "{} (Minimum: 0.0, Maximum: 8.0)".format(entropy)
    return "None"


@verbose(True, verbose_output=False, timeout=None, _str=None)
def get_entropy_float_ret(data) -> float:
    '''
    get entropy of buffer
    '''
    with ignore_excpetion(Exception):
        if not data:
            return 0.0
        entropy = 0
        counter = Counter(data)
        temp_len = len(data)
        for count in counter.values():
            temp_var = float(count) / temp_len
            entropy += - temp_var * log2(temp_var)
        return entropy
    return 0.0


@verbose(True, verbose_output=False, timeout=None, _str=None)
def get_entropyold(data):
    '''
    get entropy old (wrong do not use)
    '''
    entropy = 0
    probabilities = [float(data.count(char)) / len(data) for char in dict.fromkeys(list(data))]
    entropy = entropy - sum([probability * log2(probability) / log2(2.0) for probability in probabilities])
    return entropy


@verbose(True, verbose_output=False, timeout=None, _str=None)
def long_to_ip(decimal) -> str:
    '''
    decimal to ip
    '''
    return inet_ntoa(pack("!L", decimal))


@verbose(True, verbose_output=False, timeout=None, _str=None)
def ip_to_long(ip_add) -> int:
    '''
    ip to decimal
    '''
    return unpack("!L", inet_aton(ip_add))[0]


@verbose(True, verbose_output=False, timeout=None, _str=None)
def get_words(data, _path) -> (list, str):
    '''
    get all words of file
    '''
    words = []
    wordsinsensitive = []
    wordssensitive = []
    wordsstripped = ""
    encoding = data["Encoding"]["Details"]["ForceEncoding"]
    if encoding == "utf-16":
        words = findall(br"[\x20-\x7e\x00]{4,}", data["FilesDumps"][_path])
    else:
        words = findall(br"[\x20-\x7e]{4,}", data["FilesDumps"][_path])
    for word in words:
        wordssensitive.append(word.decode(encoding, errors="ignore"))
        wordsinsensitive.append(word.lower().decode(encoding, errors="ignore"))

    wordsstripped = '\n' + '\n'.join(wordsinsensitive) + '\n'
    data["StringsRAW"] = {"wordssensitive": wordssensitive,
                          "wordsinsensitive": wordsinsensitive,
                          "wordsstripped": wordsstripped}


@verbose(True, verbose_output=False, timeout=None, _str=None)
def get_words_multi_files(data, arr) -> (list, str):
    '''
    get all words of multi files
    '''
    words = []
    wordsstripped = ""
    wordsinsensitive = []
    wordssensitive = []
    encoding = data["Encoding"]["Details"]["ForceEncoding"]
    for word in arr:
        if encoding == "utf-16":
            words.extend(findall(br"[\x20-\x7e\x00]{4,}", data["FilesDumps"][word["Path"]]))
        else:
            words.extend(findall(br"[\x20-\x7e]{4,}", data["FilesDumps"][word["Path"]]))
    for word in words:
        wordssensitive.append(word.decode(encoding, errors="ignore"))
        wordsinsensitive.append(word.lower().decode(encoding, errors="ignore"))
    wordsstripped = '\n'.join(wordsinsensitive)
    data["StringsRAW"] = {"wordssensitive": wordssensitive,
                          "wordsinsensitive": wordsinsensitive,
                          "wordsstripped": wordsstripped}


@verbose(True, verbose_output=False, timeout=None, _str=None)
def get_words_multi_filesarray(data, arr) -> (list, str):
    '''
    get all words of buffers in an array
    '''
    words = []
    wordsstripped = ""
    wordsinsensitive = []
    wordssensitive = []
    encoding = data["Encoding"]["Details"]["ForceEncoding"]
    for word in arr:
        # if x["Path"].endswith(".xml"):
        if encoding == "utf-16":
            words.extend(findall(br"[\x20-\x7e\x00]{4,}", word))
        else:
            words.extend(findall(br"[\x20-\x7e]{4,}", word))
    for word in words:
        wordssensitive.append(word.decode('utf-8', errors="ignore"))
        wordsinsensitive.append(word.lower().decode('utf-8', errors="ignore"))
    wordsstripped = '\n'.join(wordsinsensitive)
    data["StringsRAW"] = {"wordssensitive": wordssensitive,
                          "wordsinsensitive": wordsinsensitive,
                          "wordsstripped": wordsstripped}


def serialize_obj(obj):
    '''
    recursive str serialization obj
    '''
    with ignore_excpetion(Exception):
        if isinstance(obj, dict):
            for key, value in obj.items():
                obj[key] = serialize_obj(value)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                obj[i] = serialize_obj(item)
        else:
            obj = str(obj)
        return obj


def check_url(url) -> bool:
    '''
    check if url or not
    '''
    with ignore_excpetion(Exception):
        if not url.startswith(("http://", "https://", "ftp://")):
            url = "http://" + url
        if get_tld(url, fail_silently=True):
            root = None
            with ignore_excpetion(Exception):
                root = get_fld(url, fix_protocol=True)
            if root:
                return True
    return False
