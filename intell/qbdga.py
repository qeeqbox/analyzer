'''
    __G__ = "(G)bd249ce4"
    connection -> dga
'''

from itertools import takewhile
from re import I, findall
from re import compile as rcompile
from re import search as rsearch
from copy import deepcopy
from analyzer.logger.logger import verbose
from analyzer.mics.funcs import get_entropy_float_ret

class QBDGA:
    '''
    QBDGA generates the API references map
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBDGA")
    def __init__(self):
        '''
        Initialize QBDGA, this has to pass
        '''
        self.datastruct = {"Repeated":[],
                           "LowFreqLetters":[],
                           "ConsonantsRow":[],
                           "Consonants":[],
                           "Encryption":[],
                           "Symbols":[],
                           "Numbers":[],
                           "Long":[],
                           "Entropy":[],
                           "_Repeated":["Length", "Repeated"],
                           "_LowFreqLetters":["Count", "Letters", "URL"],
                           "_ConsonantsRow":["Groups", "Row", "URL"],
                           "_Consonants":["Count", "Letters", "URL"],
                           "_Encryption":["Type", "Detected", "URL"],
                           "_Symbols":["Count", "Symbols", "URL"],
                           "_Numbers":["Count", "Numbers", "URL"],
                           "_Long":["Length", "URL"],
                           "_Entropy":["Entropy", "URL"]}

        self.detectionlowfreq = rcompile(r"[vkjxqz]")
        self.detectionconsonantslettersinrow = rcompile(r"[bcdfghjklmnpqrstvwxyz]{4,}")
        self.detectionconsonants = rcompile(r"[bcdfghjklmnpqrstvwxyz]")
        self.detectionhex = rcompile(r'([0-9a-fA-F]{4,})', I)
        self.detectionsymbols = rcompile(r'[_\-~]', I)
        self.detectionnumbers = rcompile(r'[\d]', I)

    @verbose(True, verbose_output=False, timeout=None, _str="DGA-Find repeated patterns")
    def seq_stongrams(self, data, domains):
        '''
        loop sequences, converts sequences to ngrams. map all of them and get thier intersection
        then, return the max item
        '''
        allngrams = []
        temp_var = []
        for domain in domains:
            domain = domain["domain"]
            if len(domain) > 2:
                for length in range(2, len(domain)+1):
                    temp_var.extend([domain[i:i + length] for i in range(len(domain) - length + 1)])
                allngrams.append(temp_var)
                temp_var = []
        common_items = set.intersection(*map(set, allngrams))
        if common_items:
            sortedlist = sorted(common_items, key=len, reverse=True)
            maxvalues = list(takewhile(lambda e: len(e) == len(sortedlist[0]), sortedlist))
            for temp_var in maxvalues:
                data.append({"Length":len(temp_var), "Repeated":temp_var})

    @verbose(True, verbose_output=False, timeout=None, _str="DGA-Find low frequency letters")
    def find_low_freq_letters(self, data, domains):
        '''
        loop sequences, find low frequency letters
        '''
        for domain in domains:
            domain = domain["domain"]
            temp_var = findall(self.detectionlowfreq, domain)
            if len(temp_var) > 4:
                data.append({"Count":len(temp_var), "Letters":''.join(temp_var), "URL":domain})

    @verbose(True, verbose_output=False, timeout=None, _str="DGA-Find consonants letters in row")
    def find_consonants_letters_in_row(self, data, domains):
        '''
        loop sequences, find consonants in row
        '''
        for domain in domains:
            domain = domain["domain"]
            temp_var = findall(self.detectionconsonantslettersinrow, domain)
            if len(temp_var) > 2:
                data.append({"Groups":"{} > 2 groups".format(len(temp_var)), "Row":', '.join(temp_var), "URL":domain})

    @verbose(True, verbose_output=False, timeout=None, _str="DGA-Find consonants letters")
    def find_consonants_letters(self, data, domains):
        '''
        loop sequences, find consonants
        '''
        for domain in domains:
            domain = domain["domain"]
            temp_var = findall(self.detectionconsonants, domain)
            if len(temp_var) > 8:
                data.append({"Count":"{} > 8".format(len(temp_var)), "Letters":''.join(temp_var), "URL":domain})

    @verbose(True, verbose_output=False, timeout=None, _str="DGA-Find encryptions")
    def find_encryption_patterns(self, data, domains):
        '''
        loop sequences, find encryptions
        '''
        for domain in domains:
            domain = domain["domain"]
            detection = rsearch(self.detectionhex, domain)
            if detection is not None:
                temp = ""
                if len(detection.group()) == 32:
                    temp = "md5"
                elif len(detection.group()) == 40:
                    temp = "sha1"
                elif len(detection.group()) == 64:
                    temp = "sha256"
                elif len(detection.group()) == 128:
                    temp = "sha512"
                else:
                    temp = "HEX"

                data.append({"Type":temp, "Detected":detection.group(), "URL":domain})

    @verbose(True, verbose_output=False, timeout=None, _str="DGA-Find symbols")
    def find_all_symbols(self, data, domains):
        '''
        loop sequences, find symbols
        '''
        for domain in domains:
            domain = domain["domain"]
            temp_var = findall(self.detectionsymbols, domain)
            #group them
            if len(temp_var) > 2:
                data.append({"Count":"{} > 2".format(len(temp_var)), "Symbols":''.join(temp_var), "URL":domain})

    @verbose(True, verbose_output=False, timeout=None, _str="DGA-Find numbers")
    def find_all_numbers(self, data, domains):
        '''
        loop sequences, find numbers
        '''
        for domain in domains:
            domain = domain["domain"]
            temp_var = findall(self.detectionnumbers, domain)
            if len(temp_var) > 5:
                data.append({"Count":"{} > 5".format(len(temp_var)), "Numbers":''.join(temp_var), "URL":domain})

    @verbose(True, verbose_output=False, timeout=None, _str="DGA-Find long domains")
    def url_length(self, data, domains):
        '''
        loop sequences, find long domains
        '''
        for domain in domains:
            domain = domain["domain"]
            if len(domain) > 13:
                data.append({"Length":"{} > 13".format(len(domain)), "URL":domain})

    @verbose(True, verbose_output=False, timeout=None, _str="DGA-Get entropies of domains")
    def check_entropy(self, data, domains):
        '''
        loop sequences, get entropy
        '''
        for domain in domains:
            domain = domain["domain"]
            entropy = get_entropy_float_ret(domain)
            if entropy > 3.7:
                data.append({"Entropy":"{0:.15f}".format(entropy), "URL":domain})

    @verbose(True, verbose_output=False, timeout=None, _str="Finding Domain Generational Algorithm patterns")
    def analyze(self, data):
        '''
        start DGA analysis for PCAP
        '''
        data["DGA"] = deepcopy(self.datastruct)
        self.seq_stongrams(data["DGA"]["Repeated"], data["PCAP"]["Domains"])
        self.find_low_freq_letters(data["DGA"]["LowFreqLetters"], data["PCAP"]["Domains"])
        self.find_consonants_letters_in_row(data["DGA"]["ConsonantsRow"], data["PCAP"]["Domains"])
        self.find_consonants_letters(data["DGA"]["Consonants"], data["PCAP"]["Domains"])
        self.find_encryption_patterns(data["DGA"]["Encryption"], data["PCAP"]["Domains"])
        self.find_all_symbols(data["DGA"]["Symbols"], data["PCAP"]["Domains"])
        self.find_all_numbers(data["DGA"]["Numbers"], data["PCAP"]["Domains"])
        self.url_length(data["DGA"]["Long"], data["PCAP"]["Domains"])
        self.check_entropy(data["DGA"]["Entropy"], data["PCAP"]["Domains"])
