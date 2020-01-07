__G__ = "(G)bd249ce4"

from ..logger.logger import verbose, verbose_flag, verbose_timeout
from ..mics.funcs import get_entropy_float_ret
from itertools import takewhile
from re import I, compile, findall, search
from copy import deepcopy

class QBDGA:
    @verbose(True,verbose_flag,verbose_timeout,"Starting QBDGA")
    def __init__(self):
        self.datastruct = {  "Repeated":[],
                             "LowFreqLetters":[],
                             "ConsonantsRow":[],
                             "Consonants":[],
                             "Encryption":[],
                             "Symbols":[],
                             "Numbers":[],
                             "Long":[],
                             "Entropy":[],
                             "_Repeated":["Length","Repeated"],
                             "_LowFreqLetters":["Count","Letters","URL"],
                             "_ConsonantsRow":["Groups","Row","URL"],
                             "_Consonants":["Count","Letters","URL"],
                             "_Encryption":["Type","Detected","URL"],
                             "_Symbols":["Count","Symbols","URL"],
                             "_Numbers":["Count","Numbers","URL"],
                             "_Long":["Length","URL"],
                             "_Entropy":["Entropy","URL"]}

        self.detectionlowfreq = compile(r"[vkjxqz]")
        self.detectionconsonantslettersinrow = compile(r"[bcdfghjklmnpqrstvwxyz]{4,}")
        self.detectionconsonants = compile(r"[bcdfghjklmnpqrstvwxyz]")
        self.detectionhex = compile(r'([0-9a-fA-F]{4,})',I)
        self.detectionsymbols = compile(r'[_\-~]',I)
        self.detectionnumbers = compile(r'[\d]',I)

    @verbose(True,verbose_flag,verbose_timeout,"DGA-Find repeated patterns")
    def seq_stongrams(self,data,domains):
        '''
        loop sequences, converts sequences to ngrams. map all of them and get thier intersection
        then, return the max item
        '''
        try:
            allngrams = []
            l = []
            for domain in domains:
                domain = domain["domain"]
                if len(domain) > 2: 
                    for length in range(2,len(domain)+1):
                        l.extend([domain[i: i + length] for i in range(len(domain) - length + 1)])
                    allngrams.append(l)
                    l = []
            common_items = set.intersection(*map(set, allngrams))
            if common_items:
                sortedlist = sorted(common_items, key=lambda i: len(i), reverse=True)
                maxvalues = list(takewhile(lambda e: len(e) == len(sortedlist[0]), sortedlist))
                for x in maxvalues:
                    data.append({"Length":len(x),"Repeated":x})
        except:
            pass

    @verbose(True,verbose_flag,verbose_timeout,"DGA-Find low frequency letters")
    def find_low_freq_letters(self,data,domains):
        '''
        loop sequences, find low frequency letters 
        '''
        for domain in domains:
            domain = domain["domain"]
            x = findall(self.detectionlowfreq,domain)
            if len(x) > 4:
                data.append({"Count":len(x),"Letters":''.join(x),"URL":domain})

    @verbose(True,verbose_flag,verbose_timeout,"DGA-Find consonants letters in row")
    def find_consonants_letters_in_row(self,data,domains):
        '''
        loop sequences, find consonants in row
        '''
        for domain in domains:
            domain = domain["domain"]
            x = findall(self.detectionconsonantslettersinrow,domain)
            if len(x) > 2:
                data.append({"Groups":"{} > 2 groups".format(len(x)),"Row":','.join(x),"URL":domain})

    @verbose(True,verbose_flag,verbose_timeout,"DGA-Find consonants letters")
    def find_consonants_letters(self,data,domains):
        '''
        loop sequences, find consonants 
        '''
        for domain in domains:
            domain = domain["domain"]
            x = findall(self.detectionconsonants,domain)
            if len(x) > 8:
                data.append({"Count":"{} > 8".format(len(x)),"Letters":''.join(x),"URL":domain})

    @verbose(True,verbose_flag,verbose_timeout,"DGA-Find encryptions")
    def find_encryption_patterns(self,data,domains):
        '''
        loop sequences, find encryptions 
        '''
        for domain in domains:
            domain = domain["domain"]
            detection = search(self.detectionhex, domain)
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

                data.append({"Type":temp,"Detected":detection.group(),"URL":domain})

    @verbose(True,verbose_flag,verbose_timeout,"DGA-Find symbols")
    def find_all_symbols(self,data,domains):
        '''
        loop sequences, find symbols 
        '''
        for domain in domains:
            domain = domain["domain"]
            x = findall(self.detectionsymbols,domain)
            #group them
            if len(x) > 2:
                data.append({"Count":"{} > 2".format(len(x)),"Symbols":''.join(x),"URL":domain})

    @verbose(True,verbose_flag,verbose_timeout,"DGA-Find numbers")
    def find_all_numbers(self,data,domains):
        '''
        loop sequences, find numbers 
        '''
        for domain in domains:
            domain = domain["domain"]
            x = findall(self.detectionnumbers,domain)
            if len(x) > 5:
                data.append({"Count":"{} > 5".format(len(x)),"Numbers":''.join(x),"URL":domain})

    @verbose(True,verbose_flag,verbose_timeout,"DGA-Find long domains")
    def URL_length(self,data,domains):
        '''
        loop sequences, find long domains 
        '''
        for domain in domains:
            domain = domain["domain"]
            if len(domain) > 13:
                data.append({"Length":"{} > 13".format(len(domain)),"URL":domain})

    @verbose(True,verbose_flag,verbose_timeout,"DGA-Get entropies of domains")
    def check_entropy(self,data,domains):
        '''
        loop sequences, get entropy
        '''
        for domain in domains:
            domain = domain["domain"]
            entropy = get_entropy_float_ret(domain)
            if entropy > 3.7:
                data.append({"Entropy":"{0:.15f}".format(entropy),"URL":domain})

    @verbose(True,verbose_flag,verbose_timeout,"Finding Domain Generational Algorithm patterns")
    def analyze(self,data):
        data["DGA"] = deepcopy(self.datastruct)
        self.seq_stongrams(data["DGA"]["Repeated"],data["PCAP"]["Domains"])
        self.find_low_freq_letters(data["DGA"]["LowFreqLetters"],data["PCAP"]["Domains"])
        self.find_consonants_letters_in_row(data["DGA"]["ConsonantsRow"],data["PCAP"]["Domains"])
        self.find_consonants_letters(data["DGA"]["Consonants"],data["PCAP"]["Domains"])
        self.find_encryption_patterns(data["DGA"]["Encryption"],data["PCAP"]["Domains"])
        self.find_all_symbols(data["DGA"]["Symbols"],data["PCAP"]["Domains"])
        self.find_all_numbers(data["DGA"]["Numbers"],data["PCAP"]["Domains"])
        self.URL_length(data["DGA"]["Long"],data["PCAP"]["Domains"])
        self.check_entropy(data["DGA"]["Entropy"],data["PCAP"]["Domains"])
