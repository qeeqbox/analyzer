'''
    __G__ = "(G)bd249ce4"
    modules -> office
'''

from re import sub, findall
from xml.dom.minidom import parseString
from xml.etree.cElementTree import XML as cetXML
from copy import deepcopy
from oletools.olevba3 import VBA_Parser
from analyzer.logger.logger import ignore_excpetion, verbose
from analyzer.mics.funcs import get_words_multi_files
from analyzer.modules.archive import check_packed_files, unpack_file

class Officex:
    '''
    Officex extracts artifacts from office files
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting Officex")
    def __init__(self):
        '''
        initialize class and datastruct, this has to pass
        '''
        self.datastruct = {"General":{},
                           "Text":"",
                           "Hyper":[],
                           "Other":[],
                           "Macro":[],
                           "DDE":[],
                           "_General":{},
                           "_Text":"",
                           "_Hyper":["Count", "Link"],
                           "_Other":["Count", "Link"],
                           "_Macro":["Name", "VBA"],
                           "_DDE":""}

        self.word_namespace = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
        self.para = self.word_namespace + 'p'
        self.text = self.word_namespace + 't'
        self.instrtext = self.word_namespace + 'instrText'

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def office_analysis(self, data) -> dict:
        '''
        get hyber links or other links by regex
        '''
        temp_dict = {"Hyber":[], "Other":[]}
        _temp = {"Hyber":[], "Other":[]}
        for index, temp_var in enumerate(data["Packed"]["Files"]):
            if temp_var["Name"].lower().endswith(".xml"):
                with ignore_excpetion(Exception):
                    temp_x = parseString(open(temp_var["Path"]).read()).toprettyxml(indent='  ')
                    for hyber in findall(r'http.*?\<', temp_x):
                        temp_dict["Hyber"].append(hyber)
                    for hyber in findall(r'(http.*?) ', temp_x):
                        temp_dict["Other"].append(hyber[:-1]) #-1 for "
        for key in temp_dict:
            for temp_x in set(temp_dict[key]):
                _temp[key].append({"Count":temp_dict[key].count(temp_x), "Link":temp_x})
        return _temp

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def office_read_bin(self, data):
        '''
        get all bins from office
        '''
        for index, temp_var in enumerate(data["Packed"]["Files"]):
            if temp_var["Name"].lower().endswith(".bin"):
                temp_k = 'Office_bin_{}'.format(index)
                data[temp_k] = {"Bin_Printable":"",
                                "_Bin_Printable":""}
                temp_x = open(temp_var["Path"], "r", encoding="utf-8", errors='ignore').read()
                data[temp_k]["Bin_Printable"] = sub(r'[^\x20-\x7F]+', '', temp_x)

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def office_meta_info(self, data) -> dict:
        '''
        get office meta data
        '''
        temp_dict = {}
        corepropns = '{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}'
        meta = ["filename", "title", "subject", "creator", "keywords", "description", "lastModifiedBy", "revision", "modified", "created"]
        for index, temp_var in enumerate(data["Packed"]["Files"]):
            if temp_var["Name"].lower() == "core.xml":
                tree = cetXML(open(temp_var["Path"], "rb").read())
                for item in meta:
                    temp_x = tree.find("{}{}".format(corepropns, item))
                    if temp_x is not None:
                        temp_dict.update({item:temp_x.text})
                break
        return temp_dict

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def extract_text(self, data) -> str:
        '''
        Extract text
        '''
        text = []
        for index, temp_var in enumerate(data["Packed"]["Files"]):
            if temp_var["Name"].lower() == "document.xml":
                tree = cetXML(open(temp_var["Path"], "rb").read())
                print(tree)
                for par in tree.iter(self.para):
                    text.append(''.join(node.text for node in par.iter(self.text)))
        return '\n'.join(text)

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def extract_dde(self, data) -> str:
        '''
        Extract dde
        '''
        text = []
        for index, temp_var in enumerate(data["Packed"]["Files"]):
            if temp_var["Name"].lower() == "document.xml":
                tree = cetXML(open(temp_var["Path"], "rb").read())
                for par in tree.iter(self.para):
                    string = ''.join(node.text for node in par.iter(self.instrtext))
                    if len(string) > 0:
                        text.append(string)
        return '\n'.join(text)

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def extract_macros(self, path) -> list:
        '''
        Extract macros
        '''
        temp_list = []
        with ignore_excpetion(Exception):
            for (temp_f, temp_s, vbaname, vbacode) in VBA_Parser(path).extract_macros():
                temp_list.append({"Name":vbaname, "VBA":vbacode})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig(self, data) -> bool:
        '''
        check if file is office or contains [Content_Types].xml
        '''
        if "application/vnd.openxmlformats-officedocument" in data["Details"]["Properties"]["mime"] or \
            check_packed_files(data["Location"]["File"], ["[Content_Types].xml"]):
            unpack_file(data, data["Location"]["File"])
            return True
        return False


    @verbose(True, verbose_output=False, timeout=None, _str="Analyzing office[x] file")
    def analyze(self, data):
        '''
        start analyzing office logic, get office meta informations add description
        to strings, get words and wordsstripped from the packed files
        '''
        data["Office"] = deepcopy(self.datastruct)
        data["Office"]["General"] = self.office_meta_info(data)
        data["Office"]["Text"] = self.extract_text(data)
        data["Office"]["DDE"] = self.extract_dde(data)
        data["Office"]["Macro"] = self.extract_macros(data["Location"]["File"])
        data["Office"].update(self.office_analysis(data))
        self.office_read_bin(data)
        get_words_multi_files(data, data["Packed"]["Files"])
