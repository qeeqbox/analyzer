__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.funcs import getwordsmultifilesarray,getwords,getwordsmultifiles
from ..general.archive import checkpackedfiles,dmgunpack,unpackfile
from re import sub
from magic import from_buffer,Magic
from zlib import decompress
from xml.dom.minidom import parseString
from xml.etree.cElementTree import XML as cetXML

class Officex:
    @verbose(True,verbose_flag,"Starting Officex")
    def __init__(self):
        pass

    @verbose(True,verbose_flag,None)
    def officeanalysis(self,data) -> dict:
        '''
        get hyber links or other links by regex
        '''
        _dict = {"Hyber":[],"Other":[]}
        _temp = {"Hyber":[],"Other":[]}
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Name"].lower().endswith(".xml"):
                try:
                    x = parseString(open(v["Path"]).read()).toprettyxml(indent='  ')
                    for hyber in re.findall('http.*?\<',x):
                        _dict["Hyber"].append(hyber)
                    for hyber in re.findall('(http.*?) ',x):
                        _dict["Other"].append(hyber[:-1]) #-1 for "
                except:
                    pass
        for key in _dict.keys():
            for x in set(_dict[key]):
                _temp[key].append({"Count":_dict[key].count(x),"Link":x})
        return _temp

    @verbose(True,verbose_flag,None)
    def officereadbin(self,data):
        '''
        get all bins from office
        '''
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Name"].lower().endswith(".bin"):
                k = 'Office_bin_{}'.format(i)
                data[k] = { "Bin_Printable":"",
                            "_Bin_Printable":""}
                
                x = open(v["Path"],"r",encoding="utf-8", errors='ignore').read()
                data[k]["Bin_Printable"] = sub(r'[^\x20-\x7F]+','', x)

    @verbose(True,verbose_flag,None)
    def officemetainfo(self,data) -> dict:
        '''
        get office meta data
        '''
        _dict = {}
        corePropNS = '{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}'
        meta = ["filename","title","subject","creator","keywords","description","lastModifiedBy","revision","modified","created"]
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Name"].lower() == "core.xml":
                tree = cetXML(open(v["Path"],"rb").read())
                for item in meta:
                    x = tree.find("{}{}".format(corePropNS,item))
                    if x is not None:
                        _dict.update({item:x.text})
                break
        return _dict

    @verbose(True,verbose_flag,None)
    def checkofficexsig(self,data) -> bool:
        '''
        check if file is office or contains [Content_Types].xml
        '''
        if "application/vnd.openxmlformats-officedocument" in data["Details"]["Properties"]["mime"] or \
            checkpackedfiles(data["Location"]["File"],["[Content_Types].xml"]):
                unpackfile(data,data["Location"]["File"])
                return True


    @verbose(True,verbose_flag,"Analyzing office[x] file")
    def checkofficex(self,data):
        '''
        start analyzing office logic, get office meta informations add description 
        to strings, get words and wordsstripped from the packed files 
        '''
        data["Office"] ={"General":{},
                         "Hyper":[],
                         "Other":[],
                         "_General":{},
                         "_Hyper":["Count","Link"],
                         "_Other":["Count","Link"]}
        data["Office"]["General"] = self.officemetainfo(data)
        data["Office"].update(self.officeanalysis(data))
        self.officereadbin(data)
        getwordsmultifiles(data,data["Packed"]["Files"])
