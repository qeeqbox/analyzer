__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..modules.filetypes import checkpackedfiles,dmgunpack,unpackfile
from ..mics.funcs import getwordsmultifiles,getwords
from ..intell.qbdescription import adddescription
from r2pipe import open as r2open
from xml.dom.minidom import parseString
from re import sub

class ApkParser:
    @verbose(True,verbose_flag,"Starting ApkParser")
    def __init__(self):
        '''
        initialize class
        '''
        self.sus = ["encrypt","decrypt","http:","https","sudo","password","pass","admin","loadLibrary","isEmulator"]

    @verbose(True,verbose_flag,None)
    def executewithswtich(self,r2p,switch,str) -> list:
        s = ""
        if str == "":
            return r2p.cmd(switch + "~+" + str).split("\n")
        for _ in str:
            s += r2p.cmd(switch + "~+" + _)
        return s.split("\n")

    @verbose(True,verbose_flag,None)
    def xref(self,r2p,line) -> list:
        x = ""
        try:
            add = line.split(" ")[0]
            int(add, 0)
            x = r2p.cmd("pd 1 @  " + add + "~XREF")
        except:
            pass
        return x.split("\n")

    @verbose(True,verbose_flag,None)
    def getallclasses(self,r2p) -> list:
        '''
        get all classes from dex using icq command
        '''
        _list = []
        for _ in self.executewithswtich(r2p,"icq",""):
            if _ != "":
                _list.append({"Type":"Class","Name":_})
        return _list

    @verbose(True,verbose_flag,None)
    def getallexternals(self,r2p) -> list:
        '''
        get all externals from dex using iiq command
        '''
        _list = []
        for _ in self.executewithswtich(r2p,"iiq",""):
            if _ != "":
                _list.append({"Type":"External","Name":_})
        return _list

    @verbose(True,verbose_flag,None)
    def getallsymbol(self,r2p) -> list:
        '''
        get all symbols from dex using isq command
        '''
        _list = []
        for _ in self.executewithswtich(r2p,"isq",""):
            if _ != "":
                add,x,name =_.split(" ")
                _list.append({"Type":"Symbol","Address":add,"X":x,"Name":name})
        return _list

    @verbose(True,verbose_flag,None)
    def bigfunctions(self,r2p) -> list:
        '''
        get all big functions from dex using aflj command
        '''
        _list = []
        for item in r2p.cmdj("aflj"):
            if item["size"] > 64:
                _list.append({"Size":item["size"],"Name":item["name"]})
                #_list.append(r2p.cmd("pif@"+str(a["offset"])+"~call"))
        return _list

    @verbose(True,verbose_flag,None)
    def checksus(self,r2p) -> list:
        '''
        check if suspicious strings in class, externals or symbols
        '''
        _list = []
        for _ in self.executewithswtich(r2p,"icq",self.sus):
            for __ in self.xref(r2p,_):
                if _ != "" and __ != "":
                    xref = __[__.rfind(' from ')+1:]
                    _list.append({"Location":"Classes","Function":_, "Xrefs":xref})
        for _ in self.executewithswtich(r2p,"iiq",self.sus):
            for __ in self.xref(r2p,_):
                if _ != "" and __ != "":
                    xref = __[__.rfind(' from ')+1:]
                    _list.append({"Location":"Externals","Function":_, "Xrefs":xref})
        for _ in self.executewithswtich(r2p,"isq",self.sus):
            for __ in self.xref(r2p,_):
                if _ != "" and __ != "":
                    xref = __[__.rfind(' from ')+1:]
                    _list.append({"Location":"Symbols","Function":_, "Xrefs":xref})
        return _list

    @verbose(True,verbose_flag,None)
    def readpepackage(self,_path) -> str:
        '''
        read apk permission by by xml (if xml is not compressed)
        '''
        with open(_path, 'r',encoding="utf-8") as f:
            data = f.read()
            dom = parseString(data)
            nodes = dom.getElementsByTagName('manifest')
            return nodes[0].getAttribute("package")

    @verbose(True,verbose_flag,None)
    def readpermissions(self,data,_path) -> list:
        '''
        read apk permission by regex..
        '''
        _list = []
        f = data["FilesDumps"][_path]
        text = sub(b'[^\x20-\x7e]{2,}', b' ', f)
        text = sub(b'[^\x20-\x7e]{1,}', b'', text)
        text = sub(b'[^\w\. ]', b'', text)
        words = text.decode("utf-8",errors="ignore").split(" ")
        if words:
            for x in words:
                if "permission." in x:
                    _list.append({"Permission":x,"Description":""})
        return _list

    @verbose(True,verbose_flag,None)
    def checkapksig(self,data) -> bool:
        '''
        check if mime is an apk type or if file contains Androidmanifest in packed files
        '''
        if  data["Details"]["Properties"]["mime"] == "application/java-archive" or \
            data["Details"]["Properties"]["mime"] == "application/zip":
            if checkpackedfiles(data["Location"]["File"],["Androidmanifest.xml"]):
                unpackfile(data,data["Location"]["File"])
                return True

    @verbose(True,verbose_flag,None)
    def checkdexsig(self,data) -> bool:
        '''
        check if mime is a dex
        '''
        if data["Details"]["Properties"]["mime"] == "application/octet-stream" and data["Location"]["Original"].endswith(".dex"):
            return True

    @verbose(True,verbose_flag,"Analyzing DEX file")
    def analyzedex(self,data):
        '''
        start analyzing dex logic (r2p timeout = 10) for individual dex
        add description to strings, get words and wordsstripped from the dex 
        '''
        r2p = r2open(data["Location"]["File"],flags=['-2'])
        r2p.cmd("e anal.timeout = 5")
        r2p.cmd("aaaa;")
        k = 'APK_DEX_1'
        data[k] ={ "Classes":[],
                   "Externals":[],
                    "Symbols":[],
                    "Bigfunctions":[],
                    "Suspicious":[],
                    "_Classes":["Type","Name"],
                    "_Externals":["Type","Name"],
                    "_Symbols":["Type","Address","X","Name"],
                    "_Bigfunctions":["Size","Name"],
                    "_Suspicious":["Location","Function","Xrefs"]}
        data[k]["Classes"] = self.getallclasses(r2p)
        data[k]["Externals"] = self.getallexternals(r2p)
        data[k]["Symbols"] = self.getallsymbol(r2p)
        data[k]["Bigfunctions"] = self.bigfunctions(r2p)
        data[k]["Suspicious"] = self.checksus(r2p)
        getwords(data,data["Location"]["File"])


    @verbose(True,verbose_flag,"Analyzing APK file")
    def analyzeapk(self,data):
        '''
        start analyzing apk logic (r2p timeout = 10) for all dex files
        add description to strings, get words and wordsstripped from the packed files 
        '''
        data["APK"] = { "General" : {},
                        "Permissions":[],
                        "_General":{},
                        "_Permissions":["Permission","Description"]}
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Name"].lower() == "androidmanifest.xml":
                #self.readpepackage(v["Path"])
                data["APK"]["Permissions"] = self.readpermissions(data,v["Path"])
            if "classes" in v["Name"].lower() and v["Name"].lower().endswith(".dex"):
                r2p = r2open(v["Path"],flags=['-2'])
                r2p.cmd("e anal.timeout = 5")
                r2p.cmd("aaaa;")
                k = 'APK_DEX_{}'.format(i)
                data[k] ={ "Classes":[],
                           "Externals":[],
                            "Symbols":[],
                            "Bigfunctions":[],
                            "Suspicious":[],
                            "_Classes":["Type","Name"],
                            "_Externals":["Type","Name"],
                            "_Symbols":["Type","Address","X","Name"],
                            "_Bigfunctions":["Size","Name"],
                            "_Suspicious":["Location","Function","Xrefs"]}
                data[k]["Classes"] = self.getallclasses(r2p)
                data[k]["Externals"] = self.getallexternals(r2p)
                data[k]["Symbols"] = self.getallsymbol(r2p)
                data[k]["Bigfunctions"] = self.bigfunctions(r2p)
                data[k]["Suspicious"] = self.checksus(r2p)
        adddescription("AndroidPermissions",data["APK"]["Permissions"],"Permission")
        getwordsmultifiles(data,data["Packed"]["Files"])