__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from ...modules.files.filetypes import checkpackedfiles,dmgunpack,unpackfile
from ...mics.funcs import getwordsmultifiles
from r2pipe import open as r2open
from xml.dom.minidom import parseString
from re import sub

#needs cheching..

class ApkParser:
    @verbose(verbose_flag)
    @progressbar(True,"Starting ApkParser")
    def __init__(self,qbs):
        '''
        initialize class

        Args:
            qbs: is QBStrings class, needed for string description
        '''
        self.qbs = qbs
        self.sus = ["encrypt","decrypt","http:","https","sudo","password","pass","admin","loadLibrary","isEmulator"]

    @verbose(verbose_flag)
    def executewithswtich(self,r2p,switch,str) -> list:
        s = ""
        if str == "":
            return r2p.cmd(switch + "~+" + str).split("\n")
        for _ in str:
            s += r2p.cmd(switch + "~+" + _)
        return s.split("\n")

    @verbose(verbose_flag)
    def xref(self,r2p,line) -> list:
        x = ""
        try:
            add = line.split(" ")[0]
            int(add, 0)
            x = r2p.cmd("pd 1 @  " + add + "~XREF")
        except:
            pass
        return x.split("\n")

    @verbose(verbose_flag)
    def getallclasses(self,r2p) -> list:
        '''
        get all classes from dex using icq command

        Args:
            r2p: r2p object

        Return:
            _list: list of classes and their names
        '''
        _list = []
        for _ in self.executewithswtich(r2p,"icq",""):
            if _ != "":
                _list.append({"Type":"Class","Name":_})
        return _list

    @verbose(verbose_flag)
    def getallexternals(self,r2p) -> list:
        '''
        get all externals from dex using iiq command

        Args:
            r2p: r2p object

        Return:
            _list: list of externals and their names
        '''
        _list = []
        for _ in self.executewithswtich(r2p,"iiq",""):
            if _ != "":
                _list.append({"Type":"External","Name":_})
        return _list

    @verbose(verbose_flag)
    def getallsymbol(self,r2p) -> list:
        '''
        get all symbols from dex using isq command

        Args:
            r2p: r2p object

        Return:
            _list: list of Symbols and their info
        '''
        _list = []
        for _ in self.executewithswtich(r2p,"isq",""):
            if _ != "":
                add,x,name =_.split(" ")
                _list.append({"Type":"Symbol","Address":add,"X":x,"Name":name})
        return _list

    @verbose(verbose_flag)
    def bigfunctions(self,r2p) -> list:
        '''
        get all big functions from dex using aflj command

        Args:
            r2p: r2p object

        Return:
            _list: list of big functions and their info
        '''
        _list = []
        for item in r2p.cmdj("aflj"):
            if item["size"] > 64:
                _list.append({"Size":item["size"],"Name":item["name"]})
                #_list.append(r2p.cmd("pif@"+str(a["offset"])+"~call"))
        return _list

    @verbose(verbose_flag)
    def checksus(self,r2p) -> list:
        '''
        check if suspicious strings in class, externals or symbols

        Args:
            r2p: r2p object

        Return:
            _list: list of big xref suspicious strings and their locations
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

    @verbose(verbose_flag)
    def readpepackage(self,_path) -> str:
        '''
        read apk permission by by xml (if xml is not compressed)

        Args:
            _path: path to Androidmanifest

        Return:
            Name of packege 
        '''
        with open(_path, 'r',encoding="utf-8") as f:
            data = f.read()
            dom = parseString(data)
            nodes = dom.getElementsByTagName('manifest')
            return nodes[0].getAttribute("package")

    @verbose(verbose_flag)
    def readpermissions(self,_path) -> list:
        '''
        read apk permission by regex..

        Args:
            _path: path to Androidmanifest

        Return:
            List of parsed permissions 
        '''
        _list = []
        with open(_path,"rb") as f:
            text = sub(b'[^\x20-\x7e]{2,}', b' ', f.read())
            text = sub(b'[^\x20-\x7e]{1,}', b'', text)
            text = sub(b'[^\w\. ]', b'', text)
            words = text.decode("utf-8").split(" ")
            if words:
                for x in words:
                    if "permission." in x:
                        _list.append({"Permission":x,"Description":""})
        return _list


    @verbose(verbose_flag)
    def checkapksig(self,data) -> bool:
        '''
        check if mime is an apk type or if file contains Androidmanifest in packed files

        Args:
            data: data dict

        Return:
            True if apk
        '''
        if  data["Details"]["Properties"]["mime"] == "application/java-archive" or \
            data["Details"]["Properties"]["mime"] == "application/zip":
            if checkpackedfiles(data["Location"]["File"],["Androidmanifest.xml"]):
                unpackfile(data,data["Location"]["File"])
                return True

    @verbose(verbose_flag)
    @progressbar(True,"Analyzing apk file")
    def analyzeapk(self,data):
        '''
        start analyzing apk logic (r2p timeout = 10) for all dex files
        add description to strings, get words and wordsstripped from the packed files 

        Args:
            data: data dict
        '''
        data["APK"] = { "General" : {},
                        "Permissions":[],
                        "_General":{},
                        "_Permissions":["Permission","Description"]}
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Name"].lower() == "androidmanifest.xml":
                #self.readpepackage(v["Path"])
                Permissions = self.readpermissions(v["Path"])
                data["APK"]["Permissions"] = Permissions
            if "classes" in v["Name"].lower() and v["Name"].lower().endswith(".dex"):
                r2p = r2open(v["Path"],flags=['-2'])
                r2p.cmd("e anal.timeout = 10")
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
                Classes = self.getallclasses(r2p)
                Externals = self.getallexternals(r2p)
                Symbols = self.getallsymbol(r2p)
                Bigfunctions = self.bigfunctions(r2p)
                Suspicious = self.checksus(r2p)
                data[k]["Classes"] = Classes
                data[k]["Externals"] = Externals
                data[k]["Symbols"] = Symbols
                data[k]["Bigfunctions"] = Bigfunctions
                data[k]["Suspicious"] = Suspicious
        self.qbs.adddescription("AndroidPermissions",data["APK"]["Permissions"],"Permission")
        words,wordsstripped = getwordsmultifiles(data["Packed"]["Files"])
        data["StringsRAW"] = {"words":words,
                              "wordsstripped":wordsstripped}
