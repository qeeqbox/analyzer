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
        self.qbs = qbs
        self.sus = ["encrypt","decrypt","http:","https","sudo","password","pass","admin","loadLibrary","isEmulator"]

    @verbose(verbose_flag)
    def executewithswtich(self,r2p,switch,str):
        s = ""
        if str == "":
            return r2p.cmd(switch + "~+" + str)
        for _ in str:
            s += r2p.cmd(switch + "~+" + _)
        return s

    @verbose(verbose_flag)
    def getallclasses(self,r2p):
        _list = []
        for _ in self.executewithswtich(r2p,"icq","").split("\n"):
            if _ != "":
                _list.append({"Type":"Class","Name":_})
        return _list

    @verbose(verbose_flag)
    def getallexternals(self,r2p):
        _list = []
        for _ in self.executewithswtich(r2p,"iiq","").split("\n"):
            if _ != "":
                _list.append({"Type":"External","Name":_})
        return _list

    @verbose(verbose_flag)
    def getallsymbol(self,r2p):
        _list = []
        for _ in self.executewithswtich(r2p,"isq","").split("\n"):
            if _ != "":
                add,x,name =_.split(" ")
                _list.append({"Type":"Symbol","Address":add,"X":x,"Name":name})
        return _list

    @verbose(verbose_flag)
    def bigfunctions(self,r2p):
        _list = []
        for item in r2p.cmdj("aflj"):
            if item["size"] > 64:
                _list.append({"Size":item["size"],"Name":item["name"]})
                #_list.append(r2p.cmd("pif@"+str(a["offset"])+"~call"))
        return _list

    @verbose(verbose_flag)
    def xref(self,r2p,line):
        x = ""
        try:
            add = line.split(" ")[0]
            int(add, 0)
            x = r2p.cmd("pd 1 @  " + add + "~XREF")
        except:
            pass
        return x

    @verbose(verbose_flag)
    def checksus(self,r2p):
        _list = []
        for _ in self.executewithswtich(r2p,"icq",self.sus).split("\n"):
            for __ in self.xref(r2p,_).split("\n"):
                if _ != "" and __ != "":
                    xref = __[__.rfind(' from ')+1:]
                    _list.append({"Function":_, "Xrefs":xref})
        for _ in self.executewithswtich(r2p,"iiq",self.sus).split("\n"):
            for __ in self.xref(r2p,_).split("\n"):
                if _ != "" and __ != "":
                    xref = __[__.rfind(' from ')+1:]
                    _list.append({"Function":_, "Xrefs":xref})
        for _ in self.executewithswtich(r2p,"isq",self.sus).split("\n"):
            for __ in self.xref(r2p,_).split("\n"):
                if _ != "" and __ != "":
                    xref = __[__.rfind(' from ')+1:]
                    _list.append({"Function":_, "Xrefs":xref})
        return _list

    @verbose(verbose_flag)
    def readpepackage(self,_path):
        return
        with open(_path, 'r',encoding="utf-8") as f:
            data = f.read()
            dom = parseString(data)
            nodes = dom.getElementsByTagName('manifest')
            return nodes[0].getAttribute("package")

    @verbose(verbose_flag)
    def readpermissions(self,_path):
        _list = []
        #samll hack since androidmanifest is compressed
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
    def checkapksig(self,data):
        if  data["Details"]["Properties"]["mime"] == "application/java-archive" or \
            data["Details"]["Properties"]["mime"] == "application/zip":
            if checkpackedfiles(data["Location"]["File"],["Androidmanifest.xml"]):
                unpackfile(data,data["Location"]["File"])
                return True

        #_list = []
        #data = ""
        #with open(_path, 'rb') as f:
        #    data = f.read().decode("utf-8")
        #    dom = parseString(data)
        #    nodes = dom.getElementsByTagName('uses-permission')
        #    for node in nodes:
        #        _list.append({"Permission":node.getAttribute("android:name"),"Description":""})
        #return _list

    @verbose(verbose_flag)
    @progressbar(True,"Analyzing apk file")
    def analyzeapk(self,data):
        data["APK"] = { "General" : {},
                        "Permissions":[],
                        "_General":{},
                        "_Permissions":["Permission","Description"]}
        for i, v in enumerate(data["Packed"]["Files"]):
            if v["Name"].lower() == "androidmanifest.xml":
                self.readpepackage(v["Path"])
                data["APK"]["Permissions"] = self.readpermissions(v["Path"])
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
                            "_Suspicious":["Function","Xrefs"]}
                data[k]["Classes"] = self.getallclasses(r2p)
                data[k]["Externals"] = self.getallexternals(r2p)
                data[k]["Symbols"] = self.getallsymbol(r2p)
                data[k]["Bigfunctions"] = self.bigfunctions(r2p)
                data[k]["Suspicious"] = self.checksus(r2p)
        self.qbs.adddescription("AndroidPermissions",data["APK"]["Permissions"],"Permission")
        words,wordsstripped = getwordsmultifiles(data["Packed"]["Files"])
        data["StringsRAW"] = {"words":words,
                              "wordsstripped":wordsstripped}