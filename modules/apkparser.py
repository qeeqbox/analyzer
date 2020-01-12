__G__ = "(G)bd249ce4"

from ..logger.logger import verbose, verbose_flag, verbose_timeout
from ..modules.archive import check_packed_files, unpack_file
from ..mics.funcs import get_words_multi_files,get_words
from ..intell.qbdescription import add_description
from r2pipe import open as r2open
from xml.dom.minidom import parseString
from re import sub

class ApkParser:
    @verbose(True,verbose_flag,verbose_timeout,"Starting ApkParser")
    def __init__(self):
        '''
        initialize class
        '''
        self.sus = ["encrypt","decrypt","http:","https","sudo","password","pass","admin","loadLibrary","isEmulator"]

    @verbose(True,verbose_flag,verbose_timeout,None)
    def execute_with_swtich(self,r2p,switch,str) -> list:
        s = ""
        if str == "":
            return r2p.cmd(switch + "~+" + str).split("\n")
        for _ in str:
            s += r2p.cmd(switch + "~+" + _)
        return s.split("\n")

    @verbose(True,verbose_flag,verbose_timeout,None)
    def xref(self,r2p,line) -> list:
        x = ""
        try:
            add = line.split(" ")[0]
            int(add, 0)
            x = r2p.cmd("pd 1 @  " + add + "~XREF")
        except:
            pass
        return x.split("\n")

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_all_classes(self,r2p) -> list:
        '''
        get all classes from dex using icq command
        '''
        _list = []
        for _ in self.execute_with_swtich(r2p,"icq",""):
            if _ != "":
                _list.append({"Type":"Class","Name":_})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_all_externals(self,r2p) -> list:
        '''
        get all externals from dex using iiq command
        '''
        _list = []
        for _ in self.execute_with_swtich(r2p,"iiq",""):
            if _ != "":
                _list.append({"Type":"External","Name":_})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_all_symbols(self,r2p) -> list:
        '''
        get all symbols from dex using isq command
        '''
        _list = []
        for _ in self.execute_with_swtich(r2p,"isq",""):
            if _ != "":
                add,x,name =_.split(" ")
                _list.append({"Type":"Symbol","Address":add,"X":x,"Name":name})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def big_functions(self,r2p) -> list:
        '''
        get all big functions from dex using aflj command
        '''
        _list = []
        for item in r2p.cmdj("aflj"):
            if item["size"] > 64:
                _list.append({"Size":item["size"],"Name":item["name"]})
                #_list.append(r2p.cmd("pif@"+str(a["offset"])+"~call"))
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def check_sus(self,r2p) -> list:
        '''
        check if suspicious strings in class, externals or symbols
        '''
        _list = []
        for _ in self.execute_with_swtich(r2p,"icq",self.sus):
            for __ in self.xref(r2p,_):
                if _ != "" and __ != "":
                    xref = __[__.rfind(' from ')+1:]
                    _list.append({"Location":"Classes","Function":_, "Xrefs":xref})
        for _ in self.execute_with_swtich(r2p,"iiq",self.sus):
            for __ in self.xref(r2p,_):
                if _ != "" and __ != "":
                    xref = __[__.rfind(' from ')+1:]
                    _list.append({"Location":"Externals","Function":_, "Xrefs":xref})
        for _ in self.execute_with_swtich(r2p,"isq",self.sus):
            for __ in self.xref(r2p,_):
                if _ != "" and __ != "":
                    xref = __[__.rfind(' from ')+1:]
                    _list.append({"Location":"Symbols","Function":_, "Xrefs":xref})
        return _list

    @verbose(True,verbose_flag,verbose_timeout,None)
    def read_apk_package(self,_path) -> str:
        '''
        read apk permission by by xml (if xml is not compressed)
        '''
        with open(_path, 'r',encoding="utf-8") as f:
            data = f.read()
            dom = parseString(data)
            nodes = dom.getElementsByTagName('manifest')
            return nodes[0].getAttribute("package")

    @verbose(True,verbose_flag,verbose_timeout,None)
    def read_permissions(self,data,_path) -> list:
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

    @verbose(True,verbose_flag,verbose_timeout,None)
    def check_sig_apk(self,data) -> bool:
        '''
        check if mime is an apk type or if file contains Androidmanifest in packed files
        '''
        if  data["Details"]["Properties"]["mime"] == "application/java-archive" or \
            data["Details"]["Properties"]["mime"] == "application/zip":
            if check_packed_files(data["Location"]["File"],["Androidmanifest.xml"]):
                unpack_file(data,data["Location"]["File"])
                return True

    @verbose(True,verbose_flag,verbose_timeout,None)
    def check_sig_dex(self,data) -> bool:
        '''
        check if mime is a dex
        '''
        if data["Details"]["Properties"]["mime"] == "application/octet-stream" and data["Location"]["Original"].endswith(".dex"):
            return True

    @verbose(True,verbose_flag,verbose_timeout,"Analyzing DEX file")
    def analyze_dex(self,data):
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
        data[k]["Classes"] = self.get_all_classes(r2p)
        data[k]["Externals"] = self.get_all_externals(r2p)
        data[k]["Symbols"] = self.get_all_symbols(r2p)
        data[k]["Bigfunctions"] = self.big_functions(r2p)
        data[k]["Suspicious"] = self.check_sus(r2p)
        get_words(data,data["Location"]["File"])

        #future plan; force closing - try,except
        r2p.quit()

    @verbose(True,verbose_flag,verbose_timeout,"Analyzing APK file")
    def analyze_apk(self,data):
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
                data["APK"]["Permissions"] = self.read_permissions(data,v["Path"])
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
                data[k]["Classes"] = self.get_all_classes(r2p)
                data[k]["Externals"] = self.get_all_externals(r2p)
                data[k]["Symbols"] = self.get_all_symbols(r2p)
                data[k]["Bigfunctions"] = self.big_functions(r2p)
                data[k]["Suspicious"] = self.check_sus(r2p)
        add_description("AndroidPermissions",data["APK"]["Permissions"],"Permission")
        get_words_multi_files(data,data["Packed"]["Files"])

        #future plan; force closing - try,except
        r2p.quit()