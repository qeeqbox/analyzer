__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.funcs import getwordsmultifilesarray,getwords
from re import DOTALL, MULTILINE, compile, findall
from magic import from_buffer,Magic
from zlib import decompress

class PDFParser:
    @verbose(True,verbose_flag,"Starting PDFParser")
    def __init__(self):
        self.Objectsdetection = compile(b'(\d+\s\d)+\sobj([\s\S]*?\<\<([\s\S]*?))endobj',DOTALL|MULTILINE)
        self.Streamdetection = compile(b'.*?FlateDecode.*?stream(.*?)endstream', DOTALL|MULTILINE)
        self.jsdetection = compile(b'/JS([\S][^>]+)',DOTALL|MULTILINE)
        self.javascriptdetection = compile(b'/JavaScript([\S][^>]+)',DOTALL|MULTILINE)
        self.OpenActiondetection = compile(b'/OpenAction([\S][^>]+)',DOTALL|MULTILINE)
        self.Launchdetection = compile(b'/Launch([\S][^>]+)',DOTALL|MULTILINE)
        self.URIdetection = compile(b'/URI([\S][^>]+)',DOTALL|MULTILINE)
        self.Actiondetection = compile(b'/Action([\S][^>]+)',DOTALL|MULTILINE)
        self.GoToRdetection = compile(b'/GoToR([\S][^>]+)',DOTALL|MULTILINE)
        self.RichMediadetection = compile(b'/RichMedia([\S][^>]+)',DOTALL|MULTILINE)
        self.AAdetection = compile(b'/AA([\S][^>]+)',DOTALL|MULTILINE)

    @verbose(True,verbose_flag,None)
    def getobject(self,pdf) -> (str,list):
        '''
        get objects from pdf by regex
        '''
        _List = []
        Objects = findall(self.Objectsdetection,pdf)
        for _ in Objects:
            _List.append({"Object":_[0].decode("utf-8",errors="ignore"),"Value":_[1].decode('utf-8',errors="ignore")})
        return len(Objects),_List

    @verbose(True,verbose_flag,None)
    def getstream(self,pdf) -> (str,list,list):
        '''
        get streams from pdf by regex
        '''
        _List = []
        _Streams = []
        Streams = findall(self.Streamdetection,pdf)
        for _ in Streams:
            parsed = None
            parseddecode = None
            x = _.strip(b"\r").strip(b"\n")
            mime = from_buffer(x,mime=True)
            if mime == "application/zlib":
                parsed = decompress(x)
                parseddecode = parsed.decode("utf-8",errors="ignore")
                _Streams.append(parsed)
            _List.append({"Stream":mime,"Parsed":parseddecode,"Value":x.decode('utf-8',errors="ignore")})
        return len(Streams),_List,_Streams

    @verbose(True,verbose_flag,None)
    def getjs(self,pdf) -> (str,list):
        '''
        get JS from pdf by regex
        '''
        _List = []
        jslist = findall(self.jsdetection,pdf)
        for _ in jslist:
            _List.append({"Key":"/JS","Value":_.decode("utf-8",errors="ignore")})
        return len(jslist),_List

    @verbose(True,verbose_flag,None)
    def getjavascript(self,pdf) -> (str,list):
        '''
        get JavaScript from pdf by regex
        '''
        _List = []
        Javascriptlist = findall(self.javascriptdetection,pdf)
        for _ in Javascriptlist:
            _List.append({"Key":"/JavaScript","Value":_.decode("utf-8",errors="ignore")})
        return len(Javascriptlist),_List

    @verbose(True,verbose_flag,None)
    def getopenaction(self,pdf) -> (str,list):
        '''
        get openactions from pdf by regex
        '''
        _List = []
        OpenActionlist = findall(self.OpenActiondetection,pdf)
        for _ in OpenActionlist:
            _List.append({"Key":"/OpenAction","Value":_.decode("utf-8",errors="ignore")})
        return len(OpenActionlist),_List

    @verbose(True,verbose_flag,None)
    def getlunch(self,pdf) -> (str,list):
        '''
        get Launch from pdf by regex
        '''
        _List = []
        Launchlist = findall(self.Launchdetection,pdf)
        for _ in Launchlist:
            _List.append({"Key":"/Launch","Value":_.decode("utf-8",errors="ignore")})
        return len(Launchlist),_List

    @verbose(True,verbose_flag,None)
    def geturi(self,pdf) -> (str,list):
        '''
        get URI from pdf by regex
        '''
        _List = []
        URIlist = findall(self.URIdetection,pdf)
        for _ in URIlist:
            _List.append({"Key":"/URI","Value":_.decode("utf-8",errors="ignore")})
        return len(URIlist),_List

    @verbose(True,verbose_flag,None)
    def getaction(self,pdf) -> (str,list):
        '''
        get Action from pdf by regex
        '''
        _List = []
        Actionlist = findall(self.Actiondetection,pdf)
        for _ in Actionlist:
            _List.append({"Key":"/Action","Value":_.decode("utf-8",errors="ignore")})
        return len(Actionlist),_List

    @verbose(True,verbose_flag,None)
    def getgotor(self,pdf) -> (str,list):
        '''
        get GoToR from pdf by regex
        '''
        _List = []
        Gotorlist = findall(self.GoToRdetection,pdf)
        for _ in Gotorlist:
            _List.append({"Key":"/GoToR","Value":_.decode("utf-8",errors="ignore")})
        return len(Gotorlist),_List


    @verbose(True,verbose_flag,None)
    def getrichmedia(self,pdf) -> (str,list):
        '''
        get RichMedia from pdf by regex
        '''
        _List = []
        Richmedialist = findall(self.RichMediadetection,pdf)
        for _ in Richmedialist:
            _List.append({"Key":"/RichMedia","Value":_.decode("utf-8",errors="ignore")})
        return len(Richmedialist),_List

    @verbose(True,verbose_flag,None)
    def getaa(self,pdf) -> (str,list):
        '''
        get AA from pdf by regex
        '''
        _List = []
        aalist = findall(self.AAdetection,pdf)
        for _ in aalist:
            _List.append({"Key":"/AA","Value":_.decode("utf-8",errors="ignore")})
        return len(aalist),_List

    @verbose(True,verbose_flag,None)
    def checkpdfsig(self,data) -> bool:
        '''
        check if mime is pdf
        '''
        if data["Details"]["Properties"]["mime"] == "application/pdf":
            return True


    @verbose(True,verbose_flag,"Analyzing PDF file")
    def checkpdf(self,data):
        '''
        start analyzing pdf logic, get pdf objects, 
        get words and wordsstripped from buffers if streams exist 
        otherwise get words and wordsstripped from file
        '''
        _Streams = []
        data["PDF"] = {  "Count":{},
                         "Object":[],
                         "Stream":[],
                         "JS":[],
                         "Javascript":[],
                         "OpenAction":[],
                         "Launch":[],
                         "URI":[],
                         "Action":[],
                         "GoToR":[],
                         "RichMedia":[],
                         "AA":[],
                         "_Count":{},
                         "_Object":["Object","Value"],
                         "_Stream":["Stream","Parsed","Value"],
                         "_JS":["Key","Value"],
                         "_Javascript":["Key","Value"],
                         "_Launch":["Key","Value"],
                         "_OpenAction":["Key","Value"],
                         "_URI":["Key","Value"],
                         "_Action":["Key","Value"],
                         "_GoToR":["Key","Value"],
                         "_RichMedia":["Key","Value"],
                         "_AA":["Key","Value"]}

        f = data["FilesDumps"][data["Location"]["File"]]

        objlen,objs = self.getobject(f)
        strlen,strs,_Streams = self.getstream(f)
        jslen,jslist = self.getjs(f)
        jalen,jaslist = self.getjavascript(f)
        oalen,oalist = self.getopenaction(f)
        llen,llist = self.getlunch(f)
        ulen,ulist = self.geturi(f)
        alen,alist = self.getaction(f)
        gtrlen,gtrlist = self.getgotor(f)
        rmlen,rmlist = self.getrichmedia(f)
        aalen,aalist = self.getaa(f)

        data["PDF"]["Count"] = { "Object" : objlen,
                                  "Stream" : strlen,
                                  "JS" : jslen,
                                  "Javascript" : jalen,
                                  "OpenAction" : oalen,
                                  "Launch" : llen,
                                  "URI" : ulen,
                                  "Action" : alen,
                                  "GoToR" : gtrlen,
                                  "RichMedia" : rmlen,
                                  "AA" : aalen}

        data["PDF"]["Object"] = objs
        data["PDF"]["JS"] = jslist
        data["PDF"]["Javascript"] = jaslist
        data["PDF"]["OpenAction"] = oalist
        data["PDF"]["Launch"] = llist
        data["PDF"]["URI"] = ulist
        data["PDF"]["Action"] = alist
        data["PDF"]["GoToR"] = gtrlist
        data["PDF"]["RichMedia"] = rmlist
        data["PDF"]["AA"] = aalist
        data["PDF"]["Stream"] = strs

        if len(_Streams) > 0:
            getwordsmultifilesarray(data,_Streams)
        else:
            getwords(data,_Streams)