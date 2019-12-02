__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from ..mics.funcs import getwordsmultifilesarray,getwords
from re import DOTALL, MULTILINE, compile, findall
from magic import from_buffer,Magic
from zlib import decompress

#this module need some optimization

class PDFParser:
    @verbose(verbose_flag)
    @progressbar(True,"Starting PDFParser")
    def __init__(self):
        pass

    @verbose(verbose_flag)
    def getobjects(self,pdf) -> (str,list):
        '''
        get objects from pdf by regex
        '''
        _List = []
        Object = compile(b'(\d+\s\d)+\sobj([\s\S]*?\<\<([\s\S]*?))endobj',DOTALL|MULTILINE)
        Objects = findall(Object,pdf)
        for _ in Objects:
            _List.append({"Object":_[0].decode("utf-8",errors="ignore"),"Value":_[1].decode('utf-8',errors="ignore")})
        return len(Objects),_List

    @verbose(verbose_flag)
    def getstreams(self,pdf) -> (str,list,list):
        '''
        get streams from pdf by regex
        '''
        _List = []
        _Streams = []
        Stream = compile(b'.*?FlateDecode.*?stream(.*?)endstream', DOTALL|MULTILINE)
        Streams = findall(Stream,pdf)
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

    @verbose(verbose_flag)
    def getjss(self,pdf) -> (str,list):
        '''
        get jss from pdf by regex
        '''
        _List = []
        JS = compile(b'/JS([\S][^>]+)',DOTALL|MULTILINE)
        JSs = findall(JS,pdf)
        for _ in JSs:
            _List.append({"Key":"/JS","Value":_.decode("utf-8",errors="ignore")})
        return len(JSs),_List

    @verbose(verbose_flag)
    def getjavascripts(self,pdf) -> (str,list):
        '''
        get java from pdf by regex
        '''
        _List = []
        Javascript = compile(b'/JavaScript([\S][^>]+)',DOTALL|MULTILINE)
        Javascripts = findall(Javascript,pdf)
        for _ in Javascripts:
            _List.append({"Key":"/JavaScript","Value":_.decode("utf-8",errors="ignore")})
        return len(Javascripts),_List

    @verbose(verbose_flag)
    def getopenactions(self,pdf) -> (str,list):
        '''
        get openactions from pdf by regex
        '''
        _List = []
        OpenAction = compile(b'/OpenAction([\S][^>]+)',DOTALL|MULTILINE)
        OpenActions = findall(OpenAction,pdf)
        for _ in OpenActions:
            _List.append({"Key":"/OpenAction","Value":_.decode("utf-8",errors="ignore")})
        return len(OpenActions),_List

    @verbose(verbose_flag)
    def checkpdfsig(self,data) -> bool:
        '''
        check if mime is pdf
        '''
        if data["Details"]["Properties"]["mime"] == "application/pdf":
            return True

    @verbose(verbose_flag)
    @progressbar(True,"Analyzing PDF file")
    def checkpdf(self,data):
        '''
        start analyzing pdf logic, get pdf objects, 
        get words and wordsstripped from buffers if streams exist 
        otherwise get words and wordsstripped from file
        '''
        _Streams = []
        data["PDF"] = {  "Count":{},
                         "Object":[],
                         "Javascript":[],
                         "JS":[],
                         "OpenAction":[],
                         "Stream":[],
                         "_Count":{},
                         "_Object":["Object","Value"],
                         "_Javascript":["Key","Value"],
                         "_JS":["Key","Value"],
                         "_OpenAction":["Key","Value"],
                         "_Stream":["Stream","Parsed","Value"]}
        f = data["FilesDumps"][data["Location"]["File"]]
        objlen,objs = self.getobjects(f)
        strlen,strs,_Streams = self.getstreams(f)
        jsslen,jss = self.getjss(f)
        javlen,javs = self.getjavascripts(f)
        opelen,opens = self.getopenactions(f)
        data["PDF"]["Count"] = { "Object" : objlen,
                                  "Stream" : strlen,
                                  "JS" : jsslen,
                                  "Javascript" : javlen,
                                  "OpenAction" : opelen}
        data["PDF"]["Object"] = objs
        data["PDF"]["JS"] = jss
        data["PDF"]["Javascript"] = javs
        data["PDF"]["OpenAction"] = opens
        data["PDF"]["Stream"] = strs
        if len(_Streams) > 0:
            getwordsmultifilesarray(data,_Streams)
        else:
            getwords(data,_Streams)