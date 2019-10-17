__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from ...mics.funcs import getwordsmultifilesarray,getwords
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
    def getobjects(self,pdf):
        _List = []
        Object = compile(b'(\d+\s\d)+\sobj([\s\S]*?\<\<([\s\S]*?))endobj',DOTALL|MULTILINE)
        Objects = findall(Object,pdf)
        for _ in Objects:
            _List.append({"Object":_[0].decode("utf-8"),"Value":_[1]})
        return len(Objects),_List

    @verbose(verbose_flag)
    def getstreams(self,pdf,_Streams):
        _List = []
        Stream = compile(b'.*?FlateDecode.*?stream(.*?)endstream', DOTALL|MULTILINE)
        Streams = findall(Stream,pdf)
        for _ in Streams:
            parsed = None
            parseddecode = None
            x = _.strip(b"\r").strip(b"\n")
            mime = from_buffer(x,mime=True)
            if mime == "application/zlib":
                parsed = decompress(x)
                parseddecode = parsed.decode("utf-8")
                _Streams.append(parsed)
            _List.append({"Stream":mime,"Parsed":parseddecode,"Value":x})
        return len(Streams),_List

    @verbose(verbose_flag)
    def getjss(self,pdf):
        _List = []
        JS = compile(b'/JS([\S][^>]+)',DOTALL|MULTILINE)
        JSs = findall(JS,pdf)
        for _ in JSs:
            _List.append({"Key":"/JS","Value":_.decode("utf-8")})
        return len(JSs),_List

    @verbose(verbose_flag)
    def getjavascripts(self,pdf):
        _List = []
        Javascript = compile(b'/JavaScript([\S][^>]+)',DOTALL|MULTILINE)
        Javascripts = findall(Javascript,pdf)
        for _ in Javascripts:
            _List.append({"Key":"/JavaScript","Value":_.decode("utf-8")})
        return len(Javascripts),_List

    @verbose(verbose_flag)
    def getopenactions(self,pdf):
        _List = []
        OpenAction = compile(b'/OpenAction([\S][^>]+)',DOTALL|MULTILINE)
        OpenActions = findall(OpenAction,pdf)
        for _ in OpenActions:
            _List.append({"Key":"/OpenAction","Value":_.decode("utf-8")})
        return len(OpenActions),_List

    @verbose(verbose_flag)
    def checkpdfsig(self,data):
        if data["Details"]["Properties"]["mime"] == "application/pdf":
            return True

    @verbose(verbose_flag)
    @progressbar(True,"Analyze pdf file")
    def checkpdf(self,data):
        words = None
        wordsstripped = None
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
        f = open(data["Location"]["File"],"rb").read()
        objlen,objs = self.getobjects(f)
        strlen,strs = self.getstreams(f,_Streams)
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
            words,wordsstripped = getwordsmultifilesarray(_Streams)
            data["StringsRAW"] = {"words":words,
                                  "wordsstripped":wordsstripped}
            
        else:
            words,wordsstripped = getwords(_Streams)
            data["StringsRAW"] = {"words":words,
                                  "wordsstripped":wordsstripped}