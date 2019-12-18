from ..logger.logger import logstring,verbose,verbose_flag,verbose_timeout
from ..mics.funcs import getwords, getwordsmultifiles,openinbrowser,serializeobj
from ..report.htmlmaker import HtmlMaker
from ..report.jsonmaker import JSONMaker
from ..mics.connection import additem,additemfs
from ..intell.qbimage import QBImage
from ..intell.qbicons import QBIcons
from os import path

class ReportHandler:
    @verbose(True,verbose_flag,verbose_timeout,"Starting ReportHandler")
    def __init__(self):
        self.htm = HtmlMaker(QBImage,QBIcons)
        self.JSO = JSONMaker()

    @verbose(True,verbose_flag,verbose_timeout,"Parsing and cleaning output")
    def checkoutput(self,data,parsed):
        if parsed.html:
            self.hge.rendertemplate(data,None,None,parsed)
            if path.exists(data["Location"]["html"]):
                logstring("Generated Html file {}".format(data["Location"]["html"]),"Yellow")
                if parsed.open:
                    openinbrowser(data["Location"]["html"])
        data = serializeobj(data) # force this <--- incase some value returned with object of type 'NoneType' has no len
        self.JSO.cleandata(data)
        if parsed.json:
            self.JSO.dumpjson(data)
            if parsed.json:
                if path.exists(data["Location"]["json"]):
                    logstring("Generated JSON file {}".format(data["Location"]["json"]),"Yellow")
                    if parsed.open:
                        openinbrowser(data["Location"]["json"])
                    if parsed.print:
                        self.JSO.printjson(data)
            self.saveoutput(data,parsed)

    @verbose(True,verbose_flag,verbose_timeout,None)
    def saveoutput(self,data,parsed):
        if len(data)>0:
            if parsed.db_result:
                dataserialized = serializeobj(data)
                _id = additem("tasks","results",dataserialized)
                if _id:
                    logstring("Result added to db","Green")
                else:
                    logstring("Unable to add result to db","Red")
            elif parsed.db_dump:
                datajson = self.JSO.dumpjsonandreturn(data)
                _id = additemfs("dumps",datajson,data["Details"]["Properties"]["md5"],data["Details"]["Properties"])
                if _id:
                    logstring("Result dumped into db","Green")
                else:
                    logstring("Unable to dump result to db","Red")