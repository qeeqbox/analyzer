from ..logger.logger import log_string,verbose,verbose_flag,verbose_timeout
from ..mics.funcs import open_in_browser, serialize_obj
from ..report.htmlmaker import HtmlMaker
from ..report.jsonmaker import JSONMaker
from ..connections.mongodbconn import add_item_fs
from ..intell.qbimage import QBImage
from ..intell.qbicons import QBIcons
from ..settings import defaultdb
from datetime import datetime

class ReportHandler:
    @verbose(True,verbose_flag,verbose_timeout,"Starting ReportHandler")
    def __init__(self):
        self.htmlmaker = HtmlMaker(QBImage,QBIcons)
        self.jsonmaker = JSONMaker()

    @verbose(True,verbose_flag,verbose_timeout,"Parsing and cleaning output")
    def check_output(self,data,parsed):
        renderedhtml = "Error"
        if parsed.db_dump_html:
            renderedhtml = self.htmlmaker.render_template(data,None,None,parsed,False)
        if parsed.disk_dump_html:
            if self.htmlmaker.render_template(data,None,None,parsed,True):
                log_string("Generated Html file {}".format(data["Location"]["html"]),"Yellow")
                if parsed.open:
                    open_in_browser(data["Location"]["html"])

        if parsed.db_dump_json or parsed.disk_dump_json or parsed.print_json:
            data = serialize_obj(data) # force this <--- incase some value returned with object of type 'NoneType' has no len
            self.jsonmaker.clean_data(data)
        if parsed.disk_dump_json:
            if self.jsonmaker.dump_json(data):                
                log_string("Generated JSON file {}".format(data["Location"]["json"]),"Yellow")
                if parsed.open:
                    open_in_browser(data["Location"]["json"])
        if parsed.print_json:
            self.jsonmaker.print_json(data)
        self.save_output(data,renderedhtml,parsed)

    @verbose(True,verbose_flag,verbose_timeout,None)
    def save_output(self,data,renderedhtml,parsed):
        _id = None
        _es = None
        if len(data)>0:
            if parsed.db_result:
                serialize_obj(data)
                #_id = add_item("tasks","results",dataserialized)
                #if _id:
                #    log_string("JSON result added to db","Yellow")
                #else:
                #    log_string("Unable to add JSON result to db","Red")
            if parsed.db_dump_json:
                datajson = self.jsonmaker.dump_json_and_return(data)
                _id = add_item_fs(defaultdb["dbname"],defaultdb["reportscoll"],datajson,data["Details"]["Properties"]["md5"],data["Details"]["Properties"],parsed.uuid,"application/json",datetime.now())
                #_es = push_to_elastic(parsed.uuid,datajson["Details"])
                if _id:
                    log_string("JSON result dumped into db","Yellow")
                else:
                    log_string("Unable to dump JSON result to db","Red")
                if _es:
                    log_string("JSON result dumped into elastic","Yellow")
                else:
                    log_string("Unable to dump JSON result to elastic","Red")
            if parsed.db_dump_html:
                datajson = self.jsonmaker.dump_json_and_return(data)
                _id = add_item_fs(defaultdb["dbname"],defaultdb["reportscoll"],renderedhtml,data["Details"]["Properties"]["md5"],data["Details"]["Properties"],parsed.uuid,"text/html",datetime.now())
                if _id:
                    log_string("HTML result dumped into db","Yellow")
                else:
                    log_string("Unable to dump HTML result to db","Red")