from ..logger.logger import log_string,verbose,verbose_flag,verbose_timeout
from ..mics.funcs import get_words, get_words_multi_files,open_in_browser,serialize_obj
from ..report.htmlmaker import HtmlMaker
from ..report.jsonmaker import JSONMaker
from ..mics.connection import add_item,add_item_fs
from ..intell.qbimage import QBImage
from ..intell.qbicons import QBIcons
from os import path

class ReportHandler:
    @verbose(True,verbose_flag,verbose_timeout,"Starting ReportHandler")
    def __init__(self):
        self.htmlmaker = HtmlMaker(QBImage,QBIcons)
        self.jsonmaker = JSONMaker()

    @verbose(True,verbose_flag,verbose_timeout,"Parsing and cleaning output")
    def check_output(self,data,parsed):
        if parsed.html:
            self.htmlmaker.render_template(data,None,None,parsed)
            if path.exists(data["Location"]["html"]):
                log_string("Generated Html file {}".format(data["Location"]["html"]),"Yellow")
                if parsed.open:
                    open_in_browser(data["Location"]["html"])
        data = serialize_obj(data) # force this <--- incase some value returned with object of type 'NoneType' has no len
        self.jsonmaker.clean_data(data)
        if parsed.json:
            self.jsonmaker.dump_json(data)
            if parsed.json:
                if path.exists(data["Location"]["json"]):
                    log_string("Generated JSON file {}".format(data["Location"]["json"]),"Yellow")
                    if parsed.open:
                        open_in_browser(data["Location"]["json"])
                    if parsed.print:
                        self.jsonmaker.print_json(data)
            self.save_output(data,parsed)

    @verbose(True,verbose_flag,verbose_timeout,None)
    def save_output(self,data,parsed):
        if len(data)>0:
            if parsed.db_result:
                dataserialized = serialize_obj(data)
                _id = add_item("tasks","results",dataserialized)
                if _id:
                    log_string("Result added to db","Green")
                else:
                    log_string("Unable to add result to db","Red")
            elif parsed.db_dump:
                datajson = self.jsonmaker.dump_json_and_return(data)
                _id = add_item_fs("dumps",datajson,data["Details"]["Properties"]["md5"],data["Details"]["Properties"])
                if _id:
                    log_string("Result dumped into db","Green")
                else:
                    log_string("Unable to dump result to db","Red")