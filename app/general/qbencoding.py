from ..logger.logger import logstring,verbose,verbose_flag,verbose_timeout
from magic import from_file,Magic

class QBEncdoing:
    @verbose(True,verbose_flag,verbose_timeout,"Starting QBEncdoing")
    def __init__(self):
        pass

    @verbose(True,verbose_flag,verbose_timeout,None)
    def checkbom(self,str):
        if str[:3] == '\xEF\xBB\xBF':
            return "UTF-8-SIG"
        elif str[:4] == '\xFF\xFE\x00\x00':
            return "UTF-32LE"
        elif str[:4] == '\x00\x00\xFF\xFE':
            return "UTF-32BE"
        elif str[:2] == '\xFF\xFE':
            return "UTF-16LE"
        elif str[:2] == '\xFE\xFF':
            return "UTF-16BE"
        return "None"

    @verbose(True,verbose_flag,verbose_timeout,"Checking file encoding")
    def checkfile(self,data,_path,_unicode) -> bool:

        data["Encoding"] = {"Encoding":{},
                           "_Encoding":{}}

        open(_path,"rb").read()
        fbom = open(_path,"rb").read(4)

        if _unicode:
            encoding = "utf-16"
        else:
            encoding = "utf-8"

        data["Encoding"]["Encoding"]={  "charset":Magic(mime_encoding=True).from_file(_path),
                                       "ForceEncoding":encoding,
                                       "ByteOrderMark":self.checkbom(fbom)}