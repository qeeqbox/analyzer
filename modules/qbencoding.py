'''
    __G__ = "(G)bd249ce4"
    modules -> encode
'''

from magic import Magic
from analyzer.logger.logger import verbose


class QBEncdoing:
    '''
    QBEncdoing getting encoding
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBEncdoing")
    def __init__(self):
        '''
        just for the message
        '''
        self.temp = None

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_bom(self, _str) -> str:
        '''
        check byte order mark
        '''
        temp_str = "None"
        if _str[:3] == '\xEF\xBB\xBF':
            temp_str = "UTF-8-SIG"
        elif _str[:4] == '\xFF\xFE\x00\x00':
            temp_str = "UTF-32LE"
        elif _str[:4] == '\x00\x00\xFF\xFE':
            temp_str = "UTF-32BE"
        elif _str[:2] == '\xFF\xFE':
            temp_str = "UTF-16LE"
        elif _str[:2] == '\xFE\xFF':
            temp_str = "UTF-16BE"
        return temp_str

    @verbose(True, verbose_output=False, timeout=None, _str="Checking file encoding")
    def analyze(self, data, _path, _unicode) -> bool:
        '''
        start analyzing
        '''
        data["Encoding"] = {"Details": {},
                            "_Details": {}}

        open(_path, "rb").read()
        fbom = open(_path, "rb").read(4)

        if _unicode:
            encoding = "utf-16"
        else:
            encoding = "utf-8"

        data["Encoding"]["Details"] = {"charset": Magic(mime_encoding=True).from_file(_path),
                                       "ForceEncoding": encoding,
                                       "ByteOrderMark": self.check_bom(fbom)}
