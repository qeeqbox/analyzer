'''
    __G__ = "(G)bd249ce4"
    reports -> json
'''

from os import path
from json import JSONEncoder, dump as jdump, dumps as jdumps
from analyzer.logger.logger import log_string, verbose


class ComplexEncoder(JSONEncoder):
    '''
    this will be used to encode objects
    '''

    def default(self, obj):
        '''
        override default
        '''
        if not isinstance(obj, str):
            return "Object type {} was removed..".format(type(obj))
        if isinstance(obj, int):
            return str(obj)
        return JSONEncoder.default(self, obj)


class JSONMaker:
    '''
    this will be used to generate the final json report
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting JSONMaker")
    def __init__(self):
        '''
        nothing here just for the message
        '''
        self.temp = None

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def print_json(self, data):
        '''
        print json in terminal
        '''
        log_string(jdumps(data, indent=4, sort_keys=True, cls=ComplexEncoder), "Yellow")

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def clean_data(self, data):
        '''
        start making json output file
        '''

        for item in data.copy():
            if item in ("StringsRAW", "FilesDumps"):
                del data[item]
            else:
                for key in data[item].copy():
                    if key in ("GRAPH", "Flags", "ICONS"):
                        del data[item][key]
                    elif not key.startswith("_"):
                        if len(data[item][key]) == 0:
                            del data[item][key]
                    else:
                        del data[item][key]

        for item in data.copy():
            if len(data[item]) == 0:
                del data[item]

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def dump_json(self, data):
        '''
        start making json output file
        '''

        with open(data["Location"]["json"], 'w') as file:
            jdump(data, file, cls=ComplexEncoder)
            if path.exists(data["Location"]["json"]):
                return True
        return False

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def dump_json_and_return(self, data):
        '''
        start making json output file
        '''
        return jdumps(data, cls=ComplexEncoder)
