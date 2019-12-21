__G__ = "(G)bd249ce4"

from ..logger.logger import log_string,verbose,verbose_flag,verbose_timeout
from json import JSONEncoder,dump as jdump,dumps as jdumps

class ComplexEncoder(JSONEncoder):
    def default(self, obj):
        if not isinstance(obj, str):
            return "Object type {} was removed..".format(type(obj))
        if isinstance(obj, long):
            return str(obj)
        return JSONEncoder.default(self, obj)

class JSONMaker:
    @verbose(True,verbose_flag,verbose_timeout,"Starting JSONMaker")
    def __init__(self):
        '''
        initialize class
        '''

    @verbose(True,verbose_flag,verbose_timeout,None)
    def print_json(self,data):
        log_string(jdumps(data, indent=4, sort_keys=True,cls=ComplexEncoder),"Yellow")

    @verbose(True,verbose_flag,verbose_timeout,None)
    def clean_data(self,data):
        '''
        start making json output file
        '''

        for x in data.copy():
            if x in ("StringsRAW","FilesDumps"):
                del data[x]
            else:
                for key in data[x].copy():
                    if key in ("GRAPH","Flags","ICONS"):
                        del data[x][key]
                    elif not key.startswith("_"):
                        if len(data[x][key]) == 0:
                            del data[x][key]
                    else:
                        del data[x][key]

        for x in data.copy():
            if len(data[x]) == 0:
                del data[x]

    @verbose(True,verbose_flag,verbose_timeout,None)
    def dump_json(self,data):
        '''
        start making json output file
        '''

        with open(data["Location"]["json"], 'w') as fp:
            jdump(data, fp, cls=ComplexEncoder)

    @verbose(True,verbose_flag,verbose_timeout,None)
    def dump_json_and_return(self,data):
        '''
        start making json output file
        '''
        return jdumps(data, cls=ComplexEncoder)