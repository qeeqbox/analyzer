__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from json import JSONEncoder,dump as jdump,dumps as jdumps

class ComplexEncoder(JSONEncoder):
    def default(self, obj):
        if not isinstance(obj, str):
            return "Object type {} was removed..".format(type(obj))
        return JSONEncoder.default(self, obj)

class JSONMaker:
    @verbose(True,verbose_flag,"Starting JSONMaker")
    def __init__(self):
        '''
        initialize class
        '''

    @verbose(True,verbose_flag,None)
    def printjson(self,data):
        logstring(jdumps(data, indent=4, sort_keys=True,cls=ComplexEncoder),"Yellow")

    @verbose(True,verbose_flag,None)
    def createjson(self,data):
        '''
        start making json output file
        '''
        for x in data:
            for key in data[x].copy():
                if key == "GRAPH" or key == "Flags":
                    del data[x][key]
                elif not key.startswith("_"):
                    if len(data[x][key]) == 0:
                        del data[x][key]
                else:
                    del data[x][key]
        for x in data.copy():
            if len(data[x]) == 0:
                del data[x]

        with open(data["Location"]["json"], 'w') as fp:
            jdump(data, fp, cls=ComplexEncoder)