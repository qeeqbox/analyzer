__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from ..mics.funcs import iptolong
from r2pipe import open as r2open
from re import search
from ast import literal_eval

#this module needs some optimization
#only apis for now, will change this in future
#added a little hack for handling errors 
#(check returns 0 because of error and flags=['-2'])
#Similar to objdump, still needs to optimize
  
class QBXrefs:
    @progressbar(True,"Starting QBXrefs")
    def __init__(self):
        pass

    @verbose(verbose_flag)
    def checkfunc(self,func,str) -> bool:
        '''
        check if functions are not sub or sym 

        Args:
            func: soruce function
            str: target function
        '''
        if func.startswith("sub."):
            if func[4:].split("_")[1].lower() in str.lower():
                return False
        elif func.startswith("sym."):
            if func[4:].lower() in str.lower():
                return False
        if search(r'\b{}\b'.format(func), str) is not None:
            return False
        return True

    @verbose(verbose_flag)
    @progressbar(True,"Making symbol xrefs")
    def makexref(self,data):
        '''
        get cross references from file using radare2 

        Args:
            data: data dict
        '''
        data["XREFS"] = { "GRAPH":{"nodes":[],"links":[]},
                          "TEXT":[],
                         "_TEXT":["From","To"]}
        r2p = r2open(data["Location"]["File"],flags=['-2'])
        r2p.cmd("e anal.timeout = 10")
        r2p.cmd("aaaa")
        x = r2p.cmd("axtj@@ sym.*")
        x = "["+(x.replace('\n','').replace("][","],["))+"]"
        sym = ' '.join(r2p.cmd("is~[6]").split())
        x = literal_eval(x)
        _node = []
        _links = []
        _list = []
        _temp = []
        for funcs in x:
            for func in funcs:
                if "opcode" in func and "fcn_name" in func:
                    match  = search(r'\[(.*?)\]', func["opcode"])
                    if match is not None:
                        if len(r2p.cmd("pd 1 @ "+match.group(1))) > 0:
                            _list.append({"From":func["fcn_name"],"To":match.group(1)})
                    else:
                        funcfromopcode = ''.join(func["opcode"].split(' ')[-1:])
                        _list.append({"From":func["fcn_name"],"To":funcfromopcode})

        for xfunc in _list:
            if self.checkfunc(xfunc["From"],sym):
                if xfunc["From"] not in _temp:
                    _temp.append(xfunc["From"])
                    _node.append({"func":xfunc["From"]})
                if xfunc["To"] not in _temp:
                    _temp.append(xfunc["To"])
                    _node.append({"func":xfunc["To"]})

        for xfunc in _list:
            try:
                S = _temp.index(xfunc["From"])
                T = _temp.index(xfunc["To"])
                if next((item for item in _links if item["source"] == S and item["target"] == T), False) == False:
                    _links.append({"source":S,"target":T})
            except:
                pass

        if len(_node) > 0 and len(_links) > 0:
            data["XREFS"]["GRAPH"]["nodes"] = _node
            data["XREFS"]["GRAPH"]["links"] = _links
            data["XREFS"]["TEXT"] = _list