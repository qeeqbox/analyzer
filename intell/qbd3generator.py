'''
    __G__ = "(G)bd249ce4"
    connection -> ref map
'''
from ast import literal_eval
from re import search
from r2pipe import open as r2open
from analyzer.logger.logger import ignore_excpetion, verbose


class QBD3generator:
    '''
    QBD3generator generates the API references map
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBD3generator")
    def __init__(self):
        '''
        Initialize QBD3generator, nothing here just a message
        '''
        self.temp = None

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_func(self, func, _str) -> bool:
        '''
        check if functions are not sub or sym
        '''
        if func.startswith("sub."):
            if func[4:].split("_")[1].lower() in _str.lower():
                return False
        elif func.startswith("sym."):
            if func[4:].lower() in _str.lower():
                return False
        if search(r'\b{}\b'.format(func), _str) is not None:
            return False
        return True

    @verbose(True, verbose_output=False, timeout=None, _str="Making symbol xrefs")
    def create_d3_ref(self, data):
        '''
        get cross references from file using radare2
        '''
        data["XREFS"] = {"GRAPH": {"nodes": [], "links": []},
                         "TEXT": [],
                         "_TEXT": ["From", "To"]}
        r2p = r2open(data["Location"]["File"], flags=['-2'])
        r2p.cmd("e anal.timeout = 10")
        r2p.cmd("aaaa")
        temp_var = r2p.cmd("axtj@@ sym.*")
        temp_var = "[" + (temp_var.replace('\n', '').replace("][", "], [")) + "]"
        sym = ' '.join(r2p.cmd("is~[6]").split())
        temp_var = literal_eval(temp_var)
        _node = []
        _links = []
        _list = []
        _temp = []
        for funcs in temp_var:
            for func in funcs:
                if "opcode" in func and "fcn_name" in func:
                    match = search(r'\[(.*?)\]', func["opcode"])
                    if match is not None:
                        if len(r2p.cmd("pd 1 @ " + match.group(1))) > 0:
                            _list.append({"From": func["fcn_name"], "To": match.group(1)})
                    else:
                        funcfromopcode = ''.join(func["opcode"].split(' ')[-1:])
                        _list.append({"From": func["fcn_name"], "To": funcfromopcode})

        for xfunc in _list:
            if self.check_func(xfunc["From"], sym):
                if xfunc["From"] not in _temp:
                    _temp.append(xfunc["From"])
                    _node.append({"func": xfunc["From"]})
                if xfunc["To"] not in _temp:
                    _temp.append(xfunc["To"])
                    _node.append({"func": xfunc["To"]})

        for xfunc in _list:
            with ignore_excpetion(Exception):
                temp_var_s = _temp.index(xfunc["From"])
                temp_var_t = _temp.index(xfunc["To"])
                if next((item for item in _links if item["source"] == temp_var_s and item["target"] == temp_var_t), False) is False:
                    _links.append({"source": temp_var_s, "target": temp_var_t})

        if len(_node) > 0 and len(_links) > 0:
            data["XREFS"]["GRAPH"]["nodes"] = _node
            data["XREFS"]["GRAPH"]["links"] = _links
            data["XREFS"]["TEXT"] = _list

    @verbose(True, verbose_output=False, timeout=None, _str="Making artifacts xrefs")
    def create_d3_artifacts(self, data) -> bool:
        '''
        get artifacts from data and generate d3
        '''
        data["REFS"] = {"GRAPH": {"nodes": [], "links": []},
                        "TEXT": [],
                        "_TEXT": ["From", "To"]}
        _node = []
        _links = []
        _list = []
        _temp = []

        with ignore_excpetion(Exception):
            for item in data["Strings"]["IPS"]:
                _list.append({"From": "File", "To": item["IP"]})

        with ignore_excpetion(Exception):
            for item in data["Strings"]["EMAILs"]:
                _list.append({"From": "File", "To": item["EMAIL"]})

        for item in _list:
            if item["From"] not in _temp:
                _temp.append(item["From"])
                _node.append({"func": item["From"]})
            if item["To"] not in _temp:
                _temp.append(item["To"])
                _node.append({"func": item["To"]})

        for item in _list:
            with ignore_excpetion(Exception):
                temp_var_s = _temp.index(item["From"])
                temp_var_t = _temp.index(item["To"])
                if next((item for item in _links if item["source"] == temp_var_s and item["target"] == temp_var_t), False) is False:
                    _links.append({"source": temp_var_s, "target": temp_var_t})

        if len(_node) > 0 and len(_links) > 0:
            data["REFS"]["GRAPH"]["nodes"] = _node
            data["REFS"]["GRAPH"]["links"] = _links
            data["REFS"]["TEXT"] = _list
