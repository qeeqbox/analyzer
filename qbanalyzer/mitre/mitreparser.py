__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from json import loads, dumps,dump,load
from urllib.request import urlretrieve
from codecs import open
from re import findall,compile
from collections import Counter
from os import mkdir, path

#need to optimize..

class MitreParser():
    @progressbar(True,"Starting MitreParser")
    def __init__(self):
        '''
        initialize class, make mitrefiles path and have mitre links in the class
        '''
        self.mitrepath = path.abspath(path.join(path.dirname( __file__ ),'mitrefiles'))
        if not self.mitrepath.endswith(path.sep): self.mitrepath = self.mitrepath+path.sep
        if not path.isdir(self.mitrepath): mkdir(self.mitrepath)
        self.preattackjson = {}
        self.enterpriseattackjson = {}
        self.fulldict = {}
        self.usedict = {}
        self.preattackurl = "https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json"
        self.enterpriseattackurl = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.setup(self.mitrepath)

    @verbose(verbose_flag)
    @progressbar(True,"Parsing Mitre databases")
    def setup(self,_path):
        '''
        check if there are enterprise-attack.json and pre-attack.json in the system
        if not, download them and parse them. otehrwise use the once from the system

        Args:
            _path: path to mitrefiles folder
        '''
        l = {}
        if not path.exists(_path+'enterprise-attack.json') and not path.exists(_path+'pre-attack.json'):
            urlretrieve(self.enterpriseattackurl, _path+"enterprise-attack.json")
            urlretrieve(self.preattackurl, _path+"pre-attack.json")
        with open(_path+"enterprise-attack.json", encoding='ascii', errors='ignore') as enterprise, open(_path+"pre-attack.json", encoding='ascii', errors='ignore') as pre:
            self.preattack = pre.read()
            self.enterprise = enterprise.read()
            if path.exists(_path+'hardcoded_usedict.json') and path.exists(_path+'hardcoded_fulldict.json'):
                self.fulldict = load(open(_path+"hardcoded_fulldict.json"))
                self.usedict = load(open(_path+"hardcoded_usedict.json"))
            else:
                l['preattack'] = loads(self.preattack)['objects']
                l['enterprise'] = loads(self.enterprise)['objects']
                self.updatedict(l['preattack'],{"collection":"preattack"})
                self.updatedict(l['enterprise'],{"collection":"enterprise"})
                self.fulldict = l['preattack'] + l['enterprise']
                self.usedict = self.finduses()
                dump(self.fulldict,open(_path+"hardcoded_fulldict.json", 'w' ))
                dump(self.usedict,open(_path+"hardcoded_usedict.json", 'w' ))

    @verbose(verbose_flag)
    def updatedict(self,d,s):
        for x in d:
            x.update(s)

    @verbose(verbose_flag)
    def searchonce(self,s,d):
        try:
            for x in s:
                if all((k in x and x[k]==v) for k,v in d.items()):
                    return x
        except:
            return None

    @verbose(verbose_flag)
    def searchinmitreandreturn(self,s,d,r):
        l = []
        for x in s:
            if all((k in x and x[k]==v) for k,v in d.items()):
                l.append({key: x.get(key) for key in r})
        return l

    @verbose(verbose_flag)
    def nestedsearch(self,k, d):
        if k in d:
            return d[k]
        for k, v in d.items():
            if isinstance(v, dict):
                result = nestedsearch(k, v)
                if result:
                    return k, result

    @verbose(verbose_flag)
    def findid(self,s,_print):
        l={}
        for x in s[0]:
            if x['type'] == 'attack-pattern':
                if x['id'] not in l:
                    l.update({x['id']:x['name']})
            if isinstance(x['description'], list):
                for d in x['description']:
                    if d['type'] == 'attack-pattern':
                        if d['id'] not in l:
                            l.update({d['id']:d['name']})
        if _print:
            print(dumps(l, indent=4, sort_keys=True))
        else:
            return l
    def countitem(self,_s,k):
        return Counter([d[k] for d in _s])

    @verbose(verbose_flag)
    def finduses(self):
        '''
        find all relationship_type uses value and parse them into hardcoded list 
        '''
        l = self.searchinmitreandreturn(self.fulldict,{'relationship_type':'uses'},['source_ref','target_ref','description','collection'])
        d = {}
        for i in l:
            s = self.searchonce(self.fulldict,{'id':i['source_ref']})
            u = self.searchonce(self.fulldict,{'id':i['target_ref']})
            try:
                xx = u['external_references'][0]['external_id']
            except:
                xx = None
            if s and u:
                if d.get(s['type'.lower().rstrip()]):
                    if d[s['type']].get(s['name']) == [] or d[s['type']].get(s['name']):
                        d[s['type']][s['name']].append({'id':xx,'name':u['name'],'type':u['type'],'description':i['description'],'collection':i['collection']})
                    else:
                        d[s['type']].update({s['name']:[{'id':xx,'name':u['name'],'type':u['type'],'description':i['description'],'collection':i['collection']}]})
                else:
                    d.update({s['type'].lower().rstrip():{s['name']:[{'id':xx,'name':u['name'],'type':u['type'],'description':i['description'],'collection':i['collection']}]}})
        for i in d['intrusion-set']:
            for ii in d['intrusion-set'][i]:
                if ii['type'] == 'malware' or ii['type'] == 'tool':
                    ii['description'] = []
                    for x in d[ii['type']][ii['name']]:
                        xx = self.searchonce(self.fulldict,{'name':x['name']})
                        ii['description'].append({'id':xx['external_references'][0]['external_id'],'name':x['name'],'type':x['type']})
        return d

    @verbose(verbose_flag)
    def findapt(self,apt,_print=False):
        '''
        find an apt group from the hardocded list (Name is case sensitive)

        Args:
            apt: apt name
            _print: pretty print json
        '''
        x = self.usedict['intrusion-set'][apt]
        c = self.countitem(x,'collection')
        if _print:
            print(dumps([x,c], indent=4, sort_keys=True))
        else:
            return [x,c]

    @verbose(verbose_flag)
    def listapts(self,_print=False):
        '''
        list all apts from hardocded list 

        Args:
            _print: pretty print json
        '''
        x = [x for x in self.usedict['intrusion-set']]
        if _print:
            print(dumps(x, indent=4, sort_keys=True))
        else:
            return x

    @verbose(verbose_flag)
    def findmalware(self,malware,_print=False):
        '''
        find malware from the hardocded list (Name is case sensitive)

        Args:
            malware: malware name
            _print: pretty print json
        '''
        if malware in self.usedict['malware']:
            x = self.usedict['malware'][malware]
            #c = self.countitem(x,'collection')
            if _print:
                print(dumps(x, indent=4, sort_keys=True))
            else:
                return x
        return None

    @verbose(verbose_flag)
    def findtool(self,tool,_print=False):
        '''
        find tool from the hardocded list (Name is case sensitive)

        Args:
            tool: tool name
            _print: pretty print json
        '''
        if tool in self.usedict['tool']:
            x = self.usedict['tool'][tool]
            #c = self.countitem(x,'collection')
            if _print:
                print(dumps(x, indent=4, sort_keys=True))
            else:
                return x
        return None

    @verbose(verbose_flag)
    def findword(self,word,_print=False):
        '''
        search for specific word in the files (case insensitive) 

        Args:
            word: word
            _print: pretty print json
        '''
        x = {}
        pattern = compile(r'(^.*%s.*$)' % word, 8|2)
        x['enterpriseattack'] = list(set(findall(pattern, self.enterprise)))
        x['preattack'] = list(set(findall(pattern, self.preattack)))
        if _print:
            print(dumps(x, indent=4, sort_keys=True))
        else:
            return x
