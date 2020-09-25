'''
    __G__ = "(G)bd249ce4"
    mitre -> parser
'''

from json import loads, dumps, dump, load
from urllib.request import urlretrieve
from codecs import open as copen
from re import findall
from re import compile as rcompile
from collections import Counter
from os import mkdir, path
from analyzer.logger.logger import ignore_excpetion, verbose

class MitreParser():
    '''
    mitre parser (it will download pre-attack.json/enterprise-attack.json and parse them)
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting MitreParser")
    def __init__(self):
        '''
        initialize class, make mitrefiles path and have mitre links in the class
        '''
        self.mitrepath = path.abspath(path.join(path.dirname(__file__), 'mitrefiles'))
        if not self.mitrepath.endswith(path.sep):
            self.mitrepath = self.mitrepath+path.sep
        if not path.isdir(self.mitrepath):
            mkdir(self.mitrepath)
        self.preattackjson = {}
        self.enterpriseattackjson = {}
        self.fulldict = {}
        self.usedict = {}
        self.preattackurl = "https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json"
        self.enterpriseattackurl = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.setup(self.mitrepath)


    @verbose(True, verbose_output=False, timeout=None, _str="Parsing Mitre databases")
    def setup(self, _path):
        '''
        check if there are enterprise-attack.json and pre-attack.json in the system
        if not, download them and parse them. otehrwise use the once from the system
        '''
        temp_list = {}
        if not path.exists(_path+'enterprise-attack.json') and not path.exists(_path+'pre-attack.json'):
            urlretrieve(self.enterpriseattackurl, _path+"enterprise-attack.json")
            urlretrieve(self.preattackurl, _path+"pre-attack.json")
        with copen(_path+"enterprise-attack.json", encoding='ascii', errors='ignore') as enterprise, copen(_path+"pre-attack.json", encoding='ascii', errors='ignore') as pre:
            self.preattack = pre.read()
            self.enterprise = enterprise.read()
            if path.exists(_path+'hardcoded_usedict.json') and path.exists(_path+'hardcoded_fulldict.json'):
                self.fulldict = load(copen(_path+"hardcoded_fulldict.json"))
                self.usedict = load(copen(_path+"hardcoded_usedict.json"))
            else:
                temp_list['preattack'] = loads(self.preattack)['objects']
                temp_list['enterprise'] = loads(self.enterprise)['objects']
                self.update_dict(temp_list['preattack'], {"collection":"preattack"})
                self.update_dict(temp_list['enterprise'], {"collection":"enterprise"})
                self.fulldict = temp_list['preattack'] + temp_list['enterprise']
                self.usedict = self.finduses()
                dump(self.fulldict, copen(_path+"hardcoded_fulldict.json", 'w'))
                dump(self.usedict, copen(_path+"hardcoded_usedict.json", 'w'))

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def update_dict(self, temp_d, temp_s):
        '''
        update target dict
        '''
        for temp_x in temp_d:
            temp_x.update(temp_s)

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def search_once(self, temp_s, temp_d):
        '''
        search once
        '''
        with ignore_excpetion(Exception):
            for temp_x in temp_s:
                if all((temp_k in temp_x and temp_x[temp_k] == temp_var) for temp_k, temp_var in temp_d.items()):
                    return temp_x
        return None

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def search_in_mitre_and_return(self, temp_s, temp_d, temp_r):
        '''
        fine item and return
        '''
        temp_l = []
        for temp_x in temp_s:
            if all((temp_k in temp_x and temp_x[temp_k] == temp_var) for temp_k, temp_var in temp_d.items()):
                temp_l.append({key:temp_x.get(key) for key in temp_r})
        return temp_l

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def nested_search(self, temp_k, temp_d):
        '''
        needs double check
        '''
        if temp_k in temp_d:
            return temp_d[temp_k]
        for temp_k, temp_var in temp_d.items():
            if isinstance(temp_var, dict):
                result = self.nested_search(temp_k, temp_var)
                if result:
                    return temp_k, result

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def findid(self, temp_s, _print):
        '''
        find by id
        '''
        temp_l = {}
        for temp_x in temp_s[0]:
            if temp_x['type'] == 'attack-pattern':
                if temp_x['id'] not in temp_l:
                    temp_l.update({temp_x['id']:temp_x['name']})
            if isinstance(temp_x['description'], list):
                for temp_d in temp_x['description']:
                    if temp_d['type'] == 'attack-pattern':
                        if temp_d['id'] not in temp_l:
                            temp_l.update({temp_d['id']:temp_d['name']})
        if _print:
            print(dumps(temp_l, indent=4, sort_keys=True))
        return temp_l

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def countitem(self, temp_s, temp_k):
        '''
        count
        '''
        return Counter([temp_d[temp_k] for temp_d in temp_s])

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def finduses(self):
        '''
        find all relationship_type uses value and parse them into hardcoded list 
        '''
        temp_l = self.search_in_mitre_and_return(self.fulldict, {'relationship_type':'uses'}, ['source_ref', 'target_ref', 'description', 'collection'])
        temp_d = {}
        for temp_i in temp_l:
            temp_s = self.search_once(self.fulldict, {'id':temp_i['source_ref']})
            temp_u = self.search_once(self.fulldict, {'id':temp_i['target_ref']})
            temp_xx = None
            with ignore_excpetion(Exception):
                temp_xx = temp_u['external_references'][0]['external_id']
            if temp_s and temp_u:
                if temp_d.get(temp_s['type'.lower().rstrip()]):
                    if temp_d[temp_s['type']].get(temp_s['name']) == [] or temp_d[temp_s['type']].get(temp_s['name']):
                        temp_d[temp_s['type']][temp_s['name']].append({'id':temp_xx, 'name':temp_u['name'], 'type':temp_u['type'], 'description':temp_i['description'], 'collection':temp_i['collection']})
                    else:
                        temp_d[temp_s['type']].update({temp_s['name']:[{'id':temp_xx, 'name':temp_u['name'], 'type':temp_u['type'], 'description':temp_i['description'], 'collection':temp_i['collection']}]})
                else:
                    temp_d.update({temp_s['type'].lower().rstrip():{temp_s['name']:[{'id':temp_xx, 'name':temp_u['name'], 'type':temp_u['type'], 'description':temp_i['description'], 'collection':temp_i['collection']}]}})
        for temp_i in temp_d['intrusion-set']:
            for temp_ii in temp_d['intrusion-set'][temp_i]:
                if temp_ii['type'] == 'malware' or temp_ii['type'] == 'tool':
                    temp_ii['description'] = []
                    for temp_x in temp_d[temp_ii['type']][temp_ii['name']]:
                        temp_xx = self.search_once(self.fulldict, {'name':temp_x['name']})
                        temp_ii['description'].append({'id':temp_xx['external_references'][0]['external_id'], 'name':temp_x['name'], 'type':temp_x['type']})
        return temp_d

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def findapt(self, apt, _print=False):
        '''
        find an apt group from the hardocded list (Name is case sensitive)
        '''
        temp_x = self.usedict['intrusion-set'][apt]
        temp_c = self.countitem(temp_x, 'collection')
        if _print:
            print(dumps([temp_x, temp_c], indent=4, sort_keys=True))
        return [temp_x, temp_c]

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def listapts(self, _print=False):
        '''
        list all apts from hardocded list
        '''
        temp_x = list(self.usedict['intrusion-set'])
        if _print:
            print(dumps(temp_x, indent=4, sort_keys=True))
        return temp_x

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def findmalware(self, malware, _print=False):
        '''
        find malware from the hardocded list (Name is case sensitive)
        '''
        if malware in self.usedict['malware']:
            temp_x = self.usedict['malware'][malware]
            #temp_c = self.countitem(temp_x, 'collection')
            if _print:
                print(dumps(temp_x, indent=4, sort_keys=True))
            else:
                return temp_x
        return None

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def findtool(self, tool, _print=False):
        '''
        find tool from the hardocded list (Name is case sensitive)
        '''
        if tool in self.usedict['tool']:
            temp_x = self.usedict['tool'][tool]
            #temp_c = self.countitem(temp_x, 'collection')
            if _print:
                print(dumps(temp_x, indent=4, sort_keys=True))
            else:
                return temp_x
        return None

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def findword(self, word, _print=False):
        '''
        search for specific word in the files (case insensitive)
        '''
        temp_x = {}
        pattern = rcompile(r'(^.*%s.*$)' % word, 8|2)
        temp_x['enterpriseattack'] = list(set(findall(pattern, self.enterprise)))
        temp_x['preattack'] = list(set(findall(pattern, self.preattack)))
        if _print:
            print(dumps(temp_x, indent=4, sort_keys=True))
        return temp_x
