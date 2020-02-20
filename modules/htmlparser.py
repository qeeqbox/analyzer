__G__ = "(G)bd249ce4"

from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout
from analyzer.mics.funcs import get_words,get_entropy
from bs4 import BeautifulSoup
from urllib.parse import unquote
from copy import deepcopy

class HTMLParser():
    @verbose(True,verbose_flag,verbose_timeout,"Starting HTMLParser")
    def __init__(self):
        '''
        initialize class
        '''
        self.datastruct = {  "A": [],
                             "Scripts":[],
                             "Iframes":[],
                             "Links":[],
                             "Forms":[],
                             "hrefs":[],
                             "srcs":[],
                             "_hrefs":["line","href"],
                             "_srcs":["line","src"],
                             "_A": ["line","type","href","title","text"],
                             "_Scripts":["line","Entropy","type","src","text"],
                             "_Iframes":["line","frameborder","widthxheight","scr","text"],
                             "_Links":["line","type","rel","href","text"],
                             "_Forms":["line","action","type","id","name","value","text"]}


    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_a(self,data,soup):
        links = soup.findAll("a")
        for link in links:
            temp = "Anchor"
            if "href" in link:
                if link["href"].find('tel:') > -1:
                    temp = "tel"
                elif link["href"].find('mailto:') > -1:
                    temp = "mailto"
                elif link["href"].find('sms:') > -1:
                    temp = "sms"
                elif link["href"].find('market:') > -1:
                    temp = "market"
                elif link["href"].find('whatsapp:') > -1:
                    temp = "whatsapp"
                elif link["href"].find('sip:') > -1:
                    temp = "sip"
                elif link["href"].find('skype:') > -1:
                    temp = "skype"
                elif link["href"].find('geopoint:') > -1:
                    temp = "geopoint"
                elif link["href"].find('callto:') > -1:
                    temp = "callto"
                elif link["href"].find('wtai:') > -1:
                    temp = "wtai"
                elif link["href"].find('geo:') > -1:
                    temp = "geo"
                elif link["href"].find('ftp:') > -1:
                    temp = "ftp"
            data.append({"line":link.sourceline,
                         "type":temp,
                         "href":link.get("href"),
                         "title":link.get("title"),
                         "text":link.text})

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_scripts(self,data,soup):
        scripts = soup.findAll("script")
        for script in scripts:
            if script.text != "":
                entropy = get_entropy(script.text)
            else: 
                entropy = None
            data.append({"line":script.sourceline,
                         "Entropy":entropy,
                         "type":script.get("type"),
                         "src":script.get("src"),
                         "text":script.text})

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_iframes(self,data,soup):
        iframes = soup.findAll("iframe")
        for iframe in iframes:
            data.append({"line":iframe.sourceline,
                         "frameborder":iframe.get("frameborder"),
                         "widthxheight":"{}x{}".format(iframe.get("width"),iframe.get("height")),
                         "scr":iframe.get("src"),
                         "text":iframe.text})

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_links(self,data,soup):
        links = soup.findAll("link")
        for link in links:
            data.append({"line":link.sourceline,
                         "type":link.get("type"),
                         "rel":link.get("rel"),
                         "href":link.get("href"),
                         "text":link.text})

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_forms(self,data,soup):
        forms = soup.findAll("form")
        for form in forms:
            inputs = form.findAll('input')
            for input in inputs:
                data.append({"line":input.sourceline,
                             "action":form.get("action"),
                             "type":input.get("type"),
                             "id":input.get("id"),
                             "name":input.get("name"),
                             "value":input.get("value"),
                             "text":input.text})

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_all_hrefs(self,data,soup):
        hrefs = soup.findAll(href=True)
        for href in hrefs:
            data.append({"line":href.sourceline,
                         "href":self.unquote_func(href.get("href"),10)})

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_all_srcs(self,data,soup):
        srcs = soup.findAll(src=True)
        for src in srcs:
            data.append({"line":src.sourceline,
                         "src":self.unquote_func(src.get("src"),10)})

    @verbose(True,verbose_flag,verbose_timeout,None)
    def unquote_func(self,str,num):
        while num > 0:
            return self.unquote_func(unquote(str),num-1)
        return str

    @verbose(True,verbose_flag,verbose_timeout,None)
    def check_sig(self,data) -> bool:
        '''
        check if file is html/htm
        '''
        if data["FilesDumps"][data["Location"]["File"]].lower()[:4] == b"<htm" or data["FilesDumps"][data["Location"]["File"]].lower().startswith(b"<!doctype htm"):
            return True
        #if bool(BeautifulSoup(data["FilesDumps"][data["Location"]["File"]].lower(), "html.parser").find()):
        #    return True

    @verbose(True,verbose_flag,verbose_timeout,"Starting analyzing html/htm")
    def analyze(self, data):
        '''
        start analyzing exe logic, add descriptions and get words and wordsstripped from array 
        '''
        data["HTML"] = deepcopy(self.datastruct)
        f = data["FilesDumps"][data["Location"]["File"]].lower()
        soup = BeautifulSoup(f, 'html.parser')
        self.get_all_hrefs(data["HTML"]["hrefs"],soup)
        self.get_all_srcs(data["HTML"]["srcs"],soup)
        self.get_a(data["HTML"]["A"],soup)
        self.get_scripts(data["HTML"]["Scripts"],soup)
        self.get_iframes(data["HTML"]["Iframes"],soup)
        self.get_links(data["HTML"]["Links"],soup)
        self.get_forms(data["HTML"]["Forms"],soup)
        get_words(data,data["Location"]["File"])