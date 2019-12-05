__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.funcs import getwords,getentropy
from magic import from_file,Magic
from ssdeep import hash_from_file
from bs4 import BeautifulSoup
from urllib.parse import unquote

class HTMLParser():
    @verbose(True,verbose_flag, "Starting HTMLParser")
    def __init__(self):
        '''
        initialize class
        '''

    @verbose(True,verbose_flag,None)
    def geta(self,data,soup):
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

    @verbose(True,verbose_flag,None)
    def getscripts(self,data,soup):
        scripts = soup.findAll("script")
        for script in scripts:
            if script.text != "":
                entropy = getentropy(script.text)
            else: 
                entropy = None
            data.append({"line":script.sourceline,
                         "Entropy":entropy,
                         "type":script.get("type"),
                         "src":script.get("src"),
                         "text":script.text})

    @verbose(True,verbose_flag,None)
    def getiframes(self,data,soup):
        iframes = soup.findAll("iframe")
        for iframe in iframes:
            data.append({"line":iframe.sourceline,
                         "frameborder":iframe.get("frameborder"),
                         "widthxheight":"{}x{}".format(iframe.get("width"),iframe.get("height")),
                         "scr":iframe.get("src"),
                         "text":iframe.text})

    @verbose(True,verbose_flag,None)
    def getlinks(self,data,soup):
        links = soup.findAll("link")
        for link in links:
            data.append({"line":link.sourceline,
                         "type":link.get("type"),
                         "rel":link.get("rel"),
                         "href":link.get("href"),
                         "text":link.text})

    @verbose(True,verbose_flag,None)
    def getforms(self,data,soup):
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

    @verbose(True,verbose_flag,None)
    def getallhrefs(self,data,soup):
        hrefs = soup.findAll(href=True)
        for href in hrefs:
            data.append({"line":href.sourceline,
                         "href":self.unquotefunc(href.get("href"),10)})

    @verbose(True,verbose_flag,None)
    def getallsrcs(self,data,soup):
        srcs = soup.findAll(src=True)
        for src in srcs:
            data.append({"line":src.sourceline,
                         "src":self.unquotefunc(src.get("src"),10)})

    @verbose(True,verbose_flag,None)
    def unquotefunc(self,str,num):
        while num > 0:
            return self.unquotefunc(unquote(str),num-1)
        return str

    @verbose(True,verbose_flag,None)
    def checkhtmlsig(self,data) -> bool:
        '''
        check if file is html/htm
        '''
        #if data["FilesDumps"][data["Location"]["File"]].lower()[:4] == b"<htm":
        #    return True
        if bool(BeautifulSoup(data["FilesDumps"][data["Location"]["File"]].lower(), "html.parser").find()):
            return True

    @verbose(True,verbose_flag, "Starting analyzing html/htm")
    def checkhtml(self, data):
        '''
        start analyzing exe logic, add descriptions and get words and wordsstripped from array 
        '''
        data["HTML"] = { "A": [],
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

        f = data["FilesDumps"][data["Location"]["File"]].lower()
        soup = BeautifulSoup(f, 'html.parser')
        self.getallhrefs(data["HTML"]["hrefs"],soup)
        self.getallsrcs(data["HTML"]["srcs"],soup)
        self.geta(data["HTML"]["A"],soup)
        self.getscripts(data["HTML"]["Scripts"],soup)
        self.getiframes(data["HTML"]["Iframes"],soup)
        self.getlinks(data["HTML"]["Links"],soup)
        self.getforms(data["HTML"]["Forms"],soup)
        getwords(data,data["Location"]["File"])