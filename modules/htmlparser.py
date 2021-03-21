'''
    __G__ = "(G)bd249ce4"
    modules -> html
'''

from copy import deepcopy
from urllib.parse import unquote
from bs4 import BeautifulSoup
from analyzer.logger.logger import verbose
from analyzer.mics.funcs import get_words, get_entropy


class HTMLParser():
    '''
    HTMLParser extract artifacts from html
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting HTMLParser")
    def __init__(self):
        '''
        initialize class and datastruct, this has to pass
        '''
        self.datastruct = {"A": [],
                           "Scripts": [],
                           "Iframes": [],
                           "Links": [],
                           "Forms": [],
                           "hrefs": [],
                           "srcs": [],
                           "_hrefs": ["line", "href"],
                           "_srcs": ["line", "src"],
                           "_A": ["line", "type", "href", "title", "text"],
                           "_Scripts": ["line", "Entropy", "type", "src", "text"],
                           "_Iframes": ["line", "frameborder", "widthxheight", "scr", "text"],
                           "_Links": ["line", "type", "rel", "href", "text"],
                           "_Forms": ["line", "action", "type", "id", "name", "value", "text"]}

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_a(self, data, soup):
        '''
        get all links (maybe add url analysis later on)
        '''
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
            data.append({"line": link.sourceline,
                         "type": temp,
                         "href": link.get("href"),
                         "title": link.get("title"),
                         "text": link.text})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_scripts(self, data, soup):
        '''
        get all scripts (maybe add script analysis later on)
        '''
        scripts = soup.findAll("script")
        for script in scripts:
            if script.text != "":
                entropy = get_entropy(script.text)
            else:
                entropy = None
            data.append({"line": script.sourceline,
                         "Entropy": entropy,
                         "type": script.get("type"),
                         "src": script.get("src"),
                         "text": script.text})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_iframes(self, data, soup):
        '''
        get all iframes
        '''
        iframes = soup.findAll("iframe")
        for iframe in iframes:
            data.append({"line": iframe.sourceline,
                         "frameborder": iframe.get("frameborder"),
                         "widthxheight": "{}x{}".format(iframe.get("width"), iframe.get("height")),
                         "scr": iframe.get("src"),
                         "text": iframe.text})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_links(self, data, soup):
        '''
        get all links
        '''
        links = soup.findAll("link")
        for link in links:
            data.append({"line": link.sourceline,
                         "type": link.get("type"),
                         "rel": link.get("rel"),
                         "href": link.get("href"),
                         "text": link.text})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_forms(self, data, soup):
        '''
        get all forms
        '''
        forms = soup.findAll("form")
        for form in forms:
            inputs = form.findAll('input')
            for _input in inputs:
                data.append({"line": _input.sourceline,
                             "action": form.get("action"),
                             "type": _input.get("type"),
                             "id": _input.get("id"),
                             "name": _input.get("name"),
                             "value": _input.get("value"),
                             "text": _input.text})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_all_hrefs(self, data, soup):
        '''
        get all herfs
        '''
        hrefs = soup.findAll(href=True)
        for href in hrefs:
            data.append({"line": href.sourceline,
                         "href": self.unquote_func(href.get("href"), 10)})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_all_srcs(self, data, soup):
        '''
        get all src
        '''
        srcs = soup.findAll(src=True)
        for src in srcs:
            data.append({"line": src.sourceline,
                         "src": self.unquote_func(src.get("src"), 10)})

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def unquote_func(self, _str, num):
        '''
        unqoute string
        '''
        while num > 0:
            return self.unquote_func(unquote(_str), num - 1)
        return _str

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig(self, data) -> bool:
        '''
        check if file is html/htm
        '''
        if data["FilesDumps"][data["Location"]["File"]].lower()[:4] == b"<htm" or data["FilesDumps"][data["Location"]["File"]].lower().startswith(b"<!doctype htm"):
            return True
        return False
        # if bool(BeautifulSoup(data["FilesDumps"][data["Location"]["File"]].lower(), "html.parser").find()):
        #    return True

    @verbose(True, verbose_output=False, timeout=None, _str="Starting analyzing html/htm")
    def analyze(self, data):
        '''
        start analyzing exe logic, add descriptions and get words and wordsstripped from array
        '''
        data["HTML"] = deepcopy(self.datastruct)
        temp_f = data["FilesDumps"][data["Location"]["File"]].lower()
        soup = BeautifulSoup(temp_f, 'html.parser')
        self.get_all_hrefs(data["HTML"]["hrefs"], soup)
        self.get_all_srcs(data["HTML"]["srcs"], soup)
        self.get_a(data["HTML"]["A"], soup)
        self.get_scripts(data["HTML"]["Scripts"], soup)
        self.get_iframes(data["HTML"]["Iframes"], soup)
        self.get_links(data["HTML"]["Links"], soup)
        self.get_forms(data["HTML"]["Forms"], soup)
        get_words(data, data["Location"]["File"])
