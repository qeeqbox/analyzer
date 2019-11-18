__G__ = "(G)bd249ce4"

from .logger.logger import logstring,verbose,verbose_flag
from .mics.qprogressbar import progressbar
from .mics.funcs import getwords, getwordsmultifiles
from .modules.linuxelf import LinuxELF
from .modules.macho import Macho
from .modules.windowspe import WindowsPe
from .modules.apkparser import ApkParser
from .modules.blackberry import BBParser
from .modules.readpackets import ReadPackets
from .modules.emailparser import EmailParser
from .modules.filetypes import FileTypes
from .modules.pdfparser import PDFParser
from .modules.officex import Officex
from .modules.rtfparser import RTFParser
from .yara.yaraparser import YaraParser
from .intell.qbstrings import QBStrings
from .intell.qbimage import QBImage
from .intell.qbintell import QBIntell
from .intell.qbd3generator import QBD3generator
from .intell.qbocrdetect import QBOCRDetect
from .intell.qbencryption import QBEncryption
from .intell.qbwafdetect import QBWafDetect
from .intell.qbcreditcards import QBCreditcards
from .intell.qbpatterns import QBPatterns
from .qbdetect.loaddetections import LoadDetections
from .modules.urlsimilarity import URLSimilarity
from .report.htmlmaker import HtmlMaker
from .mitre.mitreparser import MitreParser
from .mitre.qbmitresearch import QBMitresearch
from webbrowser import open_new_tab
from os import path
from sys import getsizeof
from gc import collect
from pickle import dump as pdump,HIGHEST_PROTOCOL
from json import dump as jdump
from json import JSONEncoder

#import libarchive


class ComplexEncoder(JSONEncoder):
    def default(self, obj):
        if not isinstance(obj, str):
            return "Object type {} was removed..".format(type(obj))
        return JSONEncoder.default(self, obj)

class StaticAnalyzer:
    @progressbar(True,"Starting StaticAnalyzer")
    def __init__(self):
        '''
        initialize class, and all modules 
        '''
        self.mit = MitreParser()
        self.qbm = QBMitresearch(self.mit)
        self.qbs = QBStrings()
        self.wpe = WindowsPe()
        self.elf = LinuxELF()
        self.mac = Macho()
        self.apk = ApkParser()
        self.bbl = BBParser()
        self.yar = YaraParser()
        self.waf = QBWafDetect()
        self.rpc = ReadPackets(self.waf)
        self.qbi = QBImage()
        self.hge = HtmlMaker(self.qbi)
        self.epa = EmailParser()
        self.qbt = QBIntell()
        self.qb3 = QBD3generator()
        self.qoc = QBOCRDetect()
        self.urs = URLSimilarity()
        self.fty = FileTypes()
        self.pdf = PDFParser()
        self.ofx = Officex()
        self.rtf = RTFParser()
        self.qbe = QBEncryption()
        self.qbcr = QBCreditcards()
        self.qbp = QBPatterns()
        self.LD = LoadDetections()

    @verbose(verbose_flag)
    def analyze(self,parsed):
        '''
        main analyze logic!

        Args:
            parsed: namespace contains parsed arguments
        '''
        data = {}
        if not self.fty.checkfilesig(data,parsed.file,parsed.output):
            return
        if self.pdf.checkpdfsig(data):
            self.pdf.checkpdf(data)
        elif self.wpe.checkpesig(data):
            self.wpe.getpedeatils(data)
            if parsed.intel or parsed.full:
                self.qbt.checkwithqbintell(data,"winapi.json")
            if parsed.xref or parsed.full:
                self.qb3.makexref(data)
        elif self.elf.checkelfsig(data):
            self.elf.getelfdeatils(data)
            if parsed.xref or parsed.full:
                self.qb3.makexref(data)
            if parsed.intel or parsed.full:
                self.qbt.checkwithqbintell(data,"linux.json")
        elif self.mac.checkmacsig(data):
            self.mac.getmachodeatils(data)
        elif self.mac.checkdmgsig(data):
            self.mac.getdmgdeatils(data)
        elif self.apk.checkapksig(data):
            self.apk.analyzeapk(data)
            if parsed.intel or parsed.full:
                self.qbt.checkwithqbintell(data,"android.json")
        elif self.apk.checkdexsig(data):
            self.apk.analyzedex(data)
            if parsed.intel or parsed.full:
                self.qbt.checkwithqbintell(data,"android.json")
        elif self.bbl.checkbbsig(data):
            self.bbl.getbbdeatils(data)
        elif self.epa.checkemailsig(data):
            self.epa.getemail(data)
        elif self.rpc.checkpcapsig(data):
            self.rpc.getpacpdetails(data)
        elif self.ofx.checkofficexsig(data):
            self.ofx.checkofficex(data)
        elif self.rtf.checkrtfsig(data):
            self.rtf.checkrtf(data)
        else:
            self.fty.unknownfile(data)
        if parsed.yara or parsed.full:
            self.yar.checkwithyara(data,None)
        if parsed.string or parsed.full:
            self.qbs.checkwithstring(data)
        if parsed.patterns or parsed.full:
            self.qbp.checkpatterns(data)
        if parsed.topurl or parsed.full:
            self.urs.checkwithurls(data)
        if parsed.ocr or parsed.full:
            self.qoc.checkwithocr(data)
        if parsed.enc or parsed.full:
            self.qbe.checkencryption(data)
        if parsed.cards or parsed.full:
            self.qbcr.checkcreditcards(data)
        if parsed.plugins or parsed.full:
            self.LD.checkwithdetections(data)
        if parsed.mitre or parsed.full:
            self.qbm.checkwithmitre(data)
        if parsed.visualize or parsed.full:
            self.qb3.makeartifactsd3(data)
        with open('temp.pickle', 'wb') as handle:
            pdump(data, handle, protocol=HIGHEST_PROTOCOL)
        logstring("Size of data is ~{} bytes".format(getsizeof(str(data))),"Yellow")
        self.hge.rendertemplate(data,None,None)
        if path.exists(data["Location"]["html"]):
            logstring("Generated Html file {}".format(data["Location"]["html"]),"Yellow")
            self.openinbrowser(data["Location"]["html"])
        if parsed.json or parsed.full:
            with open(data["Location"]["json"], 'w') as fp:
                jdump(data, fp, cls=ComplexEncoder)

    def openinbrowser(self,_path):
        '''
        open html file in default browser
        '''
        open_new_tab(_path)