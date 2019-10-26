__G__ = "(G)bd249ce4"

from .logger.logger import logstring,verbose,verbose_flag
from .mics.qprogressbar import progressbar
from .mics.funcs import getwords, getwordsmultifiles
from .modules.binaries.linuxelf import LinuxELF
from .modules.binaries.macho import Macho
from .modules.binaries.windowspe import WindowsPe
from .modules.binaries.apkparser import ApkParser
from .modules.binaries.blackberry import BBParser
from .modules.network.readpackets import ReadPackets
from .modules.network.wafdetect import WafDetect
from .modules.email.emailparser import EmailParser
from .modules.files.filetypes import FileTypes
from .modules.files.pdfparser import PDFParser
from .modules.files.officex import Officex
from .modules.files.rtfparser import RTFParser
from .yara.yaraparser import YaraParser
from .intell.qbstrings import QBStrings
from .intell.qbimage import QBImage
from .intell.qbintell import QBIntell
from .intell.qbxrefs import QBXrefs
from .intell.qbocrdetect import QBOCRDetect
from .intell.qbencryption import QBEncryption
from .modules.network.urlsimilarity import URLSimilarity
from .report.htmlmaker import HtmlMaker
from .mitre.mitreparser import MitreParser
from .mitre.qbmitresearch import QBMitresearch
from webbrowser import open_new_tab
from os import path
from sys import getsizeof
from gc import collect
#import libarchive

class StaticAnalyzer:
    @progressbar(True,"Starting StaticAnalyzer")
    def __init__(self):
        '''
        initialize class, and all modules 
        '''
        self.mit = MitreParser()
        self.qbm = QBMitresearch(self.mit)
        self.qbs = QBStrings()
        self.wpe = WindowsPe(self.qbs)
        self.elf = LinuxELF(self.qbs)
        self.mac = Macho(self.qbs)
        self.apk = ApkParser(self.qbs)
        self.bbl = BBParser()
        self.yar = YaraParser()
        self.waf = WafDetect()
        self.rpc = ReadPackets(self.qbs,self.waf)
        self.qbi = QBImage()
        self.hge = HtmlMaker(self.qbi)
        self.epa = EmailParser()
        self.qbt = QBIntell()
        self.qbx = QBXrefs()
        self.qoc = QBOCRDetect()
        self.urs = URLSimilarity()
        self.fty = FileTypes()
        self.pdf = PDFParser()
        self.ofx = Officex()
        self.rtf = RTFParser()
        self.qbe = QBEncryption()

    def openinbrowser(self,_path):
        '''
        open html file in default browser
        '''
        open_new_tab(_path)

    @verbose(verbose_flag)
    def analyze(self,parsed):
        '''
        main analyze logic!

        Args:
            parsed: namespace contains parsed arguments
        '''
        data = {}        #if parsed.yara or parsed.full:
        if not self.fty.checkfilesig(data,parsed.file,parsed.output):
            return
        if self.pdf.checkpdfsig(data):
            self.pdf.checkpdf(data)
        elif self.wpe.checkpesig(data):
            self.wpe.getpedeatils(data)
            if parsed.intel or parsed.full:
                self.qbt.checkwithqbintell(data,"winapi.json")
            if parsed.xref or parsed.full:
                self.qbx.makexref(data)
        elif self.elf.checkelfsig(data):
            self.elf.getelfdeatils(data)
            if parsed.xref or parsed.full:
                self.qbx.makexref(data)
        elif self.mac.checkmacsig(data):
            self.mac.getmachodeatils(data)
        elif self.mac.checkdmgsig(data):
            self.mac.getdmgdeatils(data)
        elif self.apk.checkapksig(data):
            self.apk.analyzeapk(data)
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
        if parsed.topurl or parsed.full:
            self.urs.checkwithurls(data)
        if parsed.ocr or parsed.full:
            self.qoc.checkwithocr(data)
        if parsed.mitre or parsed.full:
            self.qbm.checkwithmitre(data)
        if parsed.enc or parsed.full:
            self.qbe.checkencryption(data)
        logstring("Size of data is ~{} bytes".format(getsizeof(str(data))),"Yellow")
        self.hge.rendertemplate(data,None,None)
        if path.exists(data["Location"]["html"]):
            logstring("Generated Html file {}".format(data["Location"]["html"]),"Yellow")
            self.openinbrowser(data["Location"]["html"])
        #d = self.convert(data)
        #with open(data["Location"]["json"], 'w') as fp:
        #    dump(d, fp)
