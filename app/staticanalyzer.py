__G__ = "(G)bd249ce4"

from .logger.logger import logstring,verbose,verbose_flag,verbose_timeout
from .mics.funcs import getwords, getwordsmultifiles,openinbrowser,serializeobj
from .general.qbfile import QBFile
from .general.qbencoding import QBEncdoing
from .modules.linuxelf import LinuxELF
from .modules.macho import Macho
from .modules.windowspe import WindowsPe
from .modules.apkparser import ApkParser
from .modules.blackberry import BBParser
from .modules.readpackets import ReadPackets
from .modules.emailparser import EmailParser
from .modules.pdfparser import PDFParser
from .modules.officex import Officex
from .modules.rtfparser import RTFParser
from .modules.htmlparser import HTMLParser
from .yara.yaraparser import YaraParser
from .intell.qblanguage import QBLanguage
from .intell.qbsuspicious import QBSuspicious
from .intell.qbimage import QBImage
from .intell.qbicons import QBIcons
from .intell.qbbehavior import QBBehavior
from .intell.qbd3generator import QBD3generator
from .intell.qbocrdetect import QBOCRDetect
from .intell.qbencryption import QBEncryption
from .intell.qbwafdetect import QBWafDetect
from .intell.qbcreditcards import QBCreditcards
from .intell.qbcredentials import QBCredentials
from .intell.qbpatterns import QBPatterns
from .intell.qbdga import QBDGA
from .intell.qbcountriesviz import QBCountriesviz
from .intell.qburlsimilarity import QBURLSimilarity
from .intell.qbwhitelist import QBWhitelist
from .qbdetect.loaddetections import LoadDetections
from .report.htmlmaker import HtmlMaker
from .report.jsonmaker import JSONMaker
from .mitre.mitreparser import MitreParser
from .mitre.qbmitresearch import QBMitresearch
from os import path
from sys import getsizeof
from gc import collect

class StaticAnalyzer:
    @verbose(True,verbose_flag,verbose_timeout,"Starting StaticAnalyzer")
    def __init__(self):
        '''
        initialize class, and all modules 
        '''
        self.fty = QBFile()
        self.qbm = QBMitresearch(MitreParser)
        self.wpe = WindowsPe()
        self.elf = LinuxELF()
        self.mac = Macho()
        self.apk = ApkParser()
        self.bbl = BBParser()
        self.yar = YaraParser()
        self.rpc = ReadPackets(QBWafDetect)
        self.hge = HtmlMaker(QBImage,QBIcons)
        self.epa = EmailParser()
        self.qbt = QBBehavior()
        self.qb3 = QBD3generator()
        self.qoc = QBOCRDetect()
        self.urs = QBURLSimilarity()
        self.pdf = PDFParser()
        self.ofx = Officex()
        self.rtf = RTFParser()
        self.qbe = QBEncryption()
        self.qbcr = QBCreditcards()
        self.qbp = QBPatterns()
        self.LD = LoadDetections()
        self.qbla = QBLanguage()
        self.qbsu = QBSuspicious()
        self.dga = QBDGA()
        self.qbcv = QBCountriesviz()
        self.htm = HTMLParser()
        self.JSO = JSONMaker()
        self.qbenc = QBEncdoing()
        self.qbcs = QBCredentials()
        self.qbwi = QBWhitelist()

    def analyze(self,parsed):
        '''
        main analyze logic!
        '''

        data = {}

        logstring("Start analyzing {}".format(parsed.file),"Green")

        self.fty.checkfilesig(data,parsed.file,parsed.output)
        self.qbenc.checkfile(data,parsed.file,parsed.unicode)

        if self.pdf.checkpdfsig(data):
            self.pdf.checkpdf(data)
        elif self.wpe.checkpesig(data):
            self.wpe.getpedeatils(data)
            if parsed.behavior or parsed.full:
                self.qbt.checkwithqbintell(data,"winapi.json")
            if parsed.xref or parsed.full:
                self.qb3.makexref(data)
        elif self.elf.checkelfsig(data):
            self.elf.getelfdeatils(data)
            if parsed.xref or parsed.full:
                self.qb3.makexref(data)
            if parsed.behavior or parsed.full:
                self.qbt.checkwithqbintell(data,"linux.json")
        elif self.mac.checkmacsig(data):
            self.mac.getmachodeatils(data)
        elif self.mac.checkdmgsig(data):
            self.mac.getdmgdeatils(data)
        elif self.apk.checkapksig(data):
            self.apk.analyzeapk(data)
            if parsed.behavior or parsed.full:
                self.qbt.checkwithqbintell(data,"android.json")
        elif self.apk.checkdexsig(data):
            self.apk.analyzedex(data)
            if parsed.behavior or parsed.full:
                self.qbt.checkwithqbintell(data,"android.json")
        elif self.bbl.checkbbsig(data):
            self.bbl.getbbdeatils(data)
        elif self.epa.checkemailsig(data):
            self.epa.getemail(data)
        elif self.rpc.checkpcapsig(data):
            self.rpc.getpacpdetails(data)
            if parsed.dga or parsed.full:
                self.dga.checkdga(data)
        elif self.ofx.checkofficexsig(data):
            self.ofx.checkofficex(data)
        elif self.rtf.checkrtfsig(data):
            self.rtf.checkrtf(data)
        elif self.htm.checkhtmlsig(data):
            self.htm.checkhtml(data)
        else:
            self.fty.unknownfile(data)
            if parsed.behavior or parsed.full:
                self.qbt.checkwithqbintell(data,"winapi.json")
                self.qbt.checkwithqbintell(data,"linux.json")
                self.qbt.checkwithqbintell(data,"android.json")
        if parsed.w_internal or parsed.w_original or parsed.w_hash or parsed.w_words or parsed.w_all or parsed.full:
            self.qbwi.isitwhitelisted(data,parsed)
        if parsed.language or parsed.full:
            self.qbla.checkwithstring(data)
        if parsed.patterns or parsed.full:
            self.qbp.checkpatterns(data)
        if parsed.suspicious or parsed.full:
            self.qbsu.checksusp(data)
        if parsed.topurl or parsed.full:
            self.urs.checkwithurls(data)
        if parsed.ocr or parsed.full:
            self.qoc.checkwithocr(data)
        if parsed.enc or parsed.full:
            self.qbe.checkencryption(data)
        if parsed.cards or parsed.full:
            self.qbcr.checkcreditcards(data)
        if parsed.creds or parsed.full:
            self.qbcs.checkcreds(data)
        if parsed.plugins or parsed.full:
            self.LD.checkwithdetections(data)
        if parsed.mitre or parsed.full:
            self.qbm.checkwithmitre(data)
        if parsed.yara or parsed.full:
            self.yar.checkwithyara(data,None)
        if parsed.visualize or parsed.full:
            self.qb3.makeartifactsd3(data)
        if parsed.flags or parsed.full:
            self.qbcv.getflagsfromcodes(data)
        if parsed.worldmap or parsed.full:
            self.qbcv.getallcodes(data)
        logstring("Size of data is ~{} bytes".format(getsizeof(str(data))),"Yellow")
        if parsed.html:
            self.hge.rendertemplate(data,None,None,parsed)
            if path.exists(data["Location"]["html"]):
                logstring("Generated Html file {}".format(data["Location"]["html"]),"Yellow")
                if parsed.open:
                    openinbrowser(data["Location"]["html"])
        data = serializeobj(data)
        self.JSO.cleandata(data)
        if parsed.json:
            self.JSO.dumpjson(data)
            if parsed.json:
                if path.exists(data["Location"]["json"]):
                    logstring("Generated JSON file {}".format(data["Location"]["json"]),"Yellow")
                    if parsed.open:
                        openinbrowser(data["Location"]["json"])
                    if parsed.print:
                        self.JSO.printjson(data)
        return data
