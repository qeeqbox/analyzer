__G__ = "(G)bd249ce4"

from analyzer.logger.logger import log_string,verbose,verbose_flag,verbose_timeout
from analyzer.modules.qbfile import QBFile
from analyzer.modules.qbencoding import QBEncdoing
from analyzer.modules.linuxelf import LinuxELF
from analyzer.modules.macho import Macho
from analyzer.modules.windowspe import WindowsPe
from analyzer.modules.apkparser import ApkParser
from analyzer.modules.blackberry import BBParser
from analyzer.modules.readpackets import ReadPackets
from analyzer.modules.emailparser import EmailParser
from analyzer.modules.msgparser import MSGParser
from analyzer.modules.pdfparser import PDFParser
from analyzer.modules.officex import Officex
from analyzer.modules.htmlparser import HTMLParser
from analyzer.modules.oleparser import OLEParser
from analyzer.yara.yaraparser import YaraParser
from analyzer.intell.qblanguage import QBLanguage
from analyzer.intell.qbsuspicious import QBSuspicious
from analyzer.intell.qbbehavior import QBBehavior
from analyzer.intell.qbd3generator import QBD3generator
from analyzer.intell.qbocrdetect import QBOCRDetect
from analyzer.intell.qbencryption import QBEncryption
from analyzer.intell.qbwafdetect import QBWafDetect
from analyzer.intell.qbcreditcards import QBCreditcards
from analyzer.intell.qbcredentials import QBCredentials
from analyzer.intell.qbpatterns import QBPatterns
from analyzer.intell.qbdga import QBDGA
from analyzer.intell.qbcountriesviz import QBCountriesviz
from analyzer.intell.qburlsimilarity import QBURLSimilarity
from analyzer.intell.qbwhitelist import QBWhitelist
from analyzer.intell.qbphishing import QBPhishing
from analyzer.snort.qbsnort import QBSnort
from analyzer.qbdetect.loaddetections import LoadDetections
from analyzer.mitre.mitreparser import MitreParser
from analyzer.mitre.qbmitresearch import QBMitresearch
from analyzer.services.online.onlinemultiscanners import OnlineMultiScanners

class Analyzer:
    @verbose(True,verbose_flag,verbose_timeout,"Starting Analyzer")
    def __init__(self):
        '''
        initialize class, and all modules 
        '''
        self.qbfile = QBFile()
        self.qbmitresearch = QBMitresearch(MitreParser)
        self.windowspe = WindowsPe()
        self.linuxelf = LinuxELF()
        self.macho = Macho()
        self.apkparser = ApkParser()
        self.blackberry = BBParser()
        self.yaraparser = YaraParser()
        self.readpackets = ReadPackets(QBWafDetect)
        self.emailparser = EmailParser()
        self.msgparser = MSGParser()
        self.qbbehavior = QBBehavior()
        self.qbd3generator = QBD3generator()
        self.qbocrdetect = QBOCRDetect()
        self.qburlsimilarity = QBURLSimilarity()
        self.pdfparser = PDFParser()
        self.officex = Officex()
        self.qbencryption = QBEncryption()
        self.qbcreditcards = QBCreditcards()
        self.qbpatterns = QBPatterns()
        self.loaddetections = LoadDetections()
        self.qblanguage = QBLanguage()
        self.qbsuspicious = QBSuspicious()
        self.qbdga = QBDGA()
        self.qbcountriesviz = QBCountriesviz()
        self.qbencoding = QBEncdoing()
        self.qbcreditcardsedentials = QBCredentials()
        self.qbwhitelist = QBWhitelist()
        self.htmlparser = HTMLParser()
        self.qbphising = QBPhishing()
        self.oleparser = OLEParser()
        self.onlinemultiscanners = OnlineMultiScanners()
        self.qbsnort = QBSnort()
    
    @verbose(True,verbose_flag,verbose_timeout,"Starting Analyzer",extra="analyzer")
    def analyze(self,parsed) -> dict:
        '''
        main analyze logic!
        '''

        data = {}

        log_string("Start analyzing {}".format(parsed.file),"Yellow")

        self.qbfile.analyze(data,parsed.uuid,parsed.file,parsed.output)
        self.qbencoding.analyze(data,parsed.file,parsed.unicode)

        if self.pdfparser.check_sig(data):
            self.pdfparser.analyze(data)
        elif self.windowspe.check_sig(data):
            self.windowspe.analyze(data)
            if parsed.behavior or parsed.full:
                self.qbbehavior.analyze(data,"winapi.json")
            if parsed.xref or parsed.full:
                self.qbd3generator.create_d3_ref(data)
        elif self.linuxelf.check_sig(data):
            self.linuxelf.analyze(data)
            if parsed.xref or parsed.full:
                self.qbd3generator.create_d3_ref(data)
            if parsed.behavior or parsed.full:
                self.qbbehavior.analyze(data,"linux.json")
        elif self.macho.check_sig_macho(data):
            self.macho.analyze_macho(data)
        elif self.macho.check_sig_dmg(data):
            self.macho.analyze_dmg(data)
        elif self.apkparser.check_sig_apk(data):
            self.apkparser.analyze_apk(data)
            if parsed.behavior or parsed.full:
                self.qbbehavior.analyze(data,"android.json")
        elif self.apkparser.check_sig_dex(data):
            self.apkparser.analyze_dex(data)
            if parsed.behavior or parsed.full:
                self.qbbehavior.analyze(data,"android.json")
        elif self.blackberry.check_sig(data):
            self.blackberry.analyze(data)
        elif self.emailparser.check_sig(data):
            self.emailparser.analyze(data,parsed)
        elif self.msgparser.check_sig(data):
            self.msgparser.analyze(data,parsed)
        elif self.readpackets.check_sig(data):
            self.readpackets.analyze(data)
            self.qbsnort.analyze(data)
            if parsed.dga or parsed.full:
                self.qbdga.analyze(data)
        elif self.officex.check_sig(data):
            self.officex.analyze(data)
        elif self.htmlparser.check_sig(data):
            self.htmlparser.analyze(data)
        elif self.oleparser.check_sig(data):
            self.oleparser.analyze(data)
        else:
            self.qbfile.check_sig(data)
            if parsed.behavior or parsed.full:
                self.qbbehavior.analyze(data,"winapi.json")
                self.qbbehavior.analyze(data,"linux.json")
                self.qbbehavior.analyze(data,"android.json")
        if parsed.w_internal or parsed.w_original or parsed.w_hash or parsed.w_words or parsed.w_all or parsed.full:
            self.qbwhitelist.analyze(data,parsed)
        if parsed.language or parsed.full:
            self.qblanguage.analyze(data,parsed)
        if parsed.phishing or parsed.full:
            self.qbphising.analyze(data,parsed)
        if parsed.patterns or parsed.full:
            self.qbpatterns.analyze(data)
        if parsed.suspicious or parsed.full:
            self.qbsuspicious.analyze(data)
        if parsed.topurl or parsed.full:
            self.qburlsimilarity.analyze(data)
        if parsed.ocr or parsed.full:
            self.qbocrdetect.analyze(data)
        if parsed.enc or parsed.full:
            self.qbencryption.analyze(data)
        if parsed.cards or parsed.full:
            self.qbcreditcards.analyze(data)
        if parsed.creds or parsed.full:
            self.qbcreditcardsedentials.analyze(data)
        if parsed.plugins or parsed.full:
            self.loaddetections.checkwithdetections(data)
        if parsed.mitre or parsed.full:
            self.qbmitresearch.analyze(data)
        if parsed.yara or parsed.full:
            self.yaraparser.checkwithyara(data,None)
        if parsed.ms_all or parsed.full:
            self.onlinemultiscanners.analyze(data,parsed)
        if parsed.visualize or parsed.full:
            self.qbd3generator.create_d3_artifacts(data)
        if parsed.flags or parsed.full:
            self.qbcountriesviz.get_flags_from_codes(data)
        if parsed.worldmap or parsed.full:
            self.qbcountriesviz.get_all_codes(data)

        return data
