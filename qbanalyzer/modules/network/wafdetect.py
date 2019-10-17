__version__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from re import search,compile,I

#need refactoring

@progressbar(True,"Starting WafDetect")
class WafDetect:
    def __init__(self):
        pass

    @progressbar(True,"Checking packets for waf detection")
    def checkpacketsforwaf(self,data):
        _s = {}
        #need dynamic loop
        funcs = ["aesecure","anquanbao","appwall","aspnet","aws","barracuda","bigip","binarysec","blockdos","chinacache","ciscoacexmlgateway","cloudbric","cloudflare","comodo","crawlProtect","distil","dosarrest","dotdefender","edgecast","expressionengine","fortiweb","hyperguard","incapsula","isaserver","jiasule","knownsec","kona","modsecurity","naxsi","netcontinuum","netscaler","newdefend","nsfocus","paloaltofirewall","profense","proventia","reblaze","safe3","safedog","secureiis","senginx","shieldfy","sonicwall","stingray","sucuri","tencent","trafficshield","trueshield","urlmaster","urlscan","usp","utmwebprotection","varnish","viettel","virusdie","wallarm","watchguard","web360","webknight","webscurity","websphere","wordfence","yundun","yunjiasu","yunsuo","zenedge"]
        for _ in data:
            for func in funcs:
                x = getattr(self, func)(_["fields"],_["payload"])
                if x:
                    #one only
                    _s.update(x)
        return _s

    def compileandfind(self,detections,buffer):
        if detections and buffer:
            for detection in detections:
                compileddetection = compile(*detection)
                if isinstance(buffer, str):
                    if search(compileddetection,buffer) is not None:
                        return True
                else:
                    if search(compileddetection,str(buffer)) is not None:
                        return True
        return False
    def shieldfy(self,request,content):
        detect = 'shieldfy Web Application Firewall'
        headerdetections = [('x-web-shield|ShieldfyWebShield',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def cloudflare(self,request,content):
        detect = 'Cloud Flare Web Application Firewall'
        headerdetections = [('cf-ray|cloudflare-nginx|__cfduid',I)]
        contentdetections = [('CLOUDFLARE_ERROR_500S_BOX',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def web360(self,request,content):
        detect = '360 Web Application Firewall'
        headerdetections = [('X-Powered-By-360wzb',I)]
        contentdetections = [('wzws.waf.cgi',I),('wzws-waf-cgi',I),('wzws.waf.cgi',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def aesecure(self,request,content):
        detect = 'aeSecure Web Application Firewall'
        headerdetections = [(r'aeSecure-code',I)]
        contentdetections = [('aesecure_denied.png',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def anquanbao(self,request,content):
        detect = 'Anquanbao Web Application Firewall'
        headerdetections = [('X-Powered-By-Anquanbao',I)]
        contentdetections = [('hidden_intercept_time',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def aws(self,request,content):
        detect = 'Amazon Web Services Web Application Firewall'
        headerdetections = [('AWS',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def barracuda(self,request,content):
        detect = 'Barracuda Web Application Firewall'
        headerdetections = [('barra_counter_session|barracuda',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def bigip(self,request,content):
        detect = 'BIGIP Application Security Manager'
        headerdetections = [('BigIP|X-Cnection:|X-WA-Info:',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def binarysec(self,request,content):
        detect = 'BinarySEC Web Application Firewall'
        headerdetections = [('binarysec',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def blockdos(self,request,content):
        detect = 'BlockDos Web Application Firewall'
        headerdetections = [('BlockDos',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def chinacache(self,request,content):
        detect = 'China Cache'
        headerdetections = [('Powered-By-ChinaCache',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def ciscoacexmlgateway(self,request,content):
        detect = 'Cisco ACE XML Gateway platforms'
        headerdetections = [('ACE XML Gateway',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def cloudbric(self,request,content):
        detect = 'Cloudbric Web Application Firewall'
        headerdetections = [('Cloudbric|Malicious Code Detected',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def comodo(self,request,content):
        detect = 'Comodo Web Application Firewall'
        headerdetections = [('Protected by COMODO WAF',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def crawlProtect(self,request,content):
        detect = 'CrawlProtect Web Application Firewall'
        contentdetections = [('protected by CrawlProtect',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def websphere(self,request,content):
        detect = 'IBM WebSphere DataPower'
        headerdetections = [('X-Backside-Transport',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def distil(self,request,content):
        detect = 'Distil Web Application Firewall Security'
        headerdetections = [('x-distil-cs',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def dosarrest(self,request,content):
        detect = 'DOSarrest Internet Security'
        headerdetections = [('X-DIS-Request-ID|DOSarrest',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def dotdefender(self,request,content):
        detect = 'DotDefender Web Application Security'
        headerdetections = [('X-dotDefender-denied',I)]
        contentdetections = [('dotDefender Blocked Your Request',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def edgecast(self,request,content):
        detect = 'EdgeCast Web Application Security'
        headerdetections = [('ECS \(',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        contentdetections = [('ID:EdgeCast',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def expressionengine(self,request,content):
        detect = 'Expression Engine'
        contentdetections = [('Invalid (GET|POST) Data',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def fortiweb(self,request,content):
        detect = 'FortiWeb Web Application Firewall'
        headerdetections = [('FORTIWAFSID=',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def hyperguard(self,request,content):
        detect = 'Hyperguard Web Application Firewall'
        headerdetections = [('ODSESSION',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def incapsula(self,request,content):
        detect = 'Incapsula Web Application Firewall'
        headerdetections = [('x-cdn|incap_ses',I)]
        contentdetections = [('Incapsula',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def isaserver(self,request,content):
        detect = 'ISA Server'
        contentdetections = [('ISA Server denied',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def jiasule(self,request,content):
        detect = 'Jiasule Web Application Firewall'
        headerdetections = [('jiasule-WAF|__jsluid',I)]
        contentdetections = [('notice-jiasule',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def knownsec(self,request,content):
        detect = 'Knownsec'
        contentdetections = [('ks-waf-error',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def kona(self,request,content):
        detect = 'Jiasule Web Application Firewall'
        headerdetections = [('AkamaiGHost',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def modsecurity(self,request,content):
        detect = 'ModSecurity Web Application Firewall'
        headerdetections = [('Mod_Security|NOYB',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def naxsi(self,request,content):
        detect = 'NAXSI'
        headerdetections = [('naxsi/waf',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def netcontinuum(self,request,content):
        detect = 'NetContinuum Web Application Firewall'
        headerdetections = [('NCI__SessionId',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def netscaler(self,request,content):
        detect = 'NetScaler networking products'
        headerdetections = [('NS-CACHE',I)]
        contentdetections = [('citrix',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def newdefend(self,request,content):
        detect = 'Newdefend Web Application Firewall'
        headerdetections = [('newdefend',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def nsfocus(self,request,content):
        detect = 'NSFOCUS Web Application Firewall'
        headerdetections = [('NSFocus',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def paloaltofirewall(self,request,content):
        detect = 'Palo Alto Firewall'
        contentdetections = [('has been blocked in accordance with company policy',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def profense(self,request,content):
        detect = 'Profense Web Application Firewall'
        headerdetections = [('Profense|PLBSID',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def proventia(self,request,content):
        detect = 'Proventia Web Application Security'
        urldetection = [('Admin_Files',I)]
        if self.compileandfind(urldetection,content):
            return {'True':detect}
    def appwall(self,request,content):
        detect = 'AppWall'
        headerdetections = [('X-SL-CompState',I)]
        contentdetections = [('Unauthorized Activity Has Been Detected',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def reblaze(self,request,content):
        detect = 'Reblaze Web Application Firewall'
        headerdetections = [('rbzid=|Reblaze',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def aspnet(self,request,content):
        detect = 'ASP.NET RequestValidationMode'
        contentdetections = [('HttpRequestValidationException',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def safe3(self,request,content):
        detect = 'Safe3 Web Application Firewall'
        headerdetections = [('Safe3 Web Firewall',I)]
        contentdetections = [('safe3',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def safedog(self,request,content):
        detect = 'safedog Web Application Firewall'
        headerdetections = [('safedog',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def secureiis(self,request,content):
        detect = 'SecureIIS Web Server Security'
        contentdetections = [('secureiis',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def senginx(self,request,content):
        detect = 'SEnginx'
        contentdetections = [('SENGINX-ROBOT-MITIGATION',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def trueshield(self,request,content):
        detect = 'TrueShield Web Application Firewall'
        contentdetections = [('SiteLock Incident ID|sitelock_shield_logo|sitelock-site-verification',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def sonicwall(self,request,content):
        detect = 'SonicWALL Web Application Firewall'
        headerdetections = [('SonicWALL',I)]
        contentdetections = [('SonicWALL',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def utmwebprotection(self,request,content):
        detect = 'UTM Web Protection - Sophos'
        contentdetections = [('Powered by UTM Web Protection',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def stingray(self,request,content):
        detect = 'Stingray Application Firewall'
        headerdetections = [('X-Mapping',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def sucuri(self,request,content):
        detect = 'Safe3 Web Application Firewall'
        headerdetections = [('Sucuri',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def tencent(self,request,content):
        detect = 'Tencent Cloud Web Application Firewall'
        contentdetections = [('tencent',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def trafficshield(self,request,content):
        detect = 'TrafficShield'
        headerdetections = [('F5-TrafficShield|ASINFO',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def urlscan(self,request,content):
        detect = 'UrlScan'
        headerdetections = [('Rejected-By-UrlScan',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def usp(self,request,content):
        detect = 'USP Secure Entry Server'
        headerdetections = [('Secure Entry Server',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def varnish(self,request,content):
        detect = 'Varnish FireWall'
        contentdetections = [('xVarnish',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def wallarm(self,request,content):
        detect = 'Wallarm Web Application Firewall'
        headerdetections = [('nginx-wallarm',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def watchguard(self,request,content):
        detect = 'WatchGuard'
        headerdetections = [('WatchGuard',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def webknight(self,request,content):
        detect = 'WebKnight Application Firewall'
        headerdetections = [('WebKnight',I)]
        contentdetections = [('WebKnight',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def wordfence(self,request,content):
        detect = 'Wordfence'
        contentdetections = [('Wordfence',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def zenedge(self,request,content):
        detect = 'Zenedge Web Application Firewall'
        headerdetections = [('ZENEDGE',I)]
        contentdetections = [('ZENEDGE',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def yundun(self,request,content):
        detect = 'Yundun Web Application Firewall'
        headerdetections = [('Yundun',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def yunsuo(self,request,content):
        detect = 'Safe3 Web Application Firewall'
        headerdetections = [('yunsuo',I)]
        contentdetections = [('yunsuo',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def yunjiasu(self,request,content):
        detect = 'Baidu Web Application Firewall'
        headerdetections = [('yunjiasu-nginx',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def webscurity(self,request,content):
        detect = 'webScurity'
        headerdetections = [('nx=',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def urlmaster(self,request,content):
        detect = 'URLMaster SecurityCheck '
        headerdetections = [('UrlMaster|UrlRewriteModule|SecurityCheck',I)]
        if self.compileandfind(headerdetections,request):
            return {'True':detect}
    def viettel(self,request,content):
        detect = 'Viettel'
        contentdetections = [('yunsuo',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
    def virusdie(self,request,content):
        detect = 'Virusdie'
        contentdetections = [('Virusdie',I)]
        if self.compileandfind(contentdetections,content):
            return {'True':detect}
