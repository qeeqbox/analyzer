'''
    __G__ = "(G)bd249ce4"
    modules -> pcap
'''

from copy import deepcopy
from datetime import datetime
from re import I, search
from re import compile as rcompile
from scapy import all as scapy
from scapy.layers import http
from tldextract import TLDExtract
from analyzer.logger.logger import ignore_excpetion, verbose
from analyzer.mics.funcs import get_words
from analyzer.intell.qbdescription import add_description

class ReadPackets:
    '''
    read packets kinda slow
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting ReadPackets")
    def __init__(self, waf):
        '''
        initialize class and datastruct, this has to pass
        '''
        self.datastruct = {"WAF":[],
                           "URLs":[],
                           "Domains":[],
                           "ARP":[],
                           "DNS":[],
                           "HTTP":[],
                           "ALL":[],
                           "PORTS":[],
                           "IP4S":[],
                           "Flags":[],
                           "_WAF":["Matched", "Required", "WAF", "Detected"],
                           "_Domains":["Time", "subdomain", "domain", "tld"],
                           "_URLs":["Time", "src", "Method", "Host", "Path"],
                           "_ARP":["Time", "Type", "PacketSoruce", "PacketDestination", "Macaddress"],
                           "_DNS":["Time", "Type", "Source", "SourcePort", "Destination", "DestinationPort", "qname", "rrname", "rdata"],
                           "_HTTP":["Time", "Type", "Source", "SourcePort", "Destination", "DestinationPort", "fields", "payload"],
                           "_ALL":["Time", "ProtocolsFrame", "Source", "SourcePort", "SPDescription", "Destination", "DestinationPort", "DPDescription"],
                           "_PORTS":["Port", "Description"],
                           "_IP4S":["IP", "Code", "Alpha2", "Description"]}

        self.ipdetection = rcompile(r'(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])', I)
        self.waf = waf()
        self.extract = TLDExtract(suffix_list_urls=None)

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_layers(self, packet) -> str:
        '''
        get layers
        '''
        counter = 0
        _temp = []
        while True:
            layer = packet.getlayer(counter)
            counter += 1
            if layer is None:
                break
            if layer.name not in _temp:
                _temp.append(layer.name)
        return "->".join(_temp)

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def read_all_packets(self, packets):
        '''
        analyze each packet
        '''
        _listreadarp = []
        _listreaddns = []
        _listreadhttp = []
        _listurlhttp = []
        _tempdomains = []
        _domains = []
        _list = []
        _ports = []
        _ips = []
        tempports = []
        tempips = []
        for packet in packets:
            fields = {}
            if packet.haslayer(scapy.ARP):
                if packet[scapy.ARP].op == 1:
                    _listreadarp.append({"Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                         "Type":"ARPQuestion",
                                         "PacketSoruce":packet[scapy.ARP].psrc,
                                         "PacketDestination":packet[scapy.ARP].pdst})
                elif packet[scapy.ARP].op == 2:
                    _listreadarp.append({"time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                         "type":"ARPAnswer",
                                         "Macaddress":packet[scapy.ARP].hwsrc,
                                         "PacketSoruce":packet[scapy.ARP].psrc})
            if packet.haslayer(scapy.DNS):
                if isinstance(packet.an, scapy.DNSQR):
                    _listreaddns.append({"Type":"DNSQR",
                                         "Source":packet.getlayer(scapy.IP).src,
                                         "SourcePort":packet.getlayer(scapy.IP).sport,
                                         "Destination":packet.getlayer(scapy.IP).dst,
                                         "DestinationPort":packet.getlayer(scapy.IP).dport,
                                         "qname":packet.qd.qname,
                                         "Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')})
                elif isinstance(packet.an, scapy.DNSRR):
                    _listreaddns.append({"Type":"DNSRR",
                                         "Source":packet.getlayer(scapy.IP).src,
                                         "SourcePort":packet.getlayer(scapy.IP).sport,
                                         "Destination":packet.getlayer(scapy.IP).dst,
                                         "DestinationPort":packet.getlayer(scapy.IP).dport,
                                         "rrname":packet.an.rrname.decode("utf-8", errors="ignore"),
                                         "rdata":str(packet.an.rdata)[1:], #I know... do not ask, long story
                                         "Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')})
                    if packet.an.rrname.decode("utf-8", errors="ignore")[:-1] not in _tempdomains:
                        with ignore_excpetion(Exception):
                            parsedhost = packet.an.rrname.decode("utf-8", errors="ignore")[:-1]
                            temp_s, temp_d, temp_t = self.extract(parsedhost)
                            _tempdomains.append(parsedhost)
                            _domains.append({"Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                             "subdomain":temp_s,
                                             "domain":temp_d,
                                             "tld":temp_t})
            if packet.haslayer(http.HTTPRequest):
                for temp_k in packet.getlayer(http.HTTPRequest).fields:
                    temp_v = packet.getlayer(http.HTTPRequest).fields[temp_k]
                    with ignore_excpetion(Exception):
                        fields.update({temp_k:temp_v.decode("utf-8", errors="ignore")})
                with ignore_excpetion(Exception):
                    payload = "Error parsing"
                    payload = str(packet.getlayer(http.HTTPRequest).payload)
                _listreadhttp.append({"Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                      "Type":"HTTPRequest",
                                      "Source":packet.getlayer(scapy.IP).src,
                                      "SourcePort":packet.getlayer(scapy.IP).sport,
                                      "Destination":packet.getlayer(scapy.IP).dst,
                                      "DestinationPort":packet.getlayer(scapy.IP).dport,
                                      "fields":fields,
                                      "payload":payload})
                with ignore_excpetion(Exception):
                    src = packet.getlayer(scapy.IP).src
                    fields = packet.getlayer(http.HTTPRequest).fields
                    _listurlhttp.append({"Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                         "src":src,
                                         "Method":fields["Method"].decode("utf-8", errors="ignore"),
                                         "Host":fields["Host"].decode("utf-8", errors="ignore"),
                                         "Path":fields["Path"].decode("utf-8", errors="ignore")})
                    parsedhost = fields["Host"].decode("utf-8", errors="ignore")
                    if not search(self.ipdetection, parsedhost) and parsedhost not in _tempdomains:
                        temp_s, temp_d, temp_t = self.extract(parsedhost)
                        _tempdomains.append(parsedhost)
                        _domains.append({"Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                         "subdomain":temp_s,
                                         "domain":temp_d,
                                         "tld":temp_t})

            if packet.haslayer(http.HTTPResponse):
                for temp_k in packet.getlayer(http.HTTPResponse).fields:
                    temp_v = packet.getlayer(http.HTTPResponse).fields[temp_k]
                    with ignore_excpetion(Exception):
                        fields.update({temp_k:temp_v.decode("utf-8", errors="ignore")})
                with ignore_excpetion(Exception):
                    payload = "Error parsing"
                    payload = str(packet.getlayer(http.HTTPResponse).payload)
                _listreadhttp.append({"Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                      "Type":"HTTPResponse",
                                      "Source":packet.getlayer(scapy.IP).src,
                                      "SourcePort":packet.getlayer(scapy.IP).sport,
                                      "Destination":packet.getlayer(scapy.IP).dst,
                                      "DestinationPort":packet.getlayer(scapy.IP).dport,
                                      "fields":fields,
                                      "payload":payload})

                with ignore_excpetion(Exception):
                    src = packet.getlayer(scapy.IP).src
                    fields = packet.getlayer(http.HTTPResponse).fields
                    _listurlhttp.append({"Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                         "src":src,
                                         "Method":fields["Method"].decode("utf-8", errors="ignore"),
                                         "Host":fields["Host"].decode("utf-8", errors="ignore"),
                                         "Path":fields["Path"].decode("utf-8", errors="ignore")})
                    parsedhost = fields["Host"].decode("utf-8", errors="ignore")
                    if not search(self.ipdetection, parsedhost) and parsedhost not in _tempdomains:
                        temp_s, temp_d, temp_t = self.extract(parsedhost)
                        _tempdomains.append(parsedhost)
                        _domains.append({"Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                         "subdomain":temp_s,
                                         "domain":temp_d,
                                         "tld":temp_t})

            packetlayers = self.get_layers(packet)
            #packetdata = hexlify(bytes(packet))
            if hasattr(packet.payload, "sport"):
                _list.append({"Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                              "ProtocolsFrame":packetlayers,
                              "Source":packet.getlayer(scapy.IP).src,
                              "SourcePort":str(packet.getlayer(scapy.IP).sport),
                              "SPDescription":"",
                              "Destination":packet.getlayer(scapy.IP).dst,
                              "DestinationPort":str(packet.getlayer(scapy.IP).dport),
                              "DPDescription":"",
                              "Data":str(packet.payload)})
                if str(packet.getlayer(scapy.IP).sport) not in tempports:
                    tempports.append(str(packet.getlayer(scapy.IP).sport))
                    #_ports.append({"Port":str(packet.getlayer(scapy.IP).sport), "Description":""})
                elif str(packet.getlayer(scapy.IP).dport) not in tempports:
                    tempports.append(str(packet.getlayer(scapy.IP).dport))
                    #_ports.append({"Port":str(packet.getlayer(scapy.IP).dport), "Description":""})
                if packet.getlayer(scapy.IP).src not in tempips:
                    tempips.append(packet.getlayer(scapy.IP).src)
                    #_ports.append({"Port":str(packet.getlayer(scapy.IP).sport), "Description":""})
                elif packet.getlayer(scapy.IP).dst not in tempips:
                    tempips.append(packet.getlayer(scapy.IP).dst)
        if tempports:
            tempports.sort(key=int)
            _ports = [{"Port":x, "Description":""} for x in tempports]
        if tempips:
            _ips = [{"IP":x, "Code":"", "Alpha2":"", "Description":""} for x in tempips]

        return _list, _ports, _ips, _listreadarp, _listreaddns, _listreadhttp, _listurlhttp, _domains

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig(self, data) -> bool:
        '''
        check if mime is pcap
        '''
        return bool(data["Details"]["Properties"]["mime"] == "application/vnd.tcpdump.pcap")

    @verbose(True, verbose_output=False, timeout=None, _str="Analyzing PCAP file")
    def analyze(self, data):
        '''
        start analyzing pcap logic, add descriptions and get words and wordsstripped from the file
        '''
        data["PCAP"] = deepcopy(self.datastruct)
        packets = scapy.rdpcap(data["Location"]["File"])
        _all, ports, ips, rarp, rdns, _http, urlshttp, domains = self.read_all_packets(packets)
        data["PCAP"]["Domains"] = domains
        data["PCAP"]["URLs"] = urlshttp
        data["PCAP"]["ARP"] = rarp
        data["PCAP"]["DNS"] = rdns
        data["PCAP"]["HTTP"] = _http
        data["PCAP"]["ALL"] = _all
        data["PCAP"]["PORTS"] = ports
        data["PCAP"]["IP4S"] = ips
        self.waf.analyze(data["PCAP"]["HTTP"], data["PCAP"]["WAF"], "waf.json")
        add_description("Ports", data["PCAP"]["ALL"], "SourcePort")
        add_description("Ports", data["PCAP"]["ALL"], "DestinationPort")
        add_description("Ports", data["PCAP"]["PORTS"], "Port")
        add_description("DNSServers", data["PCAP"]["IP4S"], "IP")
        add_description("ReservedIP", data["PCAP"]["IP4S"], "IP")
        add_description("CountriesIPs", data["PCAP"]["IP4S"], "IP")
        get_words(data, data["Location"]["File"])
