__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from ..mics.funcs import getwords
from ..intell.qbdescription import adddescription
from scapy import all as scapy
from binascii import hexlify
from scapy.layers import http
from datetime import datetime

class ReadPackets:
    @verbose(verbose_flag)
    @progressbar(True,"Starting ReadPackets")
    def __init__(self,waf):
        '''
        initialize class

        Args:
            waf: is WafDetect class, needed for detecting waf
        '''
        self.waf = waf

    @verbose(verbose_flag)
    def getlayers(self,packet) -> str:
        '''
        initialize class

        Args:
            packet: packet object

        Return:
            str of layers
        '''
        c = 0
        _temp = []
        while True:
            layer = packet.getlayer(c)
            c += 1
            if layer is None:break
            _temp.append(layer.name)
        return ":".join(_temp)

    @verbose(verbose_flag)
    def readallpackets(self,packets):
        '''
        initialize class

        Args:
            packets: packets object

        Return:
            _list list of all payloads
            _ports ports list
            _ips ips list
            _listreadarp list of arp requests
            _listreaddns list of dns requests
            _listreadhttp list of http requests
        '''
        _listreadarp = []
        _listreaddns = []
        _listreadhttp = []
        _listurlhttp = []
        _list = []
        _ports = []
        _ips = []
        tempports = []
        tempips = []
        for packet in packets:
            fields = {}
            if packet.haslayer(scapy.ARP):
                if packet[scapy.ARP].op == 1:
                    _listreadarp.append({  "Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                    "Type":"ARPQuestion",
                                    "PacketSoruce":packet[scapy.ARP].psrc,
                                    "PacketDestination":packet[scapy.ARP].pdst})
                elif packet[scapy.ARP].op == 2:
                    _listreadarp.append({  "time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                    "type":"ARPAnswer",
                                    "Macaddress":packet[scapy.ARP].hwsrc,
                                    "PacketSoruce":packet[scapy.ARP].psrc})
            if packet.haslayer(scapy.DNS):
                if isinstance(packet.an, scapy.DNSQR):
                    _listreaddns.append({  "Type":"DNSQR",
                                    "Source":packet.getlayer(scapy.IP).src,
                                    "SourcePort":packet.getlayer(scapy.IP).sport,
                                    "Destination":packet.getlayer(scapy.IP).dst,
                                    "DestinationPort":packet.getlayer(scapy.IP).dport,
                                    "qname":packet.qd.qname,
                                    "Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')})
                elif isinstance(packet.an, scapy.DNSRR):
                    _listreaddns.append({  "Type":"DNSRR",
                                    "Source":packet.getlayer(scapy.IP).src,
                                    "SourcePort":packet.getlayer(scapy.IP).sport,
                                    "Destination":packet.getlayer(scapy.IP).dst,
                                    "DestinationPort":packet.getlayer(scapy.IP).dport,
                                    "rrname":packet.an.rrname.decode("utf-8",errors="ignore"),
                                    "rdata":str(packet.an.rdata)[1:], #I know... do not ask, long story
                                    "Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')})
            if packet.haslayer(http.HTTPRequest):
                for k in packet.getlayer(http.HTTPRequest).fields:
                    v = packet.getlayer(http.HTTPRequest).fields[k]
                    try:
                        fields.update({k:v.decode("utf-8",errors="ignore")})
                    except:
                        pass
                try:
                    payload = str(packet.getlayer(http.HTTPRequest).payload)
                except:
                    payload = "Error parsing"
                _listreadhttp.append({  "Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                "Type":"HTTPRequest",
                                "Source":packet.getlayer(scapy.IP).src,
                                "SourcePort":packet.getlayer(scapy.IP).sport,
                                "Destination":packet.getlayer(scapy.IP).dst,
                                "DestinationPort":packet.getlayer(scapy.IP).dport,
                                "fields":fields,
                                "payload":payload})
                try:
                    src = packet.getlayer(scapy.IP).src
                    fields = packet.getlayer(http.HTTPRequest).fields
                    _listurlhttp.append({"Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                         "src":src,
                                         "Method":fields["Method"].decode("utf-8",errors="ignore"),
                                         "Host":fields["Host"].decode("utf-8",errors="ignore"),
                                         "Path":fields["Path"].decode("utf-8",errors="ignore")})
                except:
                    pass

            if packet.haslayer(http.HTTPResponse):
                for k in packet.getlayer(http.HTTPResponse).fields:
                    v = packet.getlayer(http.HTTPResponse).fields[k]
                    try:
                        fields.update({k:v.decode("utf-8",errors="ignore")})
                    except:
                        pass
                try:
                    payload = str(packet.getlayer(http.HTTPResponse).payload)
                except:
                    payload = "Error parsing"
                _listreadhttp.append({  "Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                "Type":"HTTPResponse",
                                "Source":packet.getlayer(scapy.IP).src,
                                "SourcePort":packet.getlayer(scapy.IP).sport,
                                "Destination":packet.getlayer(scapy.IP).dst,
                                "DestinationPort":packet.getlayer(scapy.IP).dport,
                                "fields":fields,
                                "payload":payload})

                try:
                    src = packet.getlayer(scapy.IP).src
                    fields = packet.getlayer(http.HTTPResponse).fields
                    _listurlhttp.append({"Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                                         "src":src,
                                         "Method":fields["Method"].decode("utf-8",errors="ignore"),
                                         "Host":fields["Host"].decode("utf-8",errors="ignore"),
                                         "Path":fields["Path"].decode("utf-8",errors="ignore")})
                except:
                    pass

            packetlayers = self.getlayers(packet)
            #packetdata = hexlify(bytes(packet))
            if hasattr(packet.payload, "sport"):
                _list.append({  "Time":datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
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
                    #_ports.append({"Port":str(packet.getlayer(scapy.IP).sport),"Description":""})
                elif str(packet.getlayer(scapy.IP).dport) not in tempports:
                    tempports.append(str(packet.getlayer(scapy.IP).dport))
                    #_ports.append({"Port":str(packet.getlayer(scapy.IP).dport),"Description":""})
                if packet.getlayer(scapy.IP).src not in tempips:
                    tempips.append(packet.getlayer(scapy.IP).src)
                    #_ports.append({"Port":str(packet.getlayer(scapy.IP).sport),"Description":""})
                elif packet.getlayer(scapy.IP).dst not in tempips:
                    tempips.append(packet.getlayer(scapy.IP).dst)
        if tempports:
            tempports.sort(key=int)
            _ports = [{"Port":x,"Description":""} for x in tempports]
        if tempips:
            _ips = [{"IP":x,"Description":"","Code":""} for x in tempips]

        return _list,_ports,_ips,_listreadarp,_listreaddns,_listreadhttp,_listurlhttp

    @verbose(verbose_flag)
    def checkpcapsig(self,data):
        '''
        check if mime is pcap

        Args:
            data: data dict

        Return:
            true if pcap
        '''
        if data["Details"]["Properties"]["mime"] == "application/vnd.tcpdump.pcap":
            return True

    @verbose(verbose_flag)
    @progressbar(True,"Analyzing PCAP file")
    def getpacpdetails(self,data):
        '''
        start analyzing pcap logic, add descriptions and get words and wordsstripped from the file 

        Args:
            data: data dict
        '''
        data["PCAP"] = {"WAF":[],
                        "URLs":[],
                        "ARP":[],
                        "DNS":[],
                        "HTTP":[],
                        "ALL":[],
                        "PORTS":[],
                        "IPS":[],
                        "_WAF":["Matched","Required","WAF","Detected"],
                        "_URLs":["Time","src","Method","Host","Path"],
                        "_ARP":["Time","Type","PacketSoruce","PacketDestination","Macaddress"],
                        "_DNS":["Time","Type","Source","SourcePort","Destination","DestinationPort","qname","rrname","rdata"],
                        "_HTTP":["Time","Type","Source","SourcePort","Destination","DestinationPort","fields","payload"],
                        "_ALL":["Time","ProtocolsFrame","Source","SourcePort","SPDescription","Destination","DestinationPort","DPDescription"],
                        "_PORTS":["Port","Description"],
                        "_IPS":["IP","Description"]}

        packets = scapy.rdpcap(data["Location"]["File"])
        all,ports,ips,rarp,rdns,http,urlshttp = self.readallpackets(packets)
        data["PCAP"]["URLs"] = urlshttp
        data["PCAP"]["ARP"] = rarp
        data["PCAP"]["DNS"] = rdns
        data["PCAP"]["HTTP"] = http
        data["PCAP"]["ALL"] = all
        data["PCAP"]["PORTS"] = ports
        data["PCAP"]["IPS"] = ips
        self.waf.checkpacketsforwaf(data["PCAP"]["HTTP"],data["PCAP"]["WAF"],"waf.json")
        adddescription("Ports",data["PCAP"]["ALL"],"SourcePort")
        adddescription("Ports",data["PCAP"]["ALL"],"DestinationPort")
        adddescription("Ports",data["PCAP"]["PORTS"],"Port")
        adddescription("IPs",data["PCAP"]["IPS"],"IP")
        getwords(data,data["Location"]["File"])