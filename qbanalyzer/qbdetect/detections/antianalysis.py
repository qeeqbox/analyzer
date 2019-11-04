__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from re import I, compile, finditer

detections = {"Debugger or analyzer" : [rb"ProcessHacker\.exe|processmonitor\.exe|tcpview\.exe|autoruns\.exe|autorunsc\.exe|filemon\.exe|procmon\.exe|regmon\.exe|procexp\.exe|hiew32\.exe|ollydbg\.exe|idaq\.exe|idaq64\.exe|ImmunityDebugger\.exe|dumpcap\.exe|HookExplorer\.exe|ImportREC\.exe|PETools\.exe|LordPE\.exe|SysInspector\.exe|proc_analyzer\.exe|sysAnalyzer\.exe|sniff_hit\.exe|ILSpy\.exe|dnSpy\.exe|windbg\.exe|winhex\.exe|fiddler\.exe|Wireshark\.exe|\\\\\.\\NTICE|\\\\\.\\SICE|\\\\\.\\Syser|\\\\\.\\SyserBoot|\\\\\.\\SyserDbgMsg"],
				"vpx" : [rb"\x0F\x3F\x07\x0B"],
    			"vmware" : [rb"\x56\x4D\x58\x68"],
    			"vmcheckdll" : [rb"\x45\xC7\x00\x01"],
    			"redpill" : [rb"\x0F\x01\x0D\x00\x00\x00\x00\xC3"]}

@progressbar(True,"Check Anti-Analysis")
def startanalyzing(data):
	for detectonroot in detections:
		for detection in detections[detectonroot]:
			temp = {}
			for match in finditer(compile(detection,I), data["FilesDumps"][data["Location"]["File"]]):
				if match.group() in temp:
					temp[match.group()][0] += 1
				else:
					temp.update({match.group():[1,[]]})
				temp[match.group()][1].append("{}-{}".format(hex(match.span()[0]),hex(match.span()[1])))
			for match in temp:
				data["QBDETECT"]["Detection"].append({"Count":temp[match][0],"Offset":" ".join(temp[match][1]),"Rule":"Anti-Analysis","Match":match,"Parsed":None})