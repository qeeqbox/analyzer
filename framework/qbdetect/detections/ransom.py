__G__ = "(G)bd249ce4"

from ...logger.logger import log_string,verbose,verbose_flag,verbose_timeout
from itertools import combinations
from re import I, compile, search
from random import choice

detections = {"Ransom" : ['3dm', '3ds', '3g2', '3gp', '602', 'arc', 'paq', 'accdb', 'aes', 'asc', 'asf', 'asm', 'asp', 'avi', 'backup', 'bak', 'bat', 'bmp', 'brd', 'bz2', 'cgm', 'class', 'cmd', 'cpp', 'crt', 'csr', 'csv', 'dbf', 'dch', 'der', 'dif', 'dip', 'djvu', 'doc', 'docb', 'docm', 'docx', 'dot', 'dotm', 'dotx', 'dwg', 'edb', 'eml', 'fla', 'flv', 'frm', 'gif', 'gpg', 'hwp', 'ibd', 'iso', 'jar', 'java', 'jpeg', 'jpg', 'jsp', 'key', 'lay', 'lay6', 'ldf', 'm3u', 'm4u', 'max', 'mdb', 'mdf', 'mid', 'mkv', 'mml', 'mov', 'mp3', 'mp4', 'mpeg', 'mpg', 'msg', 'myd', 'myi', 'nef', 'odb', 'odg', 'odp', 'ods', 'odt', 'onetoc2', 'ost', 'otg', 'otp', 'ots', 'ott', 'p12', 'pas', 'pdf', 'pem', 'pfx', 'php', 'png', 'pot', 'potm', 'potx', 'ppam', 'pps', 'ppsm', 'ppsx', 'ppt', 'pptm', 'pptx', 'ps1', 'psd', 'pst', 'rar', 'raw', 'rtf', 'sch', 'sldm', 'sldm', 'sldx', 'slk', 'sln', 'snt', 'sql', 'sqlite3', 'sqlitedb', 'stc', 'std', 'sti', 'stw', 'suo', 'svg', 'swf', 'sxc', 'sxd', 'sxi', 'sxm', 'sxw', 'tar', 'tbk', 'tgz', 'tif', 'tiff', 'txt', 'uop', 'uot', 'vb', 'vbs', 'vcd', 'vdi', 'vmdk', 'vmx', 'vob', 'vsd', 'vsdx', 'wav', 'wb2', 'wk1', 'wks', 'wma', 'wmv', 'xlc', 'xlm', 'xls', 'xlsb', 'xlsm', 'xlsx', 'xlt', 'xltm', 'xltx', 'xlw', 'zip']}

@verbose(True,verbose_flag,verbose_timeout,"Analyzing Ransom patterns")
def startanalyzing(data):
	for detectonroot in detections:
		detect = 0
		_List = []
		for check in range(0,15):
			randompick = choice(detections[detectonroot])
			nextpick = detections[detectonroot][(detections[detectonroot].index(randompick) + 1) % len(detections[detectonroot])]
			if search(compile(r"{}[ \x00\|]{}".format(randompick,nextpick),I),data["StringsRAW"]["wordsstripped"]):
				_List.append("({} {})".format(randompick,nextpick))
				detect +=1
		if detect >= 5:
			data["QBDETECT"]["Detection"].append({"Count":detect,"Offset":"Unavailable","Rule":"Ransom","Match":",".join(_List),"Parsed":None})
		else:
			detect = 0
			_List = []
			for check in range(0,15):
				randompick1 = choice(detections[detectonroot])
				randompick2 = choice(detections[detectonroot])
				if search(compile(r"{}[ \x00\|]{}".format(randompick1,randompick2),I),data["StringsRAW"]["wordsstripped"]):
					_List.append("({} {})".format(randompick1,randompick2))
					detect +=1
			if detect >= 5:
				data["QBDETECT"]["Detection"].append({"Count":detect,"Offset":"Unavailable","Rule":"Ransom","Match":",".join(_List),"Parsed":None})