'''
    __G__ = "(G)bd249ce4"
    detector -> detect -> ransom
    You can add more detections
'''

from re import I, search
from re import compile as rcompile
from random import choice
from analyzer.logger.logger import verbose

DETECTIONS = {"Ransom" :['3dm', '3ds', '3g2', '3gp', '602', 'arc', 'paq', 'accdb', 'aes', 'asc', 'asf', 'asm', 'asp', 'avi', 'backup', 'bak', 'bat', 'bmp', 'brd', 'bz2', 'cgm', 'class', 'cmd', 'cpp', 'crt', 'csr', 'csv', 'dbf', 'dch', 'der', 'dif', 'dip', 'djvu', 'doc', 'docb', 'docm', 'docx', 'dot', 'dotm', 'dotx', 'dwg', 'edb', 'eml', 'fla', 'flv', 'frm', 'gif', 'gpg', 'hwp', 'ibd', 'iso', 'jar', 'java', 'jpeg', 'jpg', 'jsp', 'key', 'lay', 'lay6', 'ldf', 'm3u', 'm4u', 'max', 'mdb', 'mdf', 'mid', 'mkv', 'mml', 'mov', 'mp3', 'mp4', 'mpeg', 'mpg', 'msg', 'myd', 'myi', 'nef', 'odb', 'odg', 'odp', 'ods', 'odt', 'onetoc2', 'ost', 'otg', 'otp', 'ots', 'ott', 'p12', 'pas', 'pdf', 'pem', 'pfx', 'php', 'png', 'pot', 'potm', 'potx', 'ppam', 'pps', 'ppsm', 'ppsx', 'ppt', 'pptm', 'pptx', 'ps1', 'psd', 'pst', 'rar', 'raw', 'rtf', 'sch', 'sldm', 'sldm', 'sldx', 'slk', 'sln', 'snt', 'sql', 'sqlite3', 'sqlitedb', 'stc', 'std', 'sti', 'stw', 'suo', 'svg', 'swf', 'sxc', 'sxd', 'sxi', 'sxm', 'sxw', 'tar', 'tbk', 'tgz', 'tif', 'tiff', 'txt', 'uop', 'uot', 'vb', 'vbs', 'vcd', 'vdi', 'vmdk', 'vmx', 'vob', 'vsd', 'vsdx', 'wav', 'wb2', 'wk1', 'wks', 'wma', 'wmv', 'xlc', 'xlm', 'xls', 'xlsb', 'xlsm', 'xlsx', 'xlt', 'xltm', 'xltx', 'xlw', 'zip']}

@verbose(True, verbose_output=False, timeout=None, _str="Analyzing Ransom patterns")
def startanalyzing(data):
    '''
    start extracting ransom patterns
    '''
    for detectonroot in DETECTIONS:
        detect = 0
        temp_list = []
        for check in range(0, 15):
            randompick = choice(DETECTIONS[detectonroot])
            nextpick = DETECTIONS[detectonroot][(DETECTIONS[detectonroot].index(randompick) + 1) % len(DETECTIONS[detectonroot])]
            if search(rcompile(r"{}[ \x00\|]{}".format(randompick, nextpick), I), data["StringsRAW"]["wordsstripped"]):
                temp_list.append("({} {})".format(randompick, nextpick))
                detect += 1
        if detect >= 5:
            data["QBDETECT"]["Detection"].append({"Count":detect, "Offset":"Unavailable", "Rule":"Ransom", "Match":", ".join(temp_list), "Parsed":None})
        else:
            detect = 0
            temp_list = []
            for check in range(0, 15):
                randompick1 = choice(DETECTIONS[detectonroot])
                randompick2 = choice(DETECTIONS[detectonroot])
                if search(rcompile(r"{}[ \x00\|]{}".format(randompick1, randompick2), I), data["StringsRAW"]["wordsstripped"]):
                    temp_list.append("({} {})".format(randompick1, randompick2))
                    detect += 1
            if detect >= 5:
                data["QBDETECT"]["Detection"].append({"Count":detect, "Offset":"Unavailable", "Rule":"Ransom", "Match":", ".join(temp_list), "Parsed":None})
