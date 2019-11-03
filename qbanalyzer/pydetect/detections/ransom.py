__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from itertools import combinations

detections = {"Ransom" : ["doc","docx","xls","xlsx","ppt","pptx","pst","ost","msg","eml","vsd","vsdx","txt","csv","rtf","wks","wk1","pdf","dwg","onetoc2","snt","jpeg","jpg","docb","docm","dot","dotm","dotx","xlsm","xlsb","xlw","xlt","xlm","xlc","xltx","xltm","pptm","pot","pps","ppsm","ppsx","ppam","potx","potm","edb","hwp","602","sxi","sti","sldx","sldm","sldm","vdi","vmdk","vmx","gpg","aes","ARC","PAQ","bz2","tbk","bak","tar","tgz","rar","zip","backup","iso","vcd","bmp","png","gif","raw","cgm","tif","tiff","nef","psd","svg","djvu","m4u","m3u","mid","wma","flv","3g2","mkv","3gp","mp4","mov","avi","asf","mpeg","vob","mpg","wmv","fla","swf","wav","mp3","class","jar","java","asp","php","jsp","brd","sch","dch","dip","vb","vbs","ps1","bat","cmd","asm","pas","cpp","suo","sln","ldf","mdf","ibd","myi","myd","frm","odb","dbf","mdb","accdb","sql","sqlitedb","sqlite3","asc","lay6","lay","mml","sxm","otg","odg","uop","std","sxd","otp","odp","wb2","slk","dif","stc","sxc","ots","ods","3dm","max","3ds","uot","stw","sxw","ott","odt","pem","p12","csr","crt","key","pfx","der"]}

@progressbar(True,"Check Ransom")
def startanalyzing(data):
	for detectonroot in detections:
		for pair in combinations(detections[detectonroot],2):
			result = data["StringsRAW"]["wordsstripped"].find(pair[0]+" "+pair[1])
			if result != -1:
				data["PYDETECT"]["Detection"].append({"Count":"1(+)","Offset":result,"Rule":"Ransom","Match":pair[0]+" "+pair[1],"Parsed":None})