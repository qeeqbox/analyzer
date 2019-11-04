__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from re import I, compile, finditer

detections = { "cryptocurrency strings" : [r"Bitcoin|Litecoin|Namecoin|Terracoin|PPcoin|Primecoin|Feathercoin|Novacoin|Freicoin|Devoin|Franko|Megacoin|Quarkcoin|Worldcoin|Infinitecoin|Ixcoin|Anoncoin|BBQcoin|Digitalcoin|Mincoin|Goldcoin|Yacoin|Zetacoin|Fastcoin|I0coin|Tagcoin|Bytecoin|Florincoin|Phoenixcoin|Luckycoin|Craftcoin|Junkcoin"],
				"btc:Bitcoin Address":[r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}"],
				"bch:Bitcoin Cash Address":[r"((bitcoincash|bchreg|bchtest):)?(q|p)[a-z0-9]{41}"],
				"eth:Ethereum Address":[r"0x[a-fA-F0-9]{40}"],
				"ltc:Litecoin Address":[r"[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}"],
				"doge:Dogecoin Address":[r"D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}"],
				"dash:Dash Address":[r"X[1-9A-HJ-NP-Za-km-z]{33}"],
				"neo:Neo Address":[r"A[0-9a-zA-Z]{33}"],
				"xrp:Ripple Address":[r"r[0-9a-zA-Z]{33}"],
				"xmr:Monero Address":[r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"]}

@progressbar(True,"Check Crypto Currency")
def startanalyzing(data):
	for detectonroot in detections:
		for detection in detections[detectonroot]:
			temp = {}
			for match in finditer(compile(detection,I), data["StringsRAW"]["wordsstripped"]):
				if match.group() in temp:
					temp[match.group()][0] += 1
				else:
					temp.update({match.group():[1,[]]})
				temp[match.group()][1].append("{}-{}".format(hex(match.span()[0]),hex(match.span()[1])))
			for match in temp:
				data["QBDETECT"]["Detection"].append({"Count":temp[match][0],"Offset":" ".join(temp[match][1]),"Rule":detectonroot,"Match":match,"Parsed":None})