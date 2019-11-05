__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from re import I, compile, finditer

detections = { "cryptocurrency strings" : [r"\b(Bitcoin|Litecoin|Namecoin|Terracoin|PPcoin|Primecoin|Feathercoin|Novacoin|Freicoin|Devoin|Franko|Megacoin|Quarkcoin|Worldcoin|Infinitecoin|Ixcoin|Anoncoin|BBQcoin|Digitalcoin|Mincoin|Goldcoin|Yacoin|Zetacoin|Fastcoin|I0coin|Tagcoin|Bytecoin|Florincoin|Phoenixcoin|Luckycoin|Craftcoin|Junkcoin)\b"],
				"btc:Bitcoin Address":[r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"],
				"bch:Bitcoin Cash Address":[r"\b((bitcoincash|bchreg|bchtest):)?(q|p)[a-z0-9]{41}\b"],
				"eth:Ethereum Address":[r"\b0x[a-fA-F0-9]{40}\b"],
				"ltc:Litecoin Address":[r"\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b"],
				"doge:Dogecoin Address":[r"\bD{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}\b"],
				"dash:Dash Address":[r"\bX[1-9A-HJ-NP-Za-km-z]{33}\b"],
				"neo:Neo Address":[r"\bA[0-9a-zA-Z]{33}\b"],
				"xrp:Ripple Address":[r"\br[0-9a-zA-Z]{33}\b"],
				"xmr:Monero Address":[r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"]}

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
