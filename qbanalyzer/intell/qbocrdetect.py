__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from re import findall
from PIL import Image
from pytesseract import image_to_string

#this module need some optimization

verbose_flag = False

class QBOCRDetect:
    @verbose(verbose_flag)
    @progressbar(True,"Starting QBOCRDetect")
    def __init__(self):
        self.words = []

    @verbose(verbose_flag)
    def mixandsetupfileocr(self,_path):
        for x in _path:
            #if x["Path"].endswith(".png") no need < lazy try and except
            try:
                image = Image.open(x["Path"])
                image = image.convert("RGBA")
                text = image_to_string(image,config='--psm 6')
                words = findall("[\x20-\x7e]{4,}",text)
                if len(words) > 0:
                    self.words.append([words,x["Path"]])
            except:
                pass

    @verbose(verbose_flag)
    def checkocrtext(self,data,_list):
        for words in _list:
            for word in words[0]:
                if len(word) > 0:
                    data.append({"Word":word,"File":words[1]})

    @verbose(verbose_flag)
    @progressbar(True,"Analyze images with OCR")
    def checkwithocr(self,data):
        data["OCR"] = { "OCR":[],
                        "_OCR":["Word","File"]}
        try:
            if len(data["Packed"]["Files"]) > 0:
                self.mixandsetupfileocr(data["Packed"]["Files"])
                self.checkocrtext(data["OCR"]["OCR"],self.words)           
        except:
            pass