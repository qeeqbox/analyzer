__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from re import findall
from PIL import Image
from pytesseract import image_to_string
from io import BytesIO

#this module needs some optimization

class QBOCRDetect:
    @verbose(verbose_flag)
    @progressbar(True,"Starting QBOCRDetect")
    def __init__(self):
        pass

    @verbose(verbose_flag)
    def mixandsetupfileocr(self,data,paths):
        '''
        loop paths, convert each image to RGBA, and read text from image
        '''
        for x in paths:
            try:
                image = Image.open(BytesIO(data["FilesDumps"][x["Path"]]))
                image = image.convert("RGBA")
                text = image_to_string(image,config='--psm 6')
                words = findall("[\x20-\x7e]{4,}",text)
                if len(words) > 0:
                    self.words.append([words,x["Path"]])
            except:
                pass

    @verbose(verbose_flag)
    def checkocrtext(self,data,_list):
        '''
        loop paths, convert each image to RGBA, and read text from image
        '''
        for words in _list:
            for word in words[0]:
                if len(word) > 0:
                    data.append({"Word":word,"File":words[1]})

    @verbose(verbose_flag)
    @progressbar(True,"Analyzing image with OCR")
    def checkwithocr(self,data):
        '''
        start ocr reading logic for packed files only
        '''
        self.words = []
        data["OCR"] = { "OCR":[],
                        "_OCR":["Word","File"]}
        try:
            if len(data["Packed"]["Files"]) > 0:
                self.mixandsetupfileocr(data,data["Packed"]["Files"])
                self.checkocrtext(data["OCR"]["OCR"],self.words)           
        except:
            pass
