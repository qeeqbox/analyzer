__G__ = "(G)bd249ce4"

from ..logger.logger import verbose, verbose_flag, verbose_timeout
from re import findall
from PIL import Image
from pytesseract import image_to_string
from io import BytesIO
from copy import deepcopy

class QBOCRDetect:
    @verbose(True,verbose_flag,verbose_timeout,"Starting QBOCRDetect")
    def __init__(self):
        self.datastruct = { "OCR":[],
                            "_OCR":["Word","File"]}

    @verbose(True,verbose_flag,verbose_timeout,None)
    def mix_and_setup_file_ocr(self,data,paths):
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

    @verbose(True,verbose_flag,verbose_timeout,None)
    def check_ocr_text(self,data,_list):
        '''
        loop paths, convert each image to RGBA, and read text from image
        '''
        for words in _list:
            for word in words[0]:
                if len(word) > 0:
                    data.append({"Word":word,"File":words[1]})


    @verbose(True,verbose_flag,verbose_timeout,"Analyzing image with OCR")
    def analyze(self,data):
        '''
        start ocr reading logic for packed files only
        '''
        self.words = []
        data["OCR"] = deepcopy(self.datastruct)
        try:
            if len(data["Packed"]["Files"]) > 0:
                self.mix_and_setup_file_ocr(data,data["Packed"]["Files"])
                self.check_ocr_text(data["OCR"]["OCR"],self.words)           
        except:
            pass
