'''
    __G__ = "(G)bd249ce4"
    connection ->  orc wrapper
'''

from io import BytesIO
from re import findall
from copy import deepcopy
from PIL import Image
from pytesseract import image_to_string
from analyzer.logger.logger import ignore_excpetion, verbose

class QBOCRDetect:
    '''
    QBLanguage for reading OCR
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBOCRDetect")
    def __init__(self):
        '''
        Initialize QBOCRDetect, this has to pass
        '''
        self.datastruct = {"OCR":[],
                           "_OCR":["Word", "File"]}
        self.words = []

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def mix_and_setup_file_ocr(self, data, paths):
        '''
        loop paths, convert each image to RGBA, and read text from image
        '''
        for item in paths:
            with ignore_excpetion(Exception):
                image = Image.open(BytesIO(data["FilesDumps"][item["Path"]]))
                image = image.convert("RGBA")
                text = image_to_string(image, config='--psm 6')
                words = findall("[\x20-\x7e]{4,}", text)
                if len(words) > 0:
                    self.words.append([words, item["Path"]])

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_ocr_text(self, data, _list):
        '''
        loop paths, convert each image to RGBA, and read text from image
        '''
        for words in _list:
            for word in words[0]:
                if len(word) > 0:
                    data.append({"Word":word, "File":words[1]})


    @verbose(True, verbose_output=False, timeout=None, _str="Analyzing image with OCR")
    def analyze(self, data):
        '''
        start ocr reading logic for packed files only
        '''
        self.words = []
        data["OCR"] = deepcopy(self.datastruct)
        with ignore_excpetion(Exception):
            if len(data["Packed"]["Files"]) > 0:
                self.mix_and_setup_file_ocr(data, data["Packed"]["Files"])
                self.check_ocr_text(data["OCR"]["OCR"], self.words)
