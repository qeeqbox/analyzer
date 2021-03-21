'''
    __G__ = "(G)bd249ce4"
    detector -> detect
    You can add more DETECTIONS
'''

from os import mkdir, path
from copy import deepcopy
from glob import glob
from importlib import import_module
from analyzer.logger.logger import log_string, verbose, ignore_excpetion


class LoadDetections:
    '''
    LoadDetections loads ???.py detections
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting LoadDetections")
    def __init__(self):
        '''
        initialize class, this has to pass
        '''
        self.datastruct = {"Detection": [],
                           "_Detection": ["Count", "Offset", "Rule", "Parsed", "Match"]}

        self.detections = path.abspath(path.join(path.dirname(__file__), 'detections'))
        if not self.detections.endswith(path.sep):
            self.detections = self.detections + path.sep
        if not path.isdir(self.detections):
            mkdir(self.detections)
        self.modules = glob(self.detections + "*.py")
        self.imported = []
        for _module in self.modules:
            with ignore_excpetion(Exception):
                mod = import_module(".qbdetect.detections.{}".format(path.basename(_module)[:-3]), package="analyzer")
                self.imported.append(getattr(mod, "startanalyzing"))
                log_string("Loading plugins completed", "Green")

    @verbose(True, verbose_output=False, timeout=None, _str="Loading extra plugins")
    def checkwithdetections(self, data):
        '''
        run the detections
        '''
        data["QBDETECT"] = deepcopy(self.datastruct)
        for detectionplugin in self.imported:
            detectionplugin(data)
