__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from glob import glob
from importlib import import_module
from os import mkdir, path

class LoadDetections:
    @verbose(True,verbose_flag,"Starting LoadDetections")
    def __init__(self):
        '''
        initialize class and make detections path 
        '''
        self.detections = path.abspath(path.join(path.dirname( __file__ ),'detections'))
        if not self.detections.endswith(path.sep): self.detections = self.detections+path.sep
        if not path.isdir(self.detections): mkdir(self.detections)
        self.modules = glob(self.detections+"*.py")
        self.imported = []
        for x in self.modules:
            try:
                mod = import_module(".qbdetect.detections.{}".format(path.basename(x)[:-3]),package="qbanalyzer")
                self.imported.append(getattr(mod,"startanalyzing"))
            except Exception:
                logstring("Loading plugins failed","Red")


    @verbose(True,verbose_flag,"Loading extra plugins")
    def checkwithdetections(self,data):
        data["QBDETECT"] = {"Detection":[],
    						"_Detection":["Count","Offset","Rule","Parsed","Match"]}

        for detectionplugin in self.imported:
            detectionplugin(data)