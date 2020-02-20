__G__ = "(G)bd249ce4"

from analyzer.logger.logger import log_string,verbose,verbose_flag,verbose_timeout
from glob import glob
from importlib import import_module
from os import mkdir, path
from copy import deepcopy

class LoadDetections:
    @verbose(True,verbose_flag,verbose_timeout,"Starting LoadDetections")
    def __init__(self):
        self.datastruct = { "Detection":[],
                            "_Detection":["Count","Offset","Rule","Parsed","Match"]}

        self.detections = path.abspath(path.join(path.dirname( __file__ ),'detections'))
        if not self.detections.endswith(path.sep): self.detections = self.detections+path.sep
        if not path.isdir(self.detections): mkdir(self.detections)
        self.modules = glob(self.detections+"*.py")
        self.imported = []
        for x in self.modules:
            try:
                mod = import_module(".qbdetect.detections.{}".format(path.basename(x)[:-3]),package="analyzer")
                self.imported.append(getattr(mod,"startanalyzing"))
            except Exception as e:
                print(e)
                log_string("Loading plugins failed","Red")

    @verbose(True,verbose_flag,verbose_timeout,"Loading extra plugins")
    def checkwithdetections(self,data):
        data["QBDETECT"] = deepcopy(self.datastruct)
        for detectionplugin in self.imported:
            detectionplugin(data)