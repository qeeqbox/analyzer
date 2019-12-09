__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.funcs import getwords,getwordsmultifiles,getentropy
from ..general.archive import checkpackedfiles,dmgunpack,unpackfile
from shutil import copyfile,rmtree
from os import mkdir, path
from hashlib import md5, sha1, sha256
from magic import from_file,Magic
from ssdeep import hash_from_file
from mimetypes import guess_type
from re import match

@verbose(True,verbose_flag,None)
def convertsize(s):
    for u in ['B','KB','MB','GB']:
        if s < 1024.0:
            return "{:.2f}{}".format(s,u)
        else:
            s /= 1024.0
    return "File is too big"

class QBFile:
    @verbose(True,verbose_flag,"Starting QBFile")
    def __init__(self):
        pass

    @verbose(True,verbose_flag,None)
    def setupmalwarefolder(self,folder):
        '''
        setup malware folder where files will be transferred and unpacked
        '''
        self.malwarefarm = folder
        if not self.malwarefarm.endswith(path.sep): self.malwarefarm = self.malwarefarm+path.sep
        if not path.isdir(self.malwarefarm): mkdir(self.malwarefarm)

    @verbose(True,verbose_flag,"Setting up ouput folder")
    def createtempfolder(self,data,_path):
        '''
        create temp folder that has the md5 of the target file
        '''
        safename = "".join([c for c in path.basename(_path) if match(r'[\w\.]', c)])
        if len(safename) == 0: safename = "temp"
        md5 = data["Details"]["Properties"]["md5"]
        if path.exists(self.malwarefarm+md5):
            rmtree(self.malwarefarm+md5)
        mkdir(self.malwarefarm+md5)
        copyfile(_path,self.malwarefarm+md5+path.sep+"temp")
        data["Location"] = {"Original":_path,
                            "File":self.malwarefarm+md5+path.sep+"temp",
                            "html":self.malwarefarm+md5+path.sep+safename+".html",
                            "json":self.malwarefarm+md5+path.sep+safename+".json",
                            "Folder":self.malwarefarm+md5+path.sep+"temp_unpacked"}
        data["FilesDumps"] = {self.malwarefarm+md5+path.sep+"temp":open(_path,"rb").read()}

    @verbose(True,verbose_flag,"Getting file details")
    def getdetailes(self,data,_path):
        '''
        get general details of file
        '''
        data["Details"] = {"Properties":{},
                           "_Properties":{}}
        f = open(_path,"rb").read()
        open(_path,"rb").read(4)
        data["Details"]["Properties"]={ "Name": path.basename(_path),
                                        "md5": md5(f).hexdigest(),
                                        "sha1": sha1(f).hexdigest(),
                                        "sha256": sha256(f).hexdigest(),
                                        "ssdeep":hash_from_file(_path),
                                        "size": convertsize(path.getsize(_path)),
                                        "bytes": path.getsize(_path),
                                        "mime":from_file(_path,mime=True),
                                        "extension":guess_type(_path)[0],
                                        "Entropy":getentropy(f)}


    @verbose(True,verbose_flag,"Handling unknown format")
    def unknownfile(self,data):
        '''
        start unknown files logic, this file is not detected by otehr modules
        if file is archive, then unpack and get words,wordsstripped otherwise
        get words,wordsstripped from the file only
        '''
        if  data["Details"]["Properties"]["mime"] == "application/java-archive" or \
            data["Details"]["Properties"]["mime"] == "application/zip" or \
            data["Details"]["Properties"]["mime"] == "application/zlib":
            unpackfile(data,data["Location"]["File"])
            getwordsmultifiles(data,data["Packed"]["Files"])
        else:
            getwords(data,data["Location"]["File"])

    @verbose(True,verbose_flag,None)
    def checkfilesig(self,data,_path,folder) -> bool:
        '''
        first logic to execute, this will check if malware folder exists or not
        get details of the target file and move a temp version of it to a temp
        folder that has the md5
        '''
        self.setupmalwarefolder(folder)
        self.getdetailes(data,_path)
        self.createtempfolder(data,_path)

        
