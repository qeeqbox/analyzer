__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from ...mics.funcs import getwords,getwordsmultifiles
from shutil import copyfile
from os import path,mkdir,walk
from subprocess import PIPE,Popen
from hashlib import md5, sha1, sha256
from magic import from_file,Magic
from ssdeep import hash_from_file

@verbose(verbose_flag)
def checkpackedfiles(_path,files) -> bool:
    '''
    check if archive contains strings or not 

    Args:
        path to archive
        name of files to check 

    Return:
        true if all strings are detected
    '''
    try:
        detect = 0
        p = Popen(["7z", "l", _path], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        output = output.decode("utf-8",errors="ignore")
        for _ in files:
            if _.lower() in output.lower():
                detect += 1
        if detect == len(files):
            return True
    except:
        pass

@verbose(verbose_flag)
def dmgunpack(_path) -> str:
    '''
    convert dmg to img

    Args:
        path to img

    Return:
        path of new img file
    '''
    p = Popen(["dmg2img",_path,_path+".img"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, err = p.communicate()
    if b"dmg image is corrupted" not in output:
        return _path+".img"

@verbose(verbose_flag)
def unpackfile(data,_path):
    '''
    unpack files using 7z into temp folder

    Args:
        data: data dict
        path of archive

    Return:
        true if all strings are detected
    '''
    data["Packed"] = {"Files":[],
                      "Detected":[],
                      "_Detected":["Name","Path"],
                      "_Files":["Name","Type","md5","Path"]}
    try:
        p = Popen(["7z", "e", _path,"-aoa","-o"+data["Location"]["Folder"]], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        for currentpath, folders, files in walk(data["Location"]["Folder"]):
            for file in files:
                f = open(path.join(currentpath, file),"rb").read()
                _md5 = md5(f).hexdigest()
                mime = from_file(path.join(currentpath, file),mime=True)
                data["Packed"]["Files"].append({"Name":file,"Type":mime,"Path":path.join(currentpath, file),"md5":_md5})
                data["FilesDumps"].update({path.join(currentpath, file):f})
    except:
        pass

class FileTypes:
    @progressbar(True,"Starting FileTypes")
    def __init__(self):
        pass

    @verbose(verbose_flag)
    def setupmalwarefolder(self,folder):
        '''
        setup malware folder where files will be transferred and unpacked

        Args:
            folder name
        '''
        self.malwarefarm = folder
        if not self.malwarefarm.endswith(path.sep): self.malwarefarm = self.malwarefarm+path.sep
        if not path.isdir(self.malwarefarm): mkdir(self.malwarefarm)

    @verbose(verbose_flag)
    def createtempfolder(self,data,_path):
        '''
        create temp folder that has the md5 of the target file

        Args:
            data: data dict
            path of target file
        '''
        md5 = data["Details"]["Properties"]["md5"]
        if not path.exists(self.malwarefarm+md5):
            mkdir(self.malwarefarm+md5)
        copyfile(_path,self.malwarefarm+md5+path.sep+"temp")
        data["Location"] = {"Original":_path,
                            "File":self.malwarefarm+md5+path.sep+"temp",
                            "html":self.malwarefarm+md5+path.sep+"html",
                            "json":self.malwarefarm+md5+path.sep+"json",
                            "Folder":self.malwarefarm+md5+path.sep+"temp_unpacked"}
        data["FilesDumps"] = {self.malwarefarm+md5+path.sep+"temp":open(_path,"rb").read()}

    @verbose(verbose_flag)
    def getdetailes(self,data,_path):
        '''
        get general details of file

        Args:
            data: data dict
            path of target file
        '''
        data["Details"] = {"Properties":{},
                           "_Properties":{}}
        f = open(_path,"rb").read()
        data["Details"]["Properties"]={ "Name": path.basename(_path),
                                        "md5": md5(f).hexdigest(),
                                        "sha1": sha1(f).hexdigest(),
                                        "sha256": sha256(f).hexdigest(),
                                        "size": path.getsize(_path),
                                        "mime":from_file(_path,mime=True),
                                        "charset":Magic(mime_encoding=True).from_file(_path),
                                        "ssdeep":hash_from_file(_path)}

    @verbose(verbose_flag)
    @progressbar(True,"Handling unknown format")
    def unknownfile(self,data):
        '''
        start unknown files logic, this file is not detected by otehr modules
        if file is archive, then unpack and get words,wordsstripped otherwise
        get words,wordsstripped from the file only

        Args:
            data: data dict
        '''
        if  data["Details"]["Properties"]["mime"] == "application/java-archive" or \
            data["Details"]["Properties"]["mime"] == "application/zip" or \
            data["Details"]["Properties"]["mime"] == "application/zlib":
            unpackfile(data,data["Location"]["File"])
            getwordsmultifiles(data,data["Packed"]["Files"])
        else:
            getwords(data,data["Location"]["File"])

    @verbose(verbose_flag)
    def checkfilesig(self,data,_path,folder) -> bool:
        '''
        first logic to execute, this will check if malware folder exists or not
        get details of the target file and move a temp version of it to a temp
        folder that has the md5

        Args:
            data: data dict
            path of target file
            folder that will have a temp version of the target file

        Return:
            true if file is small
        '''
        self.setupmalwarefolder(folder)
        self.getdetailes(data,_path)
        self.createtempfolder(data,_path)
        if data["Details"]["Properties"]["size"] > 10242880:
            logstring("File is too big!","Red")
            return False
        return True

        
