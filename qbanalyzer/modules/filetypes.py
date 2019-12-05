__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.funcs import getwords,getwordsmultifiles,getentropy
from shutil import copyfile,rmtree
from os import path,mkdir,walk
from subprocess import PIPE,Popen
from hashlib import md5, sha1, sha256
from magic import from_file,Magic
from ssdeep import hash_from_file
from mimetypes import guess_type
from re import match

@verbose(True,verbose_flag,None)
def checkpackedfiles(_path,files) -> bool:
    '''
    check if archive contains strings or not 
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

@verbose(True,verbose_flag,None)
def dmgunpack(_path) -> str:
    '''
    convert dmg to img
    '''
    p = Popen(["dmg2img",_path,_path+".img"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, err = p.communicate()
    if b"dmg image is corrupted" not in output:
        return _path+".img"

@verbose(True,verbose_flag,None)
def unpackfile(data,_path):
    '''
    unpack files using 7z into temp folder
    '''
    data["Packed"] = {"Files":[],
                      "Detected":[],
                      "_Detected":["Name","Path"],
                      "_Files":["Name","Type","Extension","md5","Path"]}
    try:
        p = Popen(["7z", "t", _path,"-pdummypassword2019!!"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        if b"ERROR: Wrong password" in err:return
        p = Popen(["7z", "x", _path,"-aoa","-o"+data["Location"]["Folder"]], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        for currentpath, folders, files in walk(data["Location"]["Folder"]):
            for file in files:
                f = open(path.join(currentpath, file),"rb").read()
                _md5 = md5(f).hexdigest()
                mime = from_file(path.join(currentpath, file),mime=True)
                data["Packed"]["Files"].append({"Name":file,
                                                "Type":mime,
                                                "Extension":guess_type(path.join(currentpath, file))[0],
                                                "Path":path.join(currentpath, file),
                                                "md5":_md5})
                data["FilesDumps"].update({path.join(currentpath, file):f})
    except Exception as e:
        print(e)

@verbose(True,verbose_flag,None)
def convertsize(s):
    for u in ['B','KB','MB','GB']:
        if s < 1024.0:
            return "{:.2f}{}".format(s,u)
        else:
            s /= 1024.0
    return "File is too big"

@verbose(True,verbose_flag,None)
def checkbom(str):
    if str[:3] == '\xEF\xBB\xBF':
        return "UTF-8-SIG"
    elif str[:4] == '\xFF\xFE\x00\x00':
        return "UTF-32LE"
    elif str[:4] == '\x00\x00\xFF\xFE':
        return "UTF-32BE"
    elif str[:2] == '\xFF\xFE':
        return "UTF-16LE"
    elif str[:2] == '\xFE\xFF':
        return "UTF-16BE"
    return "None"

class FileTypes:
    @verbose(True,verbose_flag,"Starting FileTypes")
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

    @verbose(True,verbose_flag,None)
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

    @verbose(True,verbose_flag,None)
    def getdetailes(self,data,_path):
        '''
        get general details of file
        '''
        data["Details"] = {"Properties":{},
                           "_Properties":{}}
        f = open(_path,"rb").read()
        fbom = open(_path,"rb").read(4)
        data["Details"]["Properties"]={ "Name": path.basename(_path),
                                        "md5": md5(f).hexdigest(),
                                        "sha1": sha1(f).hexdigest(),
                                        "sha256": sha256(f).hexdigest(),
                                        "ssdeep":hash_from_file(_path),
                                        "size": convertsize(path.getsize(_path)),
                                        "mime":from_file(_path,mime=True),
                                        "extension":guess_type(_path)[0],
                                        "charset":Magic(mime_encoding=True).from_file(_path),
                                        "ByteOrderMark":checkbom(fbom),
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
        #if data["Details"]["Properties"]["size"] > 10242880:
        #    logstring("File is too big!","Red")
        #    return False
        return True

        
