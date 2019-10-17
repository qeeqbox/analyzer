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
def checkpackedfiles(_path,files):
    try:
        detect = 0
        p = Popen(["7z", "l", _path], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        for _ in files:
            if _.lower() in output.decode("utf-8").lower():
                detect += 1
        if detect == len(files):
            return True
    except:
        pass
    return False

@verbose(verbose_flag)
def dmgunpack(_path):
    p = Popen(["dmg2img",_path,_path+".img"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, err = p.communicate()
    if b"dmg image is corrupted" not in output:
        return _path+".img"
    else:
        return None

@verbose(verbose_flag)
def unpackfile(data,_path):
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
    except:
        pass


class FileTypes:
    @progressbar(True,"Starting FileTypes")
    def __init__(self):
        pass

    @verbose(verbose_flag)
    def setupmalwarefolder(self,folder):
        self.malwarefarm = folder
        if not self.malwarefarm.endswith(path.sep): self.malwarefarm = self.malwarefarm+path.sep
        if not path.isdir(self.malwarefarm): mkdir(self.malwarefarm)

    @verbose(verbose_flag)
    def createtempfolder(self,data,_path):
        md5 = data["Details"]["Properties"]["md5"]
        if not path.exists(self.malwarefarm+md5):
            mkdir(self.malwarefarm+md5)
        copyfile(_path,self.malwarefarm+md5+path.sep+"temp")
        data["Location"] = {"Original":_path,
                            "File":self.malwarefarm+md5+path.sep+"temp",
                            "html":self.malwarefarm+md5+path.sep+"html",
                            "json":self.malwarefarm+md5+path.sep+"json",
                            "Folder":self.malwarefarm+md5+path.sep+"temp_unpacked"}

    @verbose(verbose_flag)
    def getdetailes(self,data,_path):
        data["Details"] = {"Properties":{},
                           "_Properties":{}}
        name = path.basename(_path)
        f = open(_path,"rb").read()
        _md5 = md5(f).hexdigest()
        _sha1 = sha1(f).hexdigest()
        _sha256 = sha256(f).hexdigest()
        #_sha512 = sha512(f).hexdigest()
        size = path.getsize(_path)
        mime = from_file(_path,mime=True)
        charset = Magic(mime_encoding=True).from_file(_path)
        data["Details"]["Properties"]={ "Name": name,
                                        "md5": _md5,
                                        "sha1": _sha1,
                                        "sha256": _sha256,
                                        "size": size,
                                        "mime":mime,
                                        "charset":charset,
                                        "ssdeep":hash_from_file(_path)}
        return True

    @verbose(verbose_flag)
    @progressbar(True,"Handling unknown format")
    def unknownfile(self,data):
        if  data["Details"]["Properties"]["mime"] == "application/java-archive" or \
            data["Details"]["Properties"]["mime"] == "application/zip" or \
            data["Details"]["Properties"]["mime"] == "application/zlib":
            unpackfile(data,data["Location"]["File"])
            words,wordsstripped = getwordsmultifiles(data["Packed"]["Files"])
            data["StringsRAW"] = {"words":words,
                                  "wordsstripped":wordsstripped}
        else:
            words,wordsstripped = getwords(data["Location"]["File"])
            data["StringsRAW"] = {"words":words,
                                  "wordsstripped":wordsstripped}    

    @verbose(verbose_flag)
    def checkfilesig(self,data,_path,folder):
        self.setupmalwarefolder(folder)
        self.getdetailes(data,_path)
        self.createtempfolder(data,_path)
        if data["Details"]["Properties"]["size"] > 10242880:
            logstring("File is too big!","Red")
            return
        return True

        