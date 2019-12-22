from ..logger.logger import log_string,verbose,verbose_flag,verbose_timeout
from os import path, walk
from subprocess import PIPE,Popen
from hashlib import md5
from magic import from_file,Magic
from mimetypes import guess_type

@verbose(True,verbose_flag,verbose_timeout,None)
def check_packed_files(_path,files) -> bool:
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

@verbose(True,verbose_flag,verbose_timeout,None)
def dmg_unpack(_path) -> str:
    '''
    convert dmg to img
    '''
    p = Popen(["dmg2img",_path,_path+".img"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, err = p.communicate()
    if b"dmg image is corrupted" not in output:
        return _path+".img"

@verbose(True,verbose_flag,verbose_timeout,None)
def unpack_file(data,_path):
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
        for currentp_ath, folders, files in walk(data["Location"]["Folder"]):
            for file in files:
                f = open(path.join(currentp_ath, file),"rb").read()
                _md5 = md5(f).hexdigest()
                mime = from_file(path.join(currentp_ath, file),mime=True)
                data["Packed"]["Files"].append({"Name":file,
                                                "Type":mime,
                                                "Extension":guess_type(path.join(currentp_ath, file))[0],
                                                "Path":path.join(currentp_ath, file),
                                                "md5":_md5})
                data["FilesDumps"].update({path.join(currentp_ath, file):f})
    except:
        pass
