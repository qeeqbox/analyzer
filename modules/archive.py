'''
    __G__ = "(G)bd249ce4"
    modules -> archive
'''

from os import path, walk
from mimetypes import guess_type
from subprocess import PIPE, Popen
from hashlib import md5
from magic import from_file
from analyzer.logger.logger import ignore_excpetion, verbose


@verbose(True, verbose_output=False, timeout=None, _str=None)
def check_packed_files(_path, files) -> bool:
    '''
    check if archive contains strings or not
    '''
    with ignore_excpetion(Exception):
        detect = 0
        process = Popen(["7z", "l", _path], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, error = process.communicate()
        output = output.decode("utf-8", errors="ignore")
        for _ in files:
            if _.lower() in output.lower():
                detect += 1
        if detect == len(files):
            return True

    return False


@verbose(True, verbose_output=False, timeout=None, _str=None)
def dmg_unpack(_path) -> str:
    '''
    convert dmg to img
    '''
    process = Popen(["dmg2img", _path, _path + ".img"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, error = process.communicate()
    if b"dmg image is corrupted" not in output:
        return _path + ".img"
    return ""


@verbose(True, verbose_output=False, timeout=None, _str=None)
def unpack_file(data, _path):
    '''
    unpack files using 7z into temp folder
    '''
    data["Packed"] = {"Files": [],
                      "Detected": [],
                      "_Detected": ["Name", "Path"],
                      "_Files": ["Name", "Type", "Extension", "md5", "Path"]}
    with ignore_excpetion(Exception):
        process = Popen(["7z", "t", _path, "-pdummypassword2019!!"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, error = process.communicate()
        if b"ERROR: Wrong password" in error:
            return
        process = Popen(["7z", "x", _path, "-aoa", "-o" + data["Location"]["Folder"]], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, error = process.communicate()
        for currentp_ath, folders, files in walk(data["Location"]["Folder"]):
            for file in files:
                temp_buffer = open(path.join(currentp_ath, file), "rb").read()
                _md5 = md5(temp_buffer).hexdigest()
                mime = from_file(path.join(currentp_ath, file), mime=True)
                data["Packed"]["Files"].append({"Name": file,
                                                "Type": mime,
                                                "Extension": guess_type(path.join(currentp_ath, file))[0],
                                                "Path": path.join(currentp_ath, file),
                                                "md5": _md5})
                data["FilesDumps"].update({path.join(currentp_ath, file): temp_buffer})
