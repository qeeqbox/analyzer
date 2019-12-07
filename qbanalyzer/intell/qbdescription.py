__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.funcs import iptolong
from sqlite3 import connect
from os import path

refs = path.abspath(path.join(path.dirname( __file__ ),"..", 'refs'))
if not refs.endswith(path.sep): refs = refs+path.sep
cursor = connect(refs+'References.db').cursor()

@verbose(True,verbose_flag,"Adding descriptions to strings")
def adddescription(_type,data,keyword):
    '''
    add description to buffer
    '''
    global cursor
    if len(data) > 0:
        for x in data:
            try:
                if x[keyword]:
                    word = x[keyword].lower()
                    description = ""
                    if _type == "ManHelp":
                        result = cursor.execute('SELECT * FROM ManHelp WHERE cmd= ? OR cmd =?',(word,word.rstrip("_").lstrip("_"),)).fetchone()
                        if result:
                            description = result[2]
                    elif _type == "WinApis":
                        result = cursor.execute('SELECT * FROM WinApis WHERE api= ? OR api = ? OR api =?',(word,word[:-1],word.rstrip("_").lstrip("_")),).fetchone()
                        if result:
                            description = result[2]
                    elif _type == "WinDlls":
                        result = cursor.execute('SELECT * FROM WinDlls WHERE dll= ?',(word,)).fetchone()
                        if result:
                            description = result[2]
                    elif _type == "WinSections":
                        result = cursor.execute('SELECT * FROM WinSections WHERE section= ?',(word,)).fetchone()
                        if result:
                            description = result[2]
                    elif _type == "DNS":
                        result = cursor.execute('SELECT * FROM DNSServers WHERE dns= ?',(word,)).fetchone()
                        if result:
                            description = result[2] + " DNS Server"
                    elif _type == "LinuxSections":
                        result = cursor.execute('SELECT * FROM LinuxSections WHERE section= ?',(word,)).fetchone()
                        if result:
                            description = result[2]
                    elif _type == "WinResources":
                        result = cursor.execute('SELECT * FROM WinResources WHERE resource= ?',(word,)).fetchone()
                        if result:
                            description = result[2]
                    elif _type == "AndroidPermissions":
                        result = cursor.execute('SELECT * FROM AndroidPermissions WHERE permission= ?',(word.split("android.permission.")[1],)).fetchone()
                        if result:
                            description = result[3]
                    elif _type == "URLshorteners":
                        result = cursor.execute('SELECT * FROM URLshorteners WHERE URL= ?',(word,)).fetchone()
                        if result:
                            description = result[2]
                    elif _type == "Ports":
                        result = cursor.execute('SELECT * FROM Ports WHERE port= ?',(word,)).fetchone()
                        if result:
                            if keyword == "SourcePort":
                                x.update({"SPDescription":result[3]})
                            elif keyword == "DestinationPort":
                                x.update({"DPDescription":result[3]})
                            elif keyword == "Port":
                                x.update({"Description":result[4]})
                        continue
                    elif _type == "IPs":
                        if len(x["Description"]) > 0:
                            continue
                        lip = iptolong(word)
                        result = cursor.execute('SELECT * FROM CountriesIPs WHERE ipto >= ? AND ipfrom <= ?', (lip,lip,)).fetchone()
                        if result:
                            alpha2 = result[5]
                            _result = cursor.execute('SELECT * FROM CountriesIDs WHERE ctry= ?', (alpha2,)).fetchone()
                            if _result:
                                x.update({"Code":_result[4],"Alpha2":alpha2.lower(),"Description":result[7]})
                                continue
                    elif _type == "IPPrivate":
                        lip = iptolong(word)
                        result = cursor.execute('SELECT * FROM ReservedIP WHERE ipto >= ? AND ipfrom <= ?', (lip,lip,)).fetchone()
                        if result:
                            description = result[3]
                    if "Description" in x:
                        if len(x["Description"]) > 0:
                            continue
                    x.update({"Description":description})
            except:
                pass