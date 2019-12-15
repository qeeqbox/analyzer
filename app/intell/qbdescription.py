__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag,verbose_timeout
from ..mics.funcs import iptolong
from ..mics.connection import finditem

@verbose(True,verbose_flag,verbose_timeout,"Adding descriptions to strings")
def adddescription(_type,data,keyword):
    '''
    add description to buffer
    '''
    if len(data) > 0:
        for x in data:
            try:
                if x[keyword]:
                    word = x[keyword].lower()
                    description = ""
                    if _type == "ManHelp":
                        result1 = finditem("QBResearches","ManHelp",{"cmd":word})
                        result2 = finditem("QBResearches","ManHelp",{"cmd":word.rstrip("_").lstrip("_")})
                        if result1:
                            description = result1["description"]
                        elif result2:
                            description = result2["description"]
                    elif _type == "WinApis":
                        result1 = finditem("QBResearches","WinApis",{"api":word})
                        result2 = finditem("QBResearches","WinApis",{"api":word[:-1]})
                        result3 = finditem("QBResearches","WinApis",{"api":word.rstrip("_").lstrip("_")})
                        if result1:
                            description = result1["description"]
                        elif result2:
                            description = result2["description"]
                        elif result3:
                            description = result3["description"]
                    elif _type == "WinDlls":
                        result1 = finditem("QBResearches","WinDlls",{"dll":word})
                        if result1:
                            description = result1["description"]
                    elif _type == "WinSections":
                        result1 = finditem("QBResearches","WinSections",{"section":word})
                        if result1:
                            description = result1["description"]
                    elif _type == "DNSServers":
                        result1 = finditem("QBResearches","DNSServers",{"DNS":word})
                        if result1:
                            description = result1["description"] + " DNS Server"
                    elif _type == "LinuxSections":
                        result1 = finditem("QBResearches","LinuxSections",{"section":word})
                        if result1:
                            description = result1["description"]
                    elif _type == "WinResources":
                        result1 = finditem("QBResearches","WinResources",{"resource":word})
                        if result1:
                            description = result1["description"]
                    elif _type == "AndroidPermissions":
                        result1 = finditem("QBResearches","AndroidPermissions",{"permission":word.split("android.permission.")[1]})
                        if result1:
                            description = result1["description"]
                    elif _type == "URLshorteners":
                        result1 = finditem("QBResearches","URLshorteners",{"URL":word})
                        if result1:
                            description = result1["description"]
                    elif _type == "Ports":
                        result1 = finditem("QBResearches","Ports",{"port":int(word)})
                        if result1:
                            if keyword == "SourcePort":
                                x.update({"SPDescription":result1["service"]})
                            elif keyword == "DestinationPort":
                                x.update({"DPDescription":result1["service"]})
                            elif keyword == "Port":
                                x.update({"Description":result1["description"]})
                        continue
                    elif _type == "CountriesIPs":
                        if len(x["Description"]) > 0:
                            continue
                        lip = iptolong(word)
                        result1 = finditem("QBResearches","CountriesIPs",{"ipfrom": { "$lte": lip },"ipto": { "$gte": lip }})
                        if result1:
                            result2 = finditem("QBResearches","CountriesIDs",{"ctry":result1["ctry"]})
                            if result2:
                                x.update({"Code":result2["cid"],"Alpha2":result1["ctry"].lower(),"Description":result1["country"]})
                                continue
                    elif _type == "ReservedIP":
                        lip = iptolong(word)
                        result1 = finditem("QBResearches","ReservedIP",{"ipfrom": { "$lte": lip },"ipto": { "$gte": lip }})
                        if result1:
                            description = result1["description"]
                    if "Description" in x:
                        if len(x["Description"]) > 0:
                            continue
                    x.update({"Description":description})
            except Exception:
                pass