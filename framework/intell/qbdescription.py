__G__ = "(G)bd249ce4"

from ..logger.logger import verbose, verbose_flag, verbose_timeout
from ..mics.funcs import ip_to_long
from ..mics.connection import find_item

@verbose(True,verbose_flag,verbose_timeout,"Adding descriptions to strings")
def add_description(_type,data,keyword):
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
                        result1 = find_item("QBResearches","ManHelp",{"cmd":word})
                        result2 = find_item("QBResearches","ManHelp",{"cmd":word.rstrip("_").lstrip("_")})
                        if result1:
                            description = result1["description"]
                        elif result2:
                            description = result2["description"]
                    elif _type == "WinApis":
                        result1 = find_item("QBResearches","WinApis",{"api":word})
                        result2 = find_item("QBResearches","WinApis",{"api":word[:-1]})
                        result3 = find_item("QBResearches","WinApis",{"api":word.rstrip("_").lstrip("_")})
                        if result1:
                            description = result1["description"]
                        elif result2:
                            description = result2["description"]
                        elif result3:
                            description = result3["description"]
                    elif _type == "WinDlls":
                        result1 = find_item("QBResearches","WinDlls",{"dll":word})
                        if result1:
                            description = result1["description"]
                    elif _type == "WinSections":
                        result1 = find_item("QBResearches","WinSections",{"section":word})
                        if result1:
                            description = result1["description"]
                    elif _type == "DNSServers":
                        result1 = find_item("QBResearches","DNSServers",{"DNS":word})
                        if result1:
                            description = result1["description"] + " DNS Server"
                    elif _type == "LinuxSections":
                        result1 = find_item("QBResearches","LinuxSections",{"section":word})
                        if result1:
                            description = result1["description"]
                    elif _type == "WinResources":
                        result1 = find_item("QBResearches","WinResources",{"resource":word})
                        if result1:
                            description = result1["description"]
                    elif _type == "AndroidPermissions":
                        result1 = find_item("QBResearches","AndroidPermissions",{"permission":word.split("android.permission.")[1]})
                        if result1:
                            description = result1["description"]
                    elif _type == "URLshorteners":
                        result1 = find_item("QBResearches","URLshorteners",{"URL":word})
                        if result1:
                            description = result1["description"]
                    elif _type == "Emails":
                        result1 = find_item("QBResearches","Emails",{"email":word.split("@")[1]})
                        if result1:
                            description = result1["description"]
                    elif _type == "Ports":
                        result1 = find_item("QBResearches","Ports",{"port":int(word)})
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
                        lip = ip_to_long(word)
                        result1 = find_item("QBResearches","CountriesIPs",{"ipfrom": { "$lte": lip },"ipto": { "$gte": lip }})
                        if result1:
                            result2 = find_item("QBResearches","CountriesIDs",{"ctry":result1["ctry"]})
                            if result2:
                                x.update({"Code":result2["cid"],"Alpha2":result1["ctry"].lower(),"Description":result1["country"]})
                                continue
                    elif _type == "ReservedIP":
                        lip = ip_to_long(word)
                        result1 = find_item("QBResearches","ReservedIP",{"ipfrom": { "$lte": lip },"ipto": { "$gte": lip }})
                        if result1:
                            description = result1["description"]
                    if "Description" in x:
                        if len(x["Description"]) > 0:
                            continue
                    x.update({"Description":description})
            except Exception:
                pass