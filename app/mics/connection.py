from ..logger.logger import logstring,verbose,verbose_flag,verbose_timeout
from pymongo import MongoClient

client = None
if client == None:client = MongoClient('mongodb://localhost:27017/')

def finditem(db,col,_set):
    item = client[db][col].find_one(_set,{'_id': False})
    if item != None:
        return item
    else:
        return ""

def finditems(db,_set):
    _list = []
    for col in client["QBWindows"].list_collection_names():
        items = client[db][col].find(_set,{'_id': False})
        if items != None:
            for item in items:
                item.update({"Collection":col})
                _list.append(item)

    if len(_list) > 0:
        return _list
    else:
        return ""