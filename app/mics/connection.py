from ..logger.logger import log_string,verbose,verbose_flag,verbose_timeout
from pymongo import MongoClient
from gridfs import GridFS

client = None
if client == None:client = MongoClient('mongodb://localhost:27017/')

def update_item(db,col,_id,_set):
    item = client[db][col].find_one_and_update({'_id': _id},{'$set': _set})
    if item != None:
        return item
    else:
        return False

def add_item(db,col,_set):
    item = client[db][col].insert_one(_set)
    if item != None:
        return item
    else:
        return False

def find_item(db,col,_set):
    item = client[db][col].find_one(_set,{'_id': False})
    if item != None:
        return item
    else:
        return ""

def find_items(db,_set):
    _list = []
    for col in client[db].list_collection_names():
        items = client[db][col].find(_set,{'_id': False})
        if items != None:
            for item in items:
                item.update({"Collection":col})
                _list.append(item)

    if len(_list) > 0:
        return _list
    else:
        return ""

def add_item_fs(db,filebuffer,name,_set):
    item = GridFS(client[db]).put(filebuffer,filename=name,metadata=_set,encoding='utf-8')
    if item != None:
        return item
    else:
        return False