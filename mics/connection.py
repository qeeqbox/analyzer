from pymongo import MongoClient
from gridfs import GridFS
from bson.objectid import ObjectId
from os import environ, path
from json import load

client = None

try:
    if client == None:
        settings = path.abspath(path.join(path.dirname( __file__ ),'..','settings.json'))
        with open(settings) as f:
            json_settings = load(f)
            if environ["analyzer_env"] == "local":
                client = MongoClient(json_settings["mongo_settings_local"])
            elif environ["analyzer_env"] == "docker":
                client = MongoClient(json_settings["mongo_settings_docker"])
except:
    client = None

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

#def add_item_fs(db,filebuffer,name,_set,uuid,_type):
#    item = GridFS(client[db]).put(filebuffer,filename=name,metadata=_set,uuid=uuid,type=_type,encoding='utf-8')
#    if item != None:
#        return item
#    else:
#        return False

def add_item_fs(db, col,filebuffer,name,_set,uuid,_type,time):
    item = GridFS(client[db]).put(filebuffer,filename=name,uuid=uuid,content_type=_type,encoding='utf-8')
    if item != None:
        item = client[db][col].insert_one({"uuid":uuid,"type":_type,"file":ObjectId(item),"time":time})
        if item != None:
            return item
    else:
        return False

def get_it_fs(db,_set):
    item = GridFS(client[db]).find_one(_set)
    if item != None:
        return item.read()
    else:
        return False