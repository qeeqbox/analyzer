__G__ = "(G)bd249ce4"

from pymongo import MongoClient
from gridfs import GridFS
from bson.objectid import ObjectId
from os import environ
from analyzer.settings import json_settings

client = MongoClient(json_settings[environ["analyzer_env"]]["mongo_settings"])

def update_task(db,col,task,log):
    client[db][col].update({'task': task}, {'$push': {'logs': log}}, upsert = True)

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