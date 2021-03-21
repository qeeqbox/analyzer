'''
    __G__ = "(G)bd249ce4"
    connection -> monogo client
'''

from os import environ
from pymongo import MongoClient
from gridfs import GridFS
from bson.objectid import ObjectId
from analyzer.settings import json_settings

CLIENT = MongoClient(json_settings[environ["analyzer_env"]]["mongo_settings"])


def update_task(database_name, collection_name, task, log):
    '''
    simple item update
    '''
    CLIENT[database_name][collection_name].update({'task': task}, {'$push': {'logs': log}}, upsert=True)


def update_item(database_name, collection_name, _id, _set):
    '''
    simple item update
    '''
    item = CLIENT[database_name][collection_name].find_one_and_update({'_id': _id}, {'$set': _set})
    if item is not None:
        return item
    return False


def add_item(database_name, collection_name, _set):
    '''
    add an item and return it otherwise False
    '''
    item = CLIENT[database_name][collection_name].insert_one(_set)
    if item is not None:
        return item
    return False


def find_item(database_name, collection_name, _set):
    '''
    find an item and return it otherwise return empty string
    '''
    item = CLIENT[database_name][collection_name].find_one(_set, {'_id': False})
    if item is not None:
        return item
    return ""


def find_items(database_name, _set):
    '''
    find multi items and return them otherwise return empty string
    '''
    _list = []
    for collection_name in CLIENT[database_name].list_collection_names():
        items = CLIENT[database_name][collection_name].find(_set, {'_id': False})
        if items is not None:
            for item in items:
                item.update({"Collection": collection_name})
                _list.append(item)

    if len(_list) > 0:
        return _list
    return ""


def add_item_fs(database_name, collection_name, file_buffer, name, _set, uuid, _type, time):
    '''
    find an item to FS
    '''
    item = GridFS(CLIENT[database_name]).put(file_buffer, filename=name, uuid=uuid, content_type=_type, encoding='utf-8')
    if item is not None:
        item = CLIENT[database_name][collection_name].insert_one({"uuid": uuid, "type": _type, "file": ObjectId(item), "time": time})
        if item is not None:
            return item
    return False


def get_it_fs(database_name, _set):
    '''
    get an item from  FS
    '''
    item = GridFS(CLIENT[database_name]).find_one(_set)
    if item is not None:
        return item.read()
    return False
