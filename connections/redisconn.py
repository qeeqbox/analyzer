'''
    __G__ = "(G)bd249ce4"
    connection -> redis
'''

from os import environ
from pickle import dumps, loads
from redis import Redis
from analyzer.settings import json_settings

REDIS = Redis.from_url(json_settings[environ["analyzer_env"]]["redis_settings"])

def get_cache(val):
    '''
    Not used
    '''
    data = None
    data = REDIS.get(val)
    return loads(data)

def put_cache(val, data):
    '''
    Not used
    '''
    REDIS.set(val, dumps(data))
