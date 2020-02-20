from redis import Redis
from pickle import dumps, loads
from os import environ
from analyzer.settings import json_settings

_redis = Redis(host=json_settings[environ["analyzer_env"]]["redis_host"], port=json_settings[environ["analyzer_env"]]["redis_port"], db=0)

def get_cache(val):
    data = None
    data = _redis.get(val)
    return loads(data)
    
def put_cache(val,data):
    _redis.set(val,dumps(data))