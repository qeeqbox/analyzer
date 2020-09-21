from pickle import dumps, loads
from os import environ
from redis import Redis
from analyzer.settings import json_settings

_redis = Redis.from_url(json_settings[environ["analyzer_env"]]["redis_settings"])

def get_cache(val):
	data = None
	data = _redis.get(val)
	return loads(data)

def put_cache(val,data):
	_redis.set(val,dumps(data))