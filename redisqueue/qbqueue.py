__G__ = "(G)bd249ce4"

from datetime import datetime
from redis import Redis
from pickle import dumps, loads

class QBQueue(object):
    def __init__(self, name, namespace='queue', **kwargs):
        self.key = '%s:%s' %(namespace, name)
        self._redis = Redis(**kwargs)
    
    def __len__(self):
        return self._redis.llen(self.key)
    
    def empty(self):
        return self.qsize() == 0
    
    def clear(self):
        self._redis.delete(self.key)
    
    def get(self, block=False, timeout=1):
        #wait 1 sec until task is available  
        if block:
            task = self._redis.blpop(self.key, timeout=timeout)
            if task is not None:
                task = task[1]
        else:
            task = self._redis.lpop(self.key)
            if task != None:
                task = loads(task)
                task["started"] = datetime.now()
        return task
    
    def put(self, uuid, data):
        time_now = datetime.now()
        data.update({"uuid":uuid})
        task = {   'jobID': uuid,
                   'status': 'wait',
                   'created': time_now,
                   'started': time_now,
                   'finished': time_now,
                   'data': data}
        self._redis.rpush(self.key,dumps(task))