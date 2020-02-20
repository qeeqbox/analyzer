__G__ = "(G)bd249ce4"

from datetime import datetime
from redis import Redis
from pickle import dumps, loads

class QBQueue(object):
    def __init__(self, name, namespace='queue', **kwargs):
        self.key = '%s:%s' %(namespace, name)
        self._redis = Redis(**kwargs)
        self.enable_get()
        self.enable_put()

    def __len__(self):
        return self._redis.llen(self.key)
    
    def empty(self):
        return self.qsize() == 0
    
    def clear(self):
        self._redis.delete(self.key)

    def get_status(self):
        if self._redis.get('_get') == b"True":
            return True
        else:
            return False

    def put_status(self):
        if self._redis.get('_put') == b"True":
            return True
        else:
            return False
    
    def enable_get(self):
        self._redis.set('_get',"True")

    def enable_put(self):
        self._redis.set('_put',"True")

    def disable_get(self):
        self._redis.set('_get',"False")

    def disable_put(self):
        self._redis.set('_put',"False")

    def get(self, block=False, timeout=1):
        #block+timeout wait 1 sec until task is available  
        task = None
        if self.get_status():
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
        task = None
        if self.put_status():
            time_now = datetime.now()
            data.update({"uuid":uuid})
            task = {   'jobID': uuid,
                       'status': 'wait',
                       'created': time_now,
                       'started': time_now,
                       'finished': time_now,
                       'data': data}
            self._redis.rpush(self.key,dumps(task))

#queue = QBQueue("analyzer", host="localhost", port=6379, db=0)
#queue.enable_get()
#queue.enable_put()
#print(queue.get_status())