'''
    __G__ = "(G)bd249ce4"
    redis -> queue
'''

from pickle import dumps, loads
from datetime import datetime
from redis import Redis


class QBQueue():
    '''
    this will be changed to rabbitq
    queue = QBQueue("analyzer", host="localhost", port=6379, db=0)
    queue.enable_get()
    queue.enable_put()
    print(queue.get_status())
    '''

    def __init__(self, name, url, namespace='queue'):
        '''
        initialize class and enable get/put
        '''
        self.key = '%s:%s' % (namespace, name)
        self._redis = Redis.from_url(url)
        self.enable_get()
        self.enable_put()

    def __len__(self):
        '''
        get number of tasks
        '''
        return self._redis.llen(self.key)

    def empty(self):
        '''
        check if queue is empty
        '''
        return 0
        # return self.qsize() == 0 <- Instance of 'QBQueue' has no 'qsize' member (no-member)

    def clear(self):
        '''
        clear queue
        '''
        self._redis.delete(self.key)

    def get_status(self):
        '''
        get queue status
        '''
        if self._redis.get('_get') == b"True":
            return True
        return False

    def put_status(self):
        '''
        change queue status
        '''
        if self._redis.get('_put') == b"True":
            return True
        return False

    def enable_get(self):
        '''
        enable get
        '''
        self._redis.set('_get', "True")

    def enable_put(self):
        '''
        enable put
        '''
        self._redis.set('_put', "True")

    def disable_get(self):
        '''
        disable get
        '''
        self._redis.set('_get', "False")

    def disable_put(self):
        '''
        disable put
        '''
        self._redis.set('_put', "False")

    def get(self, block=False, timeout=1):
        '''
        block+timeout wait 1 sec until task is available
        '''
        task = None
        if self.get_status():
            if block:
                task = self._redis.blpop(self.key, timeout=timeout)
                if task is not None:
                    task = task[1]
            else:
                task = self._redis.lpop(self.key)
                if task is not None:
                    task = loads(task)
                    task["started"] = datetime.now()
        return task

    def put(self, uuid, data):
        '''
        add task
        '''
        task = None
        if self.put_status():
            time_now = datetime.now()
            data.update({"uuid": uuid})
            task = {'jobID': uuid,
                    'status': 'wait',
                    'created': time_now,
                    'started': time_now,
                    'finished': time_now,
                    'data': data}
            self._redis.rpush(self.key, dumps(task))
