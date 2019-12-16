from datetime import datetime
from pymongo import MongoClient
from uuid import uuid4

class qbjobqueue:
    def __init__(self, name, init=True):
        self.conn = MongoClient('mongodb://localhost:27017/')
        self.db = self.conn[name]
        if init:
            self.db.drop_collection('jobs')
            self.col = self.db.create_collection('jobs', capped=True,size=100000)
        else:
            if bool('jobs' in self.db.list_collection_names()):
                self.col = self.db['jobs']
            else:
                return
        self.col.insert_one({ 'JobID': str(uuid4()),
                              'status': 'dumy',
                              'created': datetime.now(),
                              'started': datetime.now(),
                              'finished': datetime.now(),'data': '',})
        self.cur = self.db['jobs']

    def insert(self, jobID, data):
        if jobID != '':
            setadd = { 'jobID': jobID,
                       'status': 'wait',
                       'created': datetime.now(),
                       'started': datetime.now(),
                       'finished': datetime.now(),
                       'data': data,
                       }
            id = self.col.insert_one(setadd)
            if id:
                return jobID
        return False

    def count(self):
        cursor = self.col.find({'status': 'wait'})
        if cursor:
            return cursor.count()

    def clear(self):
        self.col.drop()

    def stop(self):
        self.cancel.set()

    def status(self, JobID):
        return self.col.find_one({'jobID': JobID})['status']

#qbjobqueue("jobsqueue",False).insert("111","--buffer \"google.com bit.ly\" --full --json")


      