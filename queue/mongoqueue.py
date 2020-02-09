__G__ = "(G)bd249ce4"

from datetime import datetime
from uuid import uuid4
from ..logger.logger import verbose, verbose_flag, verbose_timeout
from ..connections.mongodbconn import client
from ..settings import jobsqueuedb

class qbjobqueue:
    @verbose(True,verbose_flag,verbose_timeout,"Starting qbjobqueue")
    def __init__(self, init=True):
        self.client = client
        self.db = None
        self.col = None
        self.cur = None
        self.dbname = jobsqueuedb["dbname"]
        self.collname = jobsqueuedb["jobscoll"]
        if self.check_connection():
            self.init_database(self.dbname,init)

    @verbose(True,verbose_flag,verbose_timeout,"Initializing database")
    def init_database(self,name, init=True):
        self.db = self.client[name]
        if init:
            self.db.drop_collection(self.collname)
            self.col = self.db.create_collection(self.collname, capped=True,size=100000)
        else:
            if bool(self.collname in self.db.list_collection_names()):
                self.col = self.db[self.collname]
            else:
                return False
        self.col.insert_one({ 'jobID': str(uuid4()),
                              'status': 'ON__',
                              'created': datetime.now(),
                              'started': datetime.now(),
                              'finished': datetime.now(),'data': ''})
        self.cur = self.db[self.collname]
        return True

    def check_connection(self):
        try:
            self.client.admin.command('ismaster')
            return True
        except ConnectionFailure:
            return False

    def insert(self, uuid, data):
        if len(data) > 0 and self.col != None:
            data.update({"uuid":uuid})
            setadd = { 'jobID': uuid,
                       'status': 'wait',
                       'created': datetime.now(),
                       'started': datetime.now(),
                       'finished': datetime.now(),
                       'data': data}
            id = self.col.insert_one(setadd)
            if id:
                return jobID
        return False

    def count(self):
        if self.col != None:
            cursor = self.col.find({'status': 'wait'})
            if cursor:
                return cursor.count()

    def clear(self):
        if self.col != None:
            self.col.drop()

    def status(self, JobID):
        if self.col != None:
            return self.col.find_one({'jobID': JobID})['status']


      