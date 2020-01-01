from datetime import datetime
from pymongo import MongoClient
from uuid import uuid4
from ..logger.logger import verbose, verbose_flag, verbose_timeout

@verbose(True,verbose_flag,verbose_timeout,"Terminating worker")
def set_dumm_off(db,col):
    conn = MongoClient('mongodb://localhost:27017/')
    item = conn[db][col].find_one({'status': 'ON__'},{'_id': False})
    if item:
        ret = conn[db][col].update_one(item, {"$set":{'status':'OFF_'}})

class qbjobqueue:
    @verbose(True,verbose_flag,verbose_timeout,"Starting qbjobqueue")
    def __init__(self, name, init=True):
        self.conn = MongoClient('mongodb://localhost:27017/')
        self.db = None
        self.col = None
        self.cur = None
        if self.check_connection():
            self.init_database(name,init)

    @verbose(True,verbose_flag,verbose_timeout,"Initializing database")
    def init_database(self,name, init=True):
        self.db = self.conn[name]
        if init:
            self.db.drop_collection('jobs')
            self.col = self.db.create_collection('jobs', capped=True,size=100000)
        else:
            if bool('jobs' in self.db.list_collection_names()):
                self.col = self.db['jobs']
            else:
                return False
        self.col.insert_one({ 'jobID': str(uuid4()),
                              'status': 'ON__',
                              'created': datetime.now(),
                              'started': datetime.now(),
                              'finished': datetime.now(),'data': ''})
        self.cur = self.db['jobs']
        return True

    def check_connection(self):
        try:
            self.conn.admin.command('ismaster')
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


      