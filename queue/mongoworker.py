__G__ = "(G)bd249ce4"

from datetime import datetime
from pymongo import CursorType
from pymongo.errors import ConnectionFailure
from time import sleep
from threading import Event
from ..logger.logger import log_string
from ..connections.mongodbconn import client
from ..settings import jobsqueuedb

class qbworker():
    def __init__(self, func, wait):
        self.client = None
        self.cur = None
        self.client = client
        self.dbname = jobsqueuedb["dbname"]
        self.collname = jobsqueuedb["jobscoll"]
        if bool(self.dbname in self.client.list_database_names()):
            self.cur = self.client[self.dbname][self.collname]
            self.func = func
            self.daemon = True
            self.cancel = Event()
            self.wait = 3
            self.run_worker()
        else:
            log_string("Database error","Red")

    def check_connection(self):
        try:
            self.client.admin.command('ismaster')
            return True
        except ConnectionFailure:
            return False

    def run_worker(self):
        if self.cur != None:
            log_string("Waiting for tasks..","Green")
            cursor = self.cur.find({'status': 'wait'},cursor_type=CursorType.TAILABLE_AWAIT)
            while cursor.alive and not self.cancel.isSet() and self.cur.find_one({'status': 'ON__'}):
                try:
                    record = cursor.next()
                    self.execute_task(record)
                except:
                    sleep(self.wait)
        else:
            log_string("Worker failed","Red")

    def execute_task(self, record):
        if self.cur != None:
            self.cur.find_one_and_update({'_id': record['_id']},{'$set': {'status': 'work', 'started': datetime.now()}})
            if record['data'] != '':
                self.func(record['data'],True)
                self.cur.find_one_and_update({'_id': record['_id']},{'$set': {'status': 'done','finished': datetime.now()}})
                return True
            else:
                self.cur.find_one_and_update({'_id': record['_id']},{'$set': {'status': 'issue','finished': datetime.now()}})
                return False