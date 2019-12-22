from datetime import datetime
from pymongo import CursorType, MongoClient
from pymongo.errors import ConnectionFailure
from time import sleep
from threading import Event

class qbworker():
    def __init__(self, name, func, wait):
        self.conn = MongoClient('mongodb://localhost:27017/')
        if bool(name in self.conn.list_database_names()):
            self.cur = self.conn[name]['jobs']
            self.func = func
            self.daemon = True
            self.cancel = Event()
            self.wait = 3
            self.run_worker()
        else:
            print('DB error')

    def check_connection(conn):
        try:
            conn.admin.command('ismaster')
            return True
        except ConnectionFailure:
            print('Server not available')
            return False

    def run_worker(self):
        cursor = self.cur.find({'status': 'wait'},cursor_type=CursorType.TAILABLE_AWAIT)
        while cursor.alive and not self.cancel.isSet():
            try:
                record = cursor.next()
                self.execute_task(record)
            except:
                #print('Waiting')
                sleep(self.wait)

    def execute_task(self, record):
        self.cur.find_one_and_update({'_id': record['_id']},{'$set': {'status': 'work', 'started': datetime.now()}})
        if record['data'] is not '':
            self.func(record['data'],True)
            self.cur.find_one_and_update({'_id': record['_id']},{'$set': {'status': 'done','finished': datetime.now()}})
            return True
        else:
            self.cur.find_one_and_update({'_id': record['_id']},{'$set': {'status': 'issue','finished': datetime.now()}})
            return False



			