__V__ = "2020.V.02.28"

defaultdb = {"dbname":"analyzer",
			 "reportscoll":"reports",
			 "filescoll":"files",
			 "userscoll":"users",
			 "alllogscoll":"alllogs",
			 "taskfileslogscoll":"taskfileslogs",
			 "taskdblogscoll":"taskdblogs"}

json_settings = {"local":{
					"mongo_settings_host":"localhost",
					"mongo_settings":"mongodb://localhost:27017/",
					"redis_host": "localhost",
					"redis_port":6379,
					"function_timeout":100,
					"analyzer_timeout":120,
					"web_mongo":[{   "ALIAS": "default",
								     "DB":    defaultdb["dbname"],
								     "HOST": "localhost",
								     "PORT": 27017
								    }]},
				"docker":{
					"mongo_settings_host":"mongodb",
					"mongo_settings":"mongodb://mongodb:27017/",
					"redis_host": "redis",
					"redis_port":6379,
					"function_timeout":100,
					"analyzer_timeout":120,
					"web_mongo":[{   "ALIAS": "default",
								     "DB":    defaultdb["dbname"],
								     "HOST": "mongodb",
								     "PORT": 27017
								    }]}}

meta_users_settings = {'db_alias':'default','collection': defaultdb["userscoll"],'strict': False}
meta_files_settings = {'db_alias':'default','collection': defaultdb["filescoll"],'strict': False}
meta_reports_settings = {'db_alias':'default','collection': defaultdb["reportscoll"],'strict': False}
meta_task_files_logs_settings = {'db_alias':'default','collection': defaultdb["taskfileslogscoll"],'strict': False}
meta_task_logs_settings = {'db_alias':'default','collection': defaultdb["taskdblogscoll"],'strict': False}
elastic_db = {u'host': u'elasticsearch', u'port': 9200}