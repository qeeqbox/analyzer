__V__ = "2020.V.02.24"

json_settings = {
	"mongo_settings_host_docker":"mongodb",
	"mongo_settings_host_local":"localhost",
	"mongo_settings_local":"mongodb://localhost:27017/",
	"mongo_settings_docker":"mongodb://mongodb:27017/",
	"function_timeout":100,
	"analyzer_timeout":120,
}

defaultdb = {"dbname":"analyzer",
			 "reportscoll":"reports",
			 "filescoll":"files",
			 "userscoll":"users",
			 "alllogscoll":"alllogs",
			 "taskfileslogscoll":"taskfileslogs",
			 "taskdblogscoll":"taskdblogs"}

mongodb_settings_docker = [{
				     "ALIAS": "default",
				     "DB":    defaultdb["dbname"],
				     "HOST": json_settings["mongo_settings_host_docker"],
				     "PORT": 27017
				    }]

mongodb_settings_local = [{
				     "ALIAS": "default",
				     "DB":    defaultdb["dbname"],
				     "HOST": json_settings["mongo_settings_host_local"],
				     "PORT": 27017
				    }]

meta_users_settings = {'db_alias':'default','collection': defaultdb["userscoll"],'strict': False}
meta_files_settings = {'db_alias':'default','collection': defaultdb["filescoll"],'strict': False}
meta_reports_settings = {'db_alias':'default','collection': defaultdb["reportscoll"],'strict': False}
meta_task_files_logs_settings = {'db_alias':'default','collection': defaultdb["taskfileslogscoll"],'strict': False}
meta_task_logs_settings = {'db_alias':'default','collection': defaultdb["taskdblogscoll"],'strict': False}
elastic_db = {u'host': u'elasticsearch', u'port': 9200}