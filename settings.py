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
			 "logscoll":"logs",
			 "filescoll":"files",
			 "userscoll":"users",
			 "alllogscoll":"alllogs",
			 "tasklogscoll":"tasklogs"}

jobsqueuedb = {"dbname":"analyzer",
			   "jobscoll":"jobs"}

mongodb_settings_docker = [{
				     "ALIAS": "default",
				     "DB":    defaultdb["dbname"],
				     "HOST": json_settings["mongo_settings_host_docker"],
				     "PORT": 27017
				    },
				    {
				     "ALIAS": "jobsqueue",
				     "DB": jobsqueuedb["dbname"],
				     "HOST": json_settings["mongo_settings_host_docker"],
				     "PORT": 27017
				    }]

mongodb_settings_local = [{
				     "ALIAS": "default",
				     "DB":    defaultdb["dbname"],
				     "HOST": json_settings["mongo_settings_host_local"],
				     "PORT": 27017
				    },
				    {
				     "ALIAS": "jobsqueue",
				     "DB": jobsqueuedb["dbname"],
				     "HOST": json_settings["mongo_settings_host_local"],
				     "PORT": 27017
				    }]

meta_users_settings = {'db_alias':'default','collection': defaultdb["userscoll"],'strict': False}
meta_jobs_settings = {"db_alias": "jobsqueue",'collection':jobsqueuedb["jobscoll"],'strict': False}
meta_files_settings = {'db_alias':'default','collection': defaultdb["filescoll"],'strict': False}
meta_reports_settings = {'db_alias':'default','collection': defaultdb["reportscoll"],'strict': False}
meta_logs_settings = {'db_alias':'default','collection': defaultdb["logscoll"],'strict': False}