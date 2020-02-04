json_settings = {
	"mongo_settings_host_docker":"mongodb",
	"mongo_settings_host_local":"localhost",
	"mongo_settings_local":"mongodb://localhost:27017/",
	"mongo_settings_docker":"mongodb://mongodb:27017/",
	"function_timeout":100,
	"analyzer_timeout":120,
}

mongodb_settings_docker = [{
				     "ALIAS": "default",
				     "DB":    'webinterface',
				     "HOST": json_settings["mongo_settings_host_docker"],
				     "PORT": 27017
				    },
				    {
				     "ALIAS": "jobsqueue",
				     "DB": 'jobsqueue',
				     "HOST": json_settings["mongo_settings_host_docker"],
				     "PORT": 27017
				    }]

mongodb_settings_local = [{
				     "ALIAS": "default",
				     "DB":    'webinterface',
				     "HOST": json_settings["mongo_settings_host_local"],
				     "PORT": 27017
				    },
				    {
				     "ALIAS": "jobsqueue",
				     "DB": 'jobsqueue',
				     "HOST": json_settings["mongo_settings_host_local"],
				     "PORT": 27017
				    }]