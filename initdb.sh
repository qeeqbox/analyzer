if which mongo ; then
	if service --status-all |& grep -Fq 'mongodb'; then    
  		service mongodb start    
	fi
	sleep 5
	mongorestore --username changeme_9620eh26sfvka017fx --password changeme_0cx821ncf7qg17ahx3 -d QBWindows databases/Windows/ --authenticationDatabase admin
	mongorestore --username changeme_9620eh26sfvka017fx --password changeme_0cx821ncf7qg17ahx3 -d QBResearches databases/Researches/ --authenticationDatabase admin
else
	echo "Please install mongodb"
fi
