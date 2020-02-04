if which mongo ; then
	if service --status-all |& grep -Fq 'mongodb'; then    
  		service mongodb start    
	fi
	sleep 5
	mongo QBWindows --eval "db.dropDatabase()"
	mongo QBResearches --eval "db.dropDatabase()"
	mongorestore -d QBWindows databases/Windows/
	mongorestore -d QBResearches databases/Researches/
else
	echo "Please install mongodb"
fi