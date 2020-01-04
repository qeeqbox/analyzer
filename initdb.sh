if which mongo ; then
	mongo QBWindows --eval "db.dropDatabase()"
	mongo QBResearches --eval "db.dropDatabase()"
	mongorestore -d QBWindows /framework/databases/Windows/
	mongorestore -d QBResearches /framework/databases/Researches/
else
	echo "Please install mongodb"
fi