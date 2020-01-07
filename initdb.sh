if which mongo ; then
	mongo QBWindows --eval "db.dropDatabase()"
	mongo QBResearches --eval "db.dropDatabase()"
	mongorestore -d QBWindows /databases/Windows/
	mongorestore -d QBResearches /databases/Researches/
else
	echo "Please install mongodb"
fi