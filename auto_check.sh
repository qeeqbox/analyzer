FILENAME=../onoff
OUTPUT=output
while true
do 
	if  grep -q "pass" "$FILENAME" ; then
	    echo "Good! -> auto commit"
	    sed -i "s/\"auto_testing\":\".*\"/\"auto_testing\":\"`uuidgen`\"/g" info
	    git add .
	    git commit -m "auto commit"
	    git show --name-only | tail -f -n 1 > output
	    if  grep -q "info" "$OUTPUT" ; then
	    	git push
	    	echo "pushed :)"
	    fi
	else
	    echo "Hmmm!"
	fi
    sleep 90
done
