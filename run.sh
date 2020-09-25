
#!/bin/bash

echo -e "\nQeeqBox Analyzer v$(jq -r '.version' info) starter script -> https://github.com/qeeqbox/analyzer"

setup_requirements () {
	sudo apt update -y
	sudo apt install -y linux-headers-$(uname -r) docker.io jq xdg-utils
	sudo curl -L "https://github.com/docker/compose/releases/download/1.25.5/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
	sudo chmod +x /usr/local/bin/docker-compose
	which docker-compose && echo "Good"
	which docker && echo "Good"
}

wait_on_web_interface () {
echo ''
until $(curl --silent --head --fail http://127.0.0.1:8000/login/ --output /dev/null); do
echo -ne "\n\n[\033[47m\033[0;31mInitializing project in progress..\033[0m]\n\n"
sleep 5
done
echo ''
xdg-open http://127.0.0.1:8000/login
}

dev_project () {
	sudo docker-compose -f docker-compose-dev.yml up --build
}

stop_containers () {
	sudo docker stop $(sudo docker ps -aq)
} 

deploy_aws_project () {
	echo "Will be added later on"
}

auto_configure () {
	stop_containers
	wait_on_web_interface & 
	setup_requirements 
	dev_project 
	stop_containers
}

if [[ "$1" == "auto_configure" ]]; then
	stop_containers
	wait_on_web_interface & 
	setup_requirements 
	dev_project 
	stop_containers
fi

while read -p "`echo -e '\nChoose an option:\n1) Setup requirements (docker, docker-compose)\n9) Run auto configuration\n>> '`"; do
  case $REPLY in
    "1") setup_requirements;;
    "9") auto_configure;;
    *) echo "Invalid option";;
  esac
done
