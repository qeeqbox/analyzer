sudo docker stop $(sudo docker ps -a -q)
sudo docker rm $(sudo docker ps -qa)
sudo docker rmi -f $(sudo docker images -qa)
sudo docker volume rm $(sudo docker volume ls -qf)
sudo docker network rm $(sudo docker network ls -q)
sudo docker volume prune
sudo docker system prune
