#!/bin/bash

# Exporting all env variables;
echo -e "\e[32m[+] Initializing env variables.\e[0m"
export $(grep -v '^#' docker/docker.env | xargs -d '\n')

docker ps -a --filter "name=netscan" --format '{{.Names}}' | grep netscan-tool > /dev/null

if [ $? -eq 0 ]
then
    echo -e "\e[32m[+] Containers are already built.. Skipping\e[0m"
    echo -e "\e[32m[+] Starting containers...\e[0m"
    docker-compose start
    echo -e "\e[32m[+] Waiting 5 seconds for containers initialization...\e[0m"
    sleep 5
else 
    echo -e "\e[32m[+] Configuring system to run dockers...\e[0m"
    sudo sysctl -w vm.max_map_count=262144 > /dev/null

    echo -e "\e[32m[+] Starting docker containers...\e[0m"
    docker-compose up --quiet-pull --build --remove-orphans -d > /dev/null

    echo -e "\e[32m[+] Waiting 60 seconds for containers initialization...\e[0m"
    sleep 60

    echo -e "\e[32m[+] Configuring Kibana...\e[0m"
    curl -u elastic:${ELASTIC_PASSWORD} -s -X POST 'http://127.0.0.1:5601/api/saved_objects/_import?createNewCopies=true' -H "kbn-xsrf: true" --form "file=@$(pwd)/kibana/kibana_dashboards.ndjson" > /dev/null
fi

echo -e "\e[32m[+] Checking that everything is ok...\e[0m"
if [ $(docker ps  --format '{{.Names}}' | grep netscan-setup | wc -l) -gt 0 ]
then
    echo -e "\e[31m[!] Oops, something went wrong...\e[0m"
    exit 1
else 
    echo -e "\e[32m[+] Kibana credentials: \e[0m\e[31m\e[40melastic:${ELASTIC_PASSWORD}\e[0m"
    echo -e "\e[32m[+] Remember to change the neo4j password: http://localhost:7474/ (default: \e[0m\e[31m\e[40mneo4j:neo4j\e[0m\e[32m)\e[0m"

    echo -e "\e[32m[+] Entering into Netscan container...Enjoy !\e[0m"
    docker exec -it netscan-tool bash
fi

