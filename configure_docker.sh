#!/bin/bash

#########################
###       CONFIG      ###
#########################
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLACK_BACKGROUND="\e[40m"
BLUE_BACKGROUND="\e[44m"
ENDCOLOR="\e[0m"

# Exporting all env variables;
echo -e "${GREEN}[+] Initializing env variables.${ENDCOLOR}"
export $(grep -v '^#' docker/docker.env | xargs -d '\n')

docker ps -a --filter "name=netscan" --format '{{.Names}}' | grep netscan-kibana > /dev/null

if [ $? -eq 0 ]
then
    echo -e "${GREEN}[+] Containers are already built.. Skipping${ENDCOLOR}"
    echo -e "${GREEN}[+] Starting containers...${ENDCOLOR}"
    docker-compose start
    echo -e "${GREEN}[+] Waiting 15 seconds for containers initialization...${ENDCOLOR}"
    sleep 15
else
    echo -e "${GREEN}[+] Configuring the host system to run dockers...${ENDCOLOR}"
    sudo sysctl -w vm.max_map_count=262144 > /dev/null
    
    echo -e "${GREEN}[+] Building & Starting containers...${ENDCOLOR}"
    docker-compose up --build --remove-orphans -d > /dev/null
    docker build . -f docker/Dockerfile -t netscan:latest > /dev/null
    
    echo -e "${GREEN}[+] Configuring Elasticsearch...${ENDCOLOR}"
    until curl -s -k https://127.0.0.1:9200/ | grep -q "missing authentication credentials"; do sleep 10; done;
    curl -k -u "elastic:$ELASTIC_PASSWORD" -s -H "Content-Type: application/json" https://127.0.0.1:9200/_security/user/kibana_system/_password -d '{"password":"'"$KIBANA_PASSWORD"'"}' > /dev/null

    echo -e "${GREEN}[+] Configuring Kibana...${ENDCOLOR}"
    until curl -s -I http://127.0.0.1:5601 | grep -q 'HTTP/1.1 302 Found'; do sleep 10; done;
    curl -u "elastic:$ELASTIC_PASSWORD" -s 'http://127.0.0.1:5601/api/saved_objects/_import?overwrite=true' -H "kbn-xsrf: true" --form "file=@$(pwd)/kibana/kibana_dashboards.ndjson" > /dev/null

    echo -e "${GREEN}[+] Configuring Netscan...${ENDCOLOR}"
    if [ ! -f "config.cfg" ]; then
    	cp docker/config-docker.cfg.sample config.cfg
    fi
fi

echo -e "${GREEN}[+] Checking that everything is ok...${ENDCOLOR}"
if [ $(docker ps  --format '{{.Names}}' | grep netscan-setup | wc -l) -gt 0 ]
then
    echo -e "${RED}[!] Oops, something went wrong...${ENDCOLOR}"
    echo -e "${RED}    You should start investigating by looking at the \"netscan-setup\" container logs...${ENDCOLOR}"
    exit 1
else
    echo -e "${GREEN}[+] Kibana credentials: ${ENDCOLOR}${RED}${BLACK_BACKGROUND} elastic:$ELASTIC_PASSWORD ${ENDCOLOR}"
    echo -e "${GREEN}[+] Remember to change the neo4j password at http://localhost:7474/ (default: ${ENDCOLOR}${RED}${BLACK_BACKGROUND} neo4j:neo4j ${ENDCOLOR}${GREEN})${ENDCOLOR}"
    
    echo -e "${GREEN}[+] Adding an alias in your personal settings...${ENDCOLOR}"
    
    netscan_docker_command="docker run -it --rm --name netscan-tool-\$RANDOM --env-file $(pwd)/docker/docker.env --network host -v /etc/localtime:/etc/localtime:ro -v \"/:/host\" -v \"$(pwd)/:/app/\" -h netscan -e HOST_PWD=\$(pwd) -u \$(id -u \${USER}):\$(id -g \${USER}) netscan:latest"
    netscan_alias_command="alias netscan='${netscan_docker_command}'"

    #netscan_docker_server_command="docker run -it --rm --name netscan-tool-\$RANDOM --env-file $(pwd)/docker/docker.env --network \"netscan-network\" -v \"/:/host\" -v \"$(pwd)/:/app/\" -h netscan -p \"0.0.0.0:3890:3890\" -p \"0.0.0.0:8000:8000\" -p \"0.0.0.0:4450:445\" -e HOST_PWD=\$(pwd) -u \$(id -u \${USER}):\$(id -g \${USER}) netscan:latest server"
    #netscan_server_alias_command="alias netscan-server='${netscan_docker_server_command}'"
    
    if [ -f "$HOME/.zshrc" ]; then
        sed -i '/^alias netscan=/d' ~/.zshrc
        echo $netscan_alias_command >> ~/.zshrc
        #sed -i '/^alias netscan-server=/d' ~/.zshrc
        #echo $netscan_server_alias_command >> ~/.zshrc
    fi
    
    if [ -f "$HOME.bash_aliases" ]; then
        sed -i '/^alias netscan=/d' ~/.bash_aliases
        echo $netscan_alias_command >> ~/.bash_aliases
        #sed -i '/^alias netscan-server=/d' ~/.bash_aliases
        #echo $netscan_server_alias_command >> ~/.bash_aliases
    elif [ -f "$HOME/.bashrc" ]; then
        sed -i '/^alias netscan=/d' ~/.bashrc
        echo $netscan_alias_command >> ~/.bashrc
        #sed -i '/^alias netscan-server=/d' ~/.bashrc
        #echo $netscan_server_alias_command >> ~/.bashrc
    fi
    
    if [ ! -f "$HOME/.zshrc" ] && [ ! -f "$HOME.bash_aliases" ] && [ ! -f "$HOME/.bashrc" ]; then
        echo -e "${YELLOW}[!] Error. You should set the alias manually ($netscan_alias_command)${ENDCOLOR}"
    fi
    
    echo -e "${GREEN}[+] You can now use the ${ENDCOLOR}${YELLOW}${RED_BACKGROUND} netscan ${ENDCOLOR}${GREEN} command!${ENDCOLOR}"
    
    # Reload aliases
    . ~/.bashrc
fi
