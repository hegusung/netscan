#!/bin/bash

docker ps -a --filter "name=netscan" --format '{{.Names}}' | grep netscan-tool > /dev/null

if [ $? -eq 0 ]
then
    echo -e "\e[32m[+] Containers are already built...\e[0m"

    docker-compose start
else 
    export $(grep -v '^#' .env | xargs -d '\n')

    echo -e "\e[32m[+] Configuring system to run dockers...\e[0m"
    sudo sysctl -w vm.max_map_count=262144 > /dev/null

    echo -e "\e[32m[+] Starting docker containers...\e[0m"
    docker-compose up --remove-orphans --build -d  > /dev/null

    echo -e "\e[32m[+] Waiting 60 seconds for containers initialization...\e[0m"
    sleep 60

    # Retreiving elastic certificate
    #docker cp netscan-elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt /tmp

    #echo -e "\e[32m[+] Configuring ElasticSearch...\e[0m"
    #curl -s -X PUT -H "Content-Type: application/json" http://localhost:9200/_all/_settings -d '{"index.blocks.read_only_allow_delete": null}' > /dev/null
    #curl -s -X PUT -H "Content-Type: application/json" http://localhost:9200/_cluster/settings -d '{ "transient": { "cluster.routing.allocation.disk.threshold_enabled": false } }' > /dev/null
    #sleep 5

    echo -e "\e[32m[+] Configuring Kibana...\e[0m"
    curl -u elastic:${ELASTIC_PASSWORD} -s -X POST 'http://127.0.0.1:5601/api/saved_objects/_import?createNewCopies=true' -H "kbn-xsrf: true" --form "file=@$(pwd)/kibana/kibana_dashboards.ndjson" > /dev/null

    #rm /tmp/http_ca.crt

    echo -e "\e[32m[+] Elasticsearch password:\e[0m"
    echo ${ELASTIC_PASSWORD}
fi

echo -e "\e[32m[+] Remember to change the neo4j password: http://localhost:7474/ (default: neo4j:neo4j)\e[0m"

echo -e "\e[32m[+] Entering into Netscan container...Enjoy !\e[0m"
docker exec -it netscan-tool bash
