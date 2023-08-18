<p align="center">
  <img src="./images/logo.png">
  <br>
  <a href="https://twitter.com/intent/follow?screen_name=hegusung" title="Follow"><img src="https://img.shields.io/twitter/follow/hegusung?label=hegusung&style=social"></a>
  <br>
</p>

# NetScan

> Netscan is a network scanner made for large-scope pentesting. 
> It lets you scan and do your recon phase on more that 20+ protocols very quickly. All results are store in an elasticsearch database and browsable with the Kibana power.
> Scan, Filter, Exploit !

## Features

- [x] FTP scanner
- [x] MySQL scanner
- [x] MongoDB scanner
- [x] Ping scanner
- [x] Port scanner
- [x] Postgres scanner
- [x] RDP scanner
- [x] Redis scanner
- [x] Rsync scanner
- [x] RTSP scanner
- [X] SMB scanner
- [X] SSH scanner
- [X] Telnet scanner
- [X] VNC scanner
- [X] WinRM scanner
- [X] AD scanner
- [X] HTTP scanner
- [X] DNS scanner

## Screenshots

Display the global help menu
![](images/netscan-help.png)

Display a specific module help menu
![](images/netscan-help-module.png)

Run a ping scan to discover devices in the network
![](images/netscan-pingscan.png)

Run a port scan to get all opened ports with the nmap options
![](images/netscan-portscan.png)

Display the result in a way-to-cool interface!
![](images/kibana-screen.png)

## 1. Installation

### 1.0 Automagic installation (with docker)

> Run the following command and enjoy immediately..

```bash
~/netscan$> ./configure_docker.sh
```

The previous command will build and/or start all the framework docker containers used by netscan.
It will create and configure : 
* an elasticsearch container
* a kibana container
* a neo4j container

![](images/running.png)

When everything is up and running, you can use the ` netscan ` command and enjoy.

### 1.1 Manual installation (without Docker)

1. Install dependencies
  ```bash
  $> pip3 install -r requirements.txt
  ```
2. Create the configuration file
  ```bash
  $> cp config.cfg.sample config.cfg
  ```
3. If needed, deploy `Elasticsearch` and `Kibana` on your systema.

## 2. Configuration
> **Note**:  
> The docker version is already configured with default settings. You're good to go.

On your system or in the docker container, 

1. Edit the `config.cfg` file to set the name of your current pentest session under the `[Global]` section.

2. Enable elasticsearch if you want to send all your scan outputs to the database under the `[Elasticsearch]` section.

3. Configure the Kibana dashboards
   
   **Via GUI**  
     > The kibana dashboards are located at [kibana/kibana_dashboards.ndjson](kibana/kibana_dashboards.ndjson).

    - Open kibana at http://127.0.0.1:5601/
    - Go to "Management > Stack Management"
    - Go to "Kibana > Saved Objects"
    - Click on "Import"
    - Select the `kibana_dashboards.ndjson` file provided in this repo
    - Click on "Import"
  
   **Via CLI**  
   ```bash
   $> curl -X POST 'http://127.0.0.1:5601/api/saved_objects/_import?createNewCopies=true' -H "kbn-xsrf: true" --form "file=@$(pwd)/kibana/kibana_dashboards.ndjson"
   ```

  The dashboards should now be available within Kibana


## 3. Troubleshooting

<hr/>

**Problem**: Elasticsearch has not enough memory-mapped areas to run smoothly.  
**Solution** : Run the following command on you system
```bash
sudo sysctl -w vm.max_map_count=262144
```
**Doc**: [https://www.elastic.co/guide/en/elasticsearch/reference/current/_maximum_map_count_check.html](https://www.elastic.co/guide/en/elasticsearch/reference/current/_maximum_map_count_check.html)

<hr/>

**Problem**: Elastic needs at least 10% free space of your hard disk (whatever the disk size). 
**Solution** : You can disable the disk size threshold by running the following commands on you system
```bash
$> curl -X PUT -H "Content-Type: application/json" http://localhost:9200/_cluster/settings -d '{ "transient": { "cluster.routing.allocation.disk.threshold_enabled": false } }'
```

<hr/>
