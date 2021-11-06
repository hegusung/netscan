# NetScan

Network scanner made for large-scope pentesting

## Install

### Installing netscan

1. Create the configuration file
```
cp config.cfg.sample config.cfg
```

2. Edit it to set the name of your current pentest under "Global => session"

3. Enable elasticsearch if you want to send all your scan outputs to the database.

### Installing the database and dashboards

1. Install Elasticsearch and Kibana

2. Import the kibana dashboards in located at "kibana/kibana_dashboards.ndjson"

 - Open kibana at http://127.0.0.1:5601/
 - Go to "Management > Stack Management"
 - Go to "Kibana > Saved Objects"
 - Click on "Import"
 - Select the kibana_dashboards.ndjson file provided
 - Click on "Import"

3. The dashboards should now be available within Kibana

