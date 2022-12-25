import os.path
import json
from urllib.parse import urljoin

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

class Module:
    name = 'Actuator'
    description = 'Search for Spring Boot actuators'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        for uri in ["dump", "trace", "logfile", "shutdown", "mappings", "env", "actuator", "heapdump"]:
            response = http.get(os.path.join(target['path'], uri))

            if response['code'] == 200 and response['content-type'] == 'application/json':
                data = json.loads(response['html'])

                Output.highlight({'target': http.url(os.path.join(target['path'], uri)), 'message': 'Actuator endpoint'})

