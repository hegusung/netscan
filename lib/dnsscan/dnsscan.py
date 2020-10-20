import socket
import re
from time import sleep
import dns.resolver

from utils.output import Output

ip_regex = re.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

def dnsscan_worker(target, dn_server, timeout):
    dnsscan = DNSScan(target['hostname'], dn_server, timeout)

    resolved = dnsscan.resolve()

    if resolved:
        for r in resolved['resolved']:
            Output.write({"message_type": "dns", "target": target['hostname'], "query_type": resolved["query_type"], "resolved": r})

class DNSScan:

    def __init__(self, hostname, dn_server, timeout):
        self.hostname = hostname
        self.timeout = timeout

        self.resolver = dns.resolver.Resolver() 
        self.resolver.timeout = timeout
        if dn_server != None:
            self.resolver.nameservers = [dn_server]

    def resolve(self):
        try:
            if self.is_ip(self.hostname):
                # self.hostname is an IP, performing reverse dns
                answer = self.resolver.query(self.hostname, "PTR")
                resolved = {"query_type": "PTR", "resolved": [str(r) for r in answer]}
            else:
                # self.hostname is a hostname, performing A dns query
                answer = self.resolver.query(self.hostname, "A")
                resolved = {"query_type": "A", "resolved": [str(r) for r in answer]}
        except dns.resolver.NXDOMAIN:
            resolved = None

        return resolved

    def is_ip(self, ip):
        if ip_regex.match(ip):
            return True
        else:
            return False


