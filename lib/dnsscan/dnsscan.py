import socket
import re
from time import sleep
import dns.resolver
import tqdm

from utils.output import Output

ip_regex = re.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

def dnsscan_worker(target, dn_server, actions, timeout):
    dnsscan = DNSScan(target['hostname'], dn_server, timeout)

    resolved = dnsscan.resolve()

    if resolved:
        for r in resolved['resolved']:
            Output.write({"message_type": "dns", "target": target['hostname'], "query_type": resolved["query_type"], "resolved": r})

    for action in actions:
        if action[0] == 'bruteforce':
            Output.write({"target": target['hostname'], "message": "Starting subdomain bruteforce"})
            for resolved in dnsscan.subdomain_bruteforce(action[1]):
                Output.write({"message_type": "dns", "target": resolved['target'], "query_type": resolved["query_type"], "resolved": resolved['resolved']})


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
        except dns.resolver.NoAnswer:
            resolved = None

        return resolved

    def is_ip(self, ip):
        if ip_regex.match(ip):
            return True
        else:
            return False

    def subdomain_bruteforce(self, subdomain_file):
        f = open(subdomain_file)
        nb_lines = sum(1 for _ in f)
        f.close()
        f = open(subdomain_file)
        for subdomain in tqdm.tqdm(f, total=nb_lines, mininterval=1, desc=self.hostname):
            subdomain = subdomain.strip()
            subdomain = "%s.%s" % (subdomain, self.hostname)

            try:
                answer = self.resolver.query(subdomain, "A")
                for r in answer:
                    yield {"target": subdomain, "query_type": "A", "resolved": str(r)}
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass

        f.close()
