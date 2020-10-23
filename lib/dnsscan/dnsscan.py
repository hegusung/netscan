import socket
import re
from time import sleep
import dns.resolver
import dns.zone
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
        if action[0] == 'axfr':
            Output.write({"target": target['hostname'], "message": "Starting AXFR check"})
            dnsscan.axfr()


class DNSScan:

    def __init__(self, hostname, dn_server, timeout):
        self.hostname = hostname
        self.timeout = timeout
        self.dn_server = dn_server

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
        if self.is_ip(self.hostname):
            return

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

    def axfr(self):
        if self.is_ip(self.hostname):
            return

        for ns_server in self.get_nameservers():
            Output.write({"target": ns_server['target'], "message": "Checking AXFR against nameserver %s" % ns_server['resolved']})

            # resolve nameserver IP
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            if self.dn_server != None:
                self.resolver.nameservers = [self.dn_server]
            answer = self.resolver.query(ns_server['resolved'], "A")

            for ns_ip in answer:
                axfr = dns.zone.from_xfr(dns.query.xfr(str(ns_ip), self.hostname, lifetime=self.timeout))
                if axfr == None:
                    continue

                for name, node in axfr.nodes.items():
                    name = str(name)
                    if name == "@":
                        name = self.hostname
                    else:
                        if not name.endswith('.'):
                            name = "%s.%s" % (name, self.hostname)
                    for rdataset in node.rdatasets:
                        parts = str(rdataset).split()
                        if len(parts) >= 4:
                            query_type = parts[2]
                            if not query_type in ["SOA", "NS"]:
                                if query_type in ["MX"]:
                                    if not parts[4].endswith('.'):
                                        resolved = "%s.%s" % (parts[4], self.hostname)
                                    Output.write({"target": ns_server['target'], "message": "%s %s %s" % (name, query_type, resolved)})
                                else:
                                    resolved = parts[3]
                                    Output.write({"target": ns_server['target'], "message": "%s %s %s" % (name, query_type, resolved)})
                        else:
                                Output.write({"target": ns_server['target'], "message": "%s %s %s" % (name, type(rdataset), rdataset)})

    def get_nameservers(self):
        if self.is_ip(self.hostname):
            return

        try:
            answer = self.resolver.query(self.hostname, 'NS')
            for r in answer:
                yield {"target": self.hostname, "query_type": "NS", "resolved": str(r)}
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
