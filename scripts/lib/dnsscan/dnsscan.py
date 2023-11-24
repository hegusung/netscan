import socket
import re
from time import sleep
import dns.resolver
import dns.zone
import tqdm

from utils.output import Output
from utils.db import DB
from utils.utils import open

ip_regex = re.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

def dnsscan_worker(target, dn_server, do_tcp, actions, timeout):
    dnsscan = DNSScan(target['hostname'], dn_server, do_tcp, timeout)

    resolved = dnsscan.resolve()

    if resolved:
        for r in resolved['resolved']:
            DB.insert_dns({
                'source': target['hostname'],
                'query_type': resolved['query_type'],
                'target': r,
            })
            Output.write({"message_type": "dns", "target": target['hostname'], "query_type": resolved["query_type"], "resolved": r})

            for action in actions:
                if action[0] == 'dc':
                    for ad_server in dnsscan.lookup_dc():
                        if ad_server['ips'] != None:
                            for ip in ad_server['ips']:
                                DB.insert_dns({
                                    'source': ad_server['hostname'],
                                    'query_type': "A",
                                    'target': ip,
                                })

                                DB.insert_port({
                                    'hostname': ip,
                                    'port': 445,
                                    'protocol': 'tcp',
                                    'service': 'smb',
                                    'service_info': {
                                        'is_dc': True,
                                        'domain': target['hostname'],
                                        'hostname': ad_server['hostname'],
                                    }
                                })


                        Output.highlight({"message_type": "dns_dc", "domain": ad_server['domain'], "hostname": ad_server["hostname"], "ips": ad_server['ips']})

    for action in actions:
        if action[0] == 'bruteforce':
            Output.highlight({"target": target['hostname'], "message": "Starting subdomain bruteforce"})
            for resolved in dnsscan.subdomain_bruteforce(action[1]):
                DB.insert_dns({
                    'source': resolved['target'],
                    'query_type': resolved['query_type'],
                    'target': resolved['resolved'],
                })
                Output.write({"message_type": "dns", "target": resolved['target'], "query_type": resolved["query_type"], "resolved": resolved['resolved']})
        if action[0] == 'axfr':
            dnsscan.axfr()


class DNSScan:

    def __init__(self, hostname, dn_server, do_tcp, timeout):
        self.hostname = hostname
        self.timeout = timeout
        self.dn_server = dn_server
        self.do_tcp = do_tcp

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        if dn_server != None:
            self.resolver.nameservers = [dn_server]

    def resolve(self):
        try:
            if self.is_ip(self.hostname):
                # self.hostname is an IP, performing reverse dns
                answer = self.resolver.query(dns.reversename.from_address(self.hostname), "PTR", tcp=self.do_tcp)
                resolved = {"query_type": "PTR", "resolved": [str(r) for r in answer]}
            else:
                # self.hostname is a hostname, performing A dns query
                answer = self.resolver.query(self.hostname, "A", tcp=self.do_tcp)
                resolved = {"query_type": "A", "resolved": [str(r) for r in answer]}
        except dns.resolver.NXDOMAIN:
            resolved = None
        except dns.resolver.NoAnswer:
            resolved = None
        except dns.resolver.NoNameservers:
            resolved = None
        except dns.exception.Timeout as e:
            Output.error(str(e))
            resolved = None

        return resolved

    def is_ip(self, ip):
        if ip_regex.match(ip):
            return True
        else:
            return False

    def lookup_dc(self):
        prepend_fqdn = ["_ldap._tcp.", "_kerberos._tcp.", "_kerberos._udp."]

        if not self.is_ip(self.hostname):

            dc_fqdn_list = []

            for prepend in prepend_fqdn:
                try:
                    for r in self.resolver.query(prepend + self.hostname, "SRV", tcp=self.do_tcp):
                        dc_fqdn_list.append(str(r).split()[-1])
                except dns.resolver.NXDOMAIN:
                    resolved = None
                except dns.resolver.NoAnswer:
                    resolved = None
                except dns.exception.Timeout as e:
                    Output.error(str(e))
                    resolved = None

            dc_fqdn_list = list(set(dc_fqdn_list))

            for dc_fqdn in dc_fqdn_list:
                try:
                    answer = self.resolver.query(dc_fqdn, "A", tcp=self.do_tcp)
                    ip_list = [str(r) for r in answer]
                except dns.resolver.NXDOMAIN:
                    ip_list = None
                except dns.resolver.NoAnswer:
                    ip_list = None
                except dns.exception.Timeout as e:
                    Output.error(str(e))
                    ip_list = None

                yield {"domain": self.hostname, "hostname": dc_fqdn, "ips": ip_list}

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
                answer = self.resolver.query(subdomain, "A", tcp=self.do_tcp)
                for r in answer:
                    yield {"target": subdomain, "query_type": "A", "resolved": str(r)}
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except dns.exception.Timeout as e:
                Output.error(str(e))

        f.close()

    def axfr(self):
        if self.is_ip(self.hostname):
            return

        # resolve nameserver IP
        #resolver = dns.resolver.Resolver()
        #resolver.timeout = self.timeout
        if self.dn_server != None:
            self.resolver.nameservers = [self.dn_server]
        answer = self.resolver.query(self.hostname, "NS", tcp=self.do_tcp)

        for ns_dns in answer:
            answer = self.resolver.query(str(ns_dns), "A", tcp=self.do_tcp)
            ns_ip = list(answer)[0]

            Output.highlight({"target": self.hostname, "message": "Checking AXFR against nameserver %s (%s)" % (ns_dns, ns_ip)})

            try:
                axfr = dns.zone.from_xfr(dns.query.xfr(str(ns_ip), self.hostname, lifetime=self.timeout))
                if axfr == None:
                    Output.minor({"target": str(ns_dns), "message": "AXFR transfer failure"})
                    continue
            except dns.exception.Timeout:
                continue
            except dns.xfr.TransferError:
                Output.minor({"target": str(ns_dns), "message": "AXFR transfer failure"})
                continue

            vuln_info = {
                'hostname': str(ns_ip),
                'port': 53,
                'service': 'dns',
                'url': 'dns://%s:%d' % (str(ns_ip), 53),
                'name': 'Zone transfer',
                'description': 'Successful zone transfer (AXFR) from domain: %s' % self.hostname
            }
            DB.insert_vulnerability(vuln_info)

            Output.vuln({'target': 'dns://%s:%d' % (str(ns_ip), 53), 'message': 'Successful zone transfer (AXFR) from domain: %s' % self.hostname})

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
                                if query_type in ['MX']:
                                    DB.insert_dns({
                                        'source': str(name),
                                        'query_type': str(query_type),
                                        'target': str(resolved),
                                    })
                            else:
                                resolved = parts[3]
                                Output.write({"target": ns_server['target'], "message": "%s %s %s" % (name, query_type, resolved)})
                                if query_type in ['A']:
                                    DB.insert_dns({
                                        'source': str(name),
                                        'query_type': str(query_type),
                                        'target': str(resolved),
                                    })
                    else:
                        Output.write({"target": ns_server['target'], "message": "%s %s %s" % (name, type(rdataset), rdataset)})


    def get_nameservers(self):
        if self.is_ip(self.hostname):
            return

        try:
            answer = self.resolver.query(self.hostname, 'NS', tcp=self.do_tcp)
            for r in answer:
                yield {"target": self.hostname, "query_type": "NS", "resolved": str(r)}
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.exception.Timeout as e:
            Output.error(str(e))
