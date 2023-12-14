import os.path
from urllib.parse import urljoin
from ctypes import *
import socket
import struct
import logging
import traceback

import dns.resolver
import dns.update
import dns.query
import dns.rcode
from dns.exception import Timeout
import random
from uuid import uuid4
from ipaddress import IPv4Network, IPv4Address

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.smbscan.smb import SMBScan

# source: https://github.com/almandin/krbjack/blob/main/krbjack/krbjacker.py

class Module:
    name = 'DNSUpdate'
    description = 'Check if the ZONE_UPDATE_INSECURE parameter is enabled [no authentication]'

    def run(self, target, target_domain, creds, args, timeout):

        if len(args) != 1:
            Output.error({'target': 'ldap://%s' % (target['hostname'],), 'message': '[%s] Requires 1 arg: -m dnsupdate <zone>' % self.name})
            return

        Output.minor({'target': 'zone://%s' % (args[0],), 'message': '[%s] Running module...' % self.name})

        try:
            resolver = dns.resolver.Resolver()
            answer = resolver.query(args[0], "NS")

            for ns_dns in answer:
                answer = resolver.query(str(ns_dns), "A")

                ns_ip = str(list(answer)[0])
            
                Output.minor({'target': 'zone://%s' % (args[0],), 'message': '[%s] Checking name server %s' % (self.name, ns_ip)})

                vulnerable = check(args[0], ns_ip)

                if vulnerable:
                    Output.vuln({'target': 'dns://%s' % (ns_ip,), 'message': '[%s] Active Directory DNS parameter ZONE_UPDATE_INSECURE is enabled, use KRBJack to exploit' % self.name})

                    vuln_info = {
                        'hostname': ns_ip,
                        'port': 53,
                        'service': 'dns',
                        'url': 'dns://%s' % (ns_ip,),
                        'name': 'Active Directory parameter ZONE_UPDATE_INSECURE is enabled',
                        'description': 'Server dns://%s has parameter ZONE_UPDATE_INSECURE is enabled, use KRBJack to exploit' % (ns_ip,),
                    }
                    DB.insert_vulnerability(vuln_info)
        except dns.resolver.NXDOMAIN as e:
            Output.error({'target': 'zone://%s' % (args[0],), 'message': "%s, maybe configure /etc/resolv.conf ?" % str(e)})

def check(zone, ns_ip):
        # to check, we try to add a random record and see if it works
        # Generation of a random RFC1918 private IPv4 address
        networks = [
            IPv4Network("10.0.0.0/8"), IPv4Network("192.168.0.0/16"), IPv4Network("172.16.0.0/12")
        ]
        network = random.choice(networks)
        name = str(uuid4())
        ip = IPv4Address(
            random.randrange(
                int(network.network_address) + 1, int(network.broadcast_address) - 1
            )
        )
        try:
            response = add_dns_record(zone, ns_ip, name, str(ip))
            if response == dns.rcode.NOERROR:
                del_dns_record(zone, ns_ip, name)
                return True
            else:
                return False
        except Timeout:
            return False
        except OSError:
            return False


# Adds a single record A for this (name, ip)
def add_dns_record(zone, ns_ip, record_name, ip):
    add = dns.update.Update(f"{zone}.")
    add.add(record_name, 300, 'A', ip)
    response = dns.query.tcp(add, ns_ip, timeout=10)
    return response.rcode()

# Removes all records with the given name
def del_dns_record(zone, ns_ip, record_name):
    delete = dns.update.Update(f"{zone}.")
    delete.delete(record_name)
    response = dns.query.tcp(delete, ns_ip, timeout=10)
    return response.rcode()
