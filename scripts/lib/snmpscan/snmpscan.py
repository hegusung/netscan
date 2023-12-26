import socket
import subprocess
import traceback
import copy
from time import sleep
from utils.output import Output
from utils.dispatch import dispatch
from utils.db import DB

#from pysnmp.entity.rfc3413.oneliner import cmdgen
import pysnmp
from pysnmp.hlapi import *

class SNMPTimeout(Exception):
    pass
class SNMPError(Exception):
    pass
class SNMPAuthFailure(Exception):
    pass

def snmpscan_worker(target, actions, creds, timeout):
    snmp = SNMP(target['hostname'], target['port'], timeout)

    protocols = []

    try:
        if 'community' in creds:
            community = creds['community']
        else:
            community = 'public'

        snmp.request_v2(community=community)

        protocols.append('SNMPv2')
    except SNMPTimeout as e:
        # Note: if wrong community, server won't answer... 
        pass
    except SNMPError as e:
        protocols.append('SNMPv2')
        Output.minor({'target': snmp.url(), 'message': str(e)})
    except pysnmp.error.PySnmpError:
        pass
    except Exception as e:
        Output.error({'target': snmp.url(), 'message': "%s: %s\n%s" % (type(e), str(e), traceback.format_exc())})

    if len(protocols) == 0: # Try snmpv3
        try:
            snmp.request_v3_noauth()

            protocols.append('SNMPv3')
        except SNMPTimeout as e:
            pass
        except SNMPAuthFailure as e:
            protocols.append('SNMPv3')
        except SNMPError as e:
            protocols.append('SNMPv3')
            Output.minor({'target': snmp.url(), 'message': str(e)})
        except pysnmp.error.PySnmpError:
            pass
        except Exception as e:
            Output.error({'target': snmp.url(), 'message': "%s: %s\n%s" % (type(e), str(e), traceback.format_exc())})

    if len(protocols) != 0:
        Output.write({'target': snmp.url(), 'message': 'SNMP Service'})
        DB.insert_port({
            'hostname': target['hostname'],
            'port': target['port'],
            'protocol': 'udp',
            'service': 'snmp',
        })

        # Check Auth
        auth = None
        if 'SNMPv2' in protocols:
            auth = ('SNMPv2', community)
            Output.success({'target': snmp.url(), 'message': '(SNMPv2) Authentication success with community string: %s' % community})

            cred_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'service': 'snmp',
                'url': snmp.url(),
                'type': 'password',
                'username': 'N/A',
                'password': community,
            }
            DB.insert_credential(cred_info)

        # Query
        if actions and auth:
            try:
                if 'oid' in actions:
                    if actions['oid'] == 'all':
                        oid = '1.3.6.1.2'
                    else:
                        oid = actions['oid']

                    if auth[0] == 'SNMPv2':
                        result = snmp.request_v2(community=auth[1], oid=oid)
                        for res in result:
                            Output.highlight({'target': snmp.url(), 'message': '%s: (%s) %s' % tuple(res)})

                            DB.insert_snmp_entry({
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'snmp_key': res[0],
                                'snmp_type': res[1],
                                'snmp_value': res[2],
                            })
                    else:
                        raise NotImplementedError("SNMPv2 only")
            except SNMPTimeout as e:
                pass

        if actions:
            if 'bruteforce' in actions:
                if 'community_file' in actions['bruteforce'] != None:
                    Output.highlight({'target': snmp.url(), 'message': 'Starting bruteforce:'})

                    community_file = actions['bruteforce']['community_file']
                    bruteforce_workers = actions['bruteforce']['workers']

                    gen = bruteforce_v2_generator(target, community_file)
                    gen_size = bruteforce_v2_generator_count(target, community_file)

                    args = (timeout,)
                    dispatch(gen, gen_size, bruteforce_v2_worker, args, workers=bruteforce_workers, process=False, pg_name=target['hostname'])

def bruteforce_v2_generator(target, community_file):
    community_f = open(community_file)
    for c in community_f:
        c = c.strip()
        if len(c) == 0:
            continue

        t = copy.copy(target)
        t['b_community'] = c

        yield t
    community_f.close()

def bruteforce_v2_generator_count(target, community_file):
    count = 0

    community_f = open(community_file)
    for c in community_f:
        c = c.strip()
        if len(c) == 0:
            continue

        count += 1
    community_f.close()

    return count

def bruteforce_v2_worker(target, timeout):
    community = target['b_community']
    try:
        snmp = SNMP(target['hostname'], target['port'], timeout)
        snmp.request_v2(community=community)

        Output.success({'target': snmp.url(), 'message': '(SNMPv2) Authentication success with community: %s' % community})
        cred_info = {
            'hostname': target['hostname'],
            'port': target['port'],
            'service': 'snmp',
            'url': snmp.url(),
            'type': 'password',
            'username': 'N/A',
            'password': community,
        }
        DB.insert_credential(cred_info)
    except SNMPTimeout as e:
        # Note: if wrong community, server won't answer... 
        pass
    except SNMPError as e:
        Output.minor({'target': snmp.url(), 'message': str(e)})
    except pysnmp.error.PySnmpError:
        pass
    except Exception as e:
        Output.error({'target': snmp.url(), 'message': "%s: %s\n%s" % (type(e), str(e), traceback.format_exc())})

class SNMP:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.sock = None

    def url(self):
        return 'snmp://%s:%d' % (self.hostname, self.port)

    def request_v2(self, community='public', oid='1.3.6.1.2.1.1.1'):

        oid_list = [ObjectType(ObjectIdentity(item)) for item in oid.split(',')]
        
        result = []
        for (error_indication, error_status, error_index, var_binds) in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((self.hostname, self.port), timeout=self.timeout/6.0), # 10 = 60 sec timeout... so divide by 6
                ContextData(),
                *oid_list,
                lexicographicMode=False):

            if error_indication or error_status:
                if str(error_indication) == "No SNMP response received before timeout": # timeout
                    raise SNMPTimeout(error_indication)
                else:
                    raise SNMPError("%d: %s" % (error_status, error_indication))

            for var_bind in var_binds:
                if type(var_bind[1]) == pysnmp.proto.rfc1905.EndOfMibView:
                    continue

                res = [x.prettyPrint() for x in var_bind]

                result.append([var_bind[0].prettyPrint(), var_bind[1].__class__.__name__, var_bind[1].prettyPrint()])

        return result

    def request_v3_noauth(self):

        iterator = getCmd(
            SnmpEngine(),
            UsmUserData('user-none-none'),
            UdpTransportTarget((self.hostname, self.port), timeout=self.timeout/6.0), # 10 = 60sec timeout....
            ContextData(),
            ObjectType(ObjectIdentity('IF-MIB', 'ifInOctets', 1))
        )

        error_indication, error_status, error_index, var_binds = next(iterator)

        if error_indication or error_status:
            if str(error_indication) == "No SNMP response received before timeout": # timeout
                raise SNMPTimeout(error_indication)
            elif str(error_indication) == "Unknown USM user": # Auth error
                raise SNMPAuthFailure(error_indication)
            else:
                raise SNMPError("%d: %s" % (error_status, error_indication))



