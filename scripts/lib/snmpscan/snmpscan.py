import socket
import subprocess
import traceback
from time import sleep
from utils.output import Output
from utils.db import DB

#from pysnmp.entity.rfc3413.oneliner import cmdgen
#import pysnmp
#from pysnmp.hlapi import *

# PySNMP upgrade...
import asyncio

from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,      # use mpModel=0 (v1) or 1 (v2c)
    UsmUserData,        # for v3
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    next_cmd,
    walk_cmd,
)
from pysnmp.hlapi.v3arch.asyncio import UsmUserData
import pysnmp.error
import pysnmp.proto.rfc1905

class SNMPTimeout(Exception):
    pass
class SNMPError(Exception):
    pass
class SNMPAuthFailure(Exception):
    pass

def _run_in_thread(coro):
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    if loop.is_running():
        new_loop = asyncio.new_event_loop()
        try:
            return new_loop.run_until_complete(coro)
        finally:
            new_loop.close()
    else:
        return loop.run_until_complete(coro)

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
            'host': target['hostname'],
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
                'host': target['hostname'],
                'port': target['port'],
                'service': 'snmp',
                'url': snmp.url(),
                'type': 'password',
                'username': 'N/A',
                'password': community,
                '_secret_kind': 'community',
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
                                'host': target['hostname'],
                                'port': target['port'],
                                'snmp_key': res[0],
                                'snmp_type': res[1],
                                'snmp_value': res[2],
                            })
                    else:
                        raise NotImplementedError("SNMPv2 only")
            except SNMPTimeout as e:
                pass

class SNMP:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.sock = None


    def url(self):
        return f"snmp://{self.hostname}:{self.port}"

    # ---------- public sync methods ----------
    def request_v2(self, community='public', oid='1.3.6.1.2.1.1.1'):
        return _run_in_thread(self._request_v2_async(community, oid))

    def request_v3_noauth(self):
        return _run_in_thread(self._request_v3_noauth_async())

    # ---------- async implementations ----------
    async def _mk_transport(self):
        # timeout is seconds; you previously divided by 6 to match older behavior
        return await UdpTransportTarget.create(
            (self.hostname, self.port),
            timeout=self.timeout / 6.0,
            retries=0,
        )

    async def _request_v2_async(self, community, oid):
        engine = SnmpEngine()
        try:
            transport = await UdpTransportTarget.create(
                (self.hostname, self.port),
                timeout=self.timeout / 6.0,
                retries=0,
            )
            ctx = ContextData()

            results = []
            # walk_cmd yields multiple responses (async generator)
            walker = walk_cmd(
                engine,
                CommunityData(community, mpModel=1),
                transport,
                ctx,
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
            )
            try:
                async for (err_ind, err_stat, err_idx, var_binds) in walker:
                    if err_ind:
                        s = str(err_ind)
                        if "No SNMP response received before timeout" in s:
                            raise SNMPTimeout(err_ind)
                        raise SNMPError(f"{err_stat}: {err_ind}")
                    if err_stat:
                        raise SNMPError(f"{int(err_stat)}: {err_stat.prettyPrint()}")

                    for vb in var_binds:
                        if isinstance(vb[1], pysnmp.proto.rfc1905.EndOfMibView):
                            continue
                        results.append([
                            vb[0].prettyPrint(),
                            vb[1].__class__.__name__,
                            vb[1].prettyPrint()
                        ])
            finally:
                await walker.aclose()
            return results
        finally:
            engine.closeDispatcher()

    async def _request_v3_noauth_async(self):
        engine = SnmpEngine()
        try:
            transport = await UdpTransportTarget.create(
                (self.hostname, self.port),
                timeout=self.timeout / 6.0,
                retries=0,
            )
            err_ind, err_stat, err_idx, var_binds = await get_cmd(
                engine,
                UsmUserData('user-none-none'),
                transport,
                ContextData(),
                ObjectType(ObjectIdentity('IF-MIB', 'ifInOctets', 1)),
            )
        finally:
            engine.closeDispatcher()
        if err_ind:
            s = str(err_ind)
            if "No SNMP response received before timeout" in s:
                raise SNMPTimeout(err_ind)
            if "Unknown USM user" in s:
                raise SNMPAuthFailure(err_ind)
            raise SNMPError(f"{err_stat}: {err_ind}")
        if err_stat:
            raise SNMPError(f"{int(err_stat)}: {err_stat.prettyPrint()}")
        return True
    

