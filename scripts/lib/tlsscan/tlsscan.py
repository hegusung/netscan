import socket
import subprocess
import traceback
import copy
from time import sleep
from utils.output import Output
from utils.db import DB
import dataclasses

from sslyze import *
import sslyze
from sslyze.mozilla_tls_profile.mozilla_config_checker import (
     MozillaTlsConfigurationChecker,
     ServerNotCompliantWithMozillaTlsConfiguration,
     ServerScanResultIncomplete,
)
from sslyze.mozilla_tls_profile.mozilla_config_checker import MozillaTlsConfigurationEnum
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanResult
from sslyze.scanner.models import SessionRenegotiationScanAttempt


def tlsscan_worker(target, tls_config, timeout):
    try:
         server_location = ServerNetworkLocation(hostname=target['hostname'], port=target['port'])
         request = ServerScanRequest(server_location=server_location, network_configuration=ServerNetworkConfiguration(server_location.hostname, network_timeout=timeout))
    except sslyze.errors.ServerHostnameCouldNotBeResolved:
          return

    scanner = Scanner()
    scanner.queue_scans([request])
    res = next(scanner.get_results())

    if res.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
        return

    # In some cases, session_renegotiation required a client certificate. This means sslyze won't like it and will not display the results, hack it
    test = getattr(res.scan_result, ScanCommand.SESSION_RENEGOTIATION.value)
    if test.status == ScanCommandAttemptStatusEnum.ERROR:
        result = res.scan_result

        new_result = dataclasses.replace(result, session_renegotiation=SessionRenegotiationScanAttempt(status=ScanCommandAttemptStatusEnum.COMPLETED, error_reason=None, error_trace=None, result=SessionRenegotiationScanResult(supports_secure_renegotiation=True, is_vulnerable_to_client_renegotiation_dos=False)))

        new_res = dataclasses.replace(res, scan_result=new_result)

        res = new_res

    mozilla_checker = MozillaTlsConfigurationChecker.get_default()
    try:
        if tls_config == 'old':
            mozilla_config = MozillaTlsConfigurationEnum.OLD
        elif tls_config == 'intermediate':
            mozilla_config = MozillaTlsConfigurationEnum.INTERMEDIATE
        elif tls_config == 'modern':
            mozilla_config = MozillaTlsConfigurationEnum.MODERN
        else:
            raise NotImplementedError()
        
        mozilla_checker.check_server(against_config=mozilla_config, server_scan_result=res)

        Output.success({'target': 'ssl://%s:%d' % (target['hostname'], target['port']), 'message': 'TLS: Certificate compliant with Mozilla\'s %s configuration' % tls_config}) 
    except ServerNotCompliantWithMozillaTlsConfiguration as e:
        Output.vuln({'target': 'ssl://%s:%d' % (target['hostname'], target['port']), 'message': 'TLS: Certificate not compliant with Mozilla\'s %s configuration' % tls_config}) 

        for criteria, error_description in e.issues.items():
            Output.vuln({'target': 'ssl://%s:%d' % (target['hostname'], target['port']), 'message': '  - %s: %s' % (criteria, error_description)}) 
            vuln_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'service': 'ssl',
                'url': 'ssl://%s:%d' % (target['hostname'], target['port']),
                'name': '%s: %s' % (tls_config, criteria),
                'description': error_description,
            }
            DB.insert_vulnerability(vuln_info)
    except ServerScanResultIncomplete as e:
        Output.error({'target': 'ssl://%s:%d' % (target['hostname'], target['port']), 'message': 'Scan did not run successfully: %s' % str(e)}) 




