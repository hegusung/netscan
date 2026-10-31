import socket
import time
import subprocess
import traceback
import copy
from time import sleep
from utils.output import Output
from utils.db import DB
import dataclasses

from sslyze import *
import sslyze
try:
    # SSLyze < 6.3
    from sslyze.mozilla_tls_profile.mozilla_config_checker import (
         MozillaTlsConfigurationChecker,
         ServerNotCompliantWithMozillaTlsConfiguration,
         ServerScanResultIncomplete,
    )
    from sslyze.mozilla_tls_profile.mozilla_config_checker import MozillaTlsConfigurationEnum

    def check_server_against_mozilla_config(server_scan_result, profile_name):
        mozilla_config = getattr(MozillaTlsConfigurationEnum, profile_name.upper())
        MozillaTlsConfigurationChecker.get_default().check_server(
            against_config=mozilla_config,
            server_scan_result=server_scan_result,
        )
except ModuleNotFoundError:
    # SSLyze >= 6.3 renamed and simplified the Mozilla profile API.
    from sslyze.mozilla_tls_profile.tls_config_checker import (
        MozillaTlsConfiguration,
        ServerNotCompliantWithTlsConfiguration as ServerNotCompliantWithMozillaTlsConfiguration,
        ServerScanResultIncomplete,
        TlsConfigurationEnum,
        check_server_against_tls_configuration,
    )

    def check_server_against_mozilla_config(server_scan_result, profile_name):
        mozilla_config = MozillaTlsConfiguration.get(
            getattr(TlsConfigurationEnum, "MOZILLA_%s" % profile_name.upper())
        )
        check_server_against_tls_configuration(server_scan_result, mozilla_config)
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanResult
from sslyze.scanner.models import SessionRenegotiationScanAttempt


def tlsscan_worker(target, tls_config, timeout):

    retry = 0
    while True:
        try:
             server_location = ServerNetworkLocation(hostname=target['hostname'], port=target['port'])
             request = ServerScanRequest(server_location=server_location, network_configuration=ServerNetworkConfiguration(server_location.hostname, network_timeout=timeout))
        except sslyze.errors.ServerHostnameCouldNotBeResolved:
              Output.error({'target': 'ssl://%s:%d' % (target['hostname'], target['port']), 'message': 'Not resolved'}) 

              return

        scanner = Scanner()
        scanner.queue_scans([request])
        res = next(scanner.get_results())

        if res.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            Output.error({'target': 'ssl://%s:%d' % (target['hostname'], target['port']), 'message': 'No conn'}) 
            return

        # In some cases, session_renegotiation required a client certificate. This means sslyze won't like it and will not display the results, hack it
        test = getattr(res.scan_result, ScanCommand.SESSION_RENEGOTIATION.value)
        if test.status == ScanCommandAttemptStatusEnum.ERROR:
            result = res.scan_result

            new_result = dataclasses.replace(result, session_renegotiation=SessionRenegotiationScanAttempt(status=ScanCommandAttemptStatusEnum.COMPLETED, error_reason=None, error_trace=None, result=SessionRenegotiationScanResult(supports_secure_renegotiation=True, is_vulnerable_to_client_renegotiation_dos=False)))

            new_res = dataclasses.replace(res, scan_result=new_result)

            res = new_res

        if res.scan_result.certificate_info.result != None:
            certificate_domain = res.scan_result.certificate_info.result.hostname_used_for_server_name_indication
        else:
            certificate_domain = "<No domain>"

        try:
            if tls_config not in ('old', 'intermediate', 'modern'):
                raise NotImplementedError()

            check_server_against_mozilla_config(res, tls_config)

            Output.success({'target': 'ssl://%s:%d' % (target['hostname'], target['port']), 'message': '%s\t\t\tTLS: Certificate compliant with Mozilla\'s %s configuration' % (certificate_domain, tls_config)}) 
        except ServerNotCompliantWithMozillaTlsConfiguration as e:
            Output.vuln({'target': 'ssl://%s:%d' % (target['hostname'], target['port']), 'message': '%s\t\t\tTLS: Certificate not compliant with Mozilla\'s %s configuration' % (certificate_domain, tls_config)}) 

            for criteria, error_description in e.issues.items():
                Output.vuln({'target': 'ssl://%s:%d' % (target['hostname'], target['port']), 'message': '  - %s: %s' % (criteria, error_description)}) 
                vuln_info = {
                    'host': target['hostname'],
                    'port': target['port'],
                    'service': 'ssl',
                    'url': 'ssl://%s:%d' % (target['hostname'], target['port']),
                    'name': '%s: %s' % (tls_config, criteria),
                    'description': error_description,
                }
                DB.insert_vulnerability(vuln_info)
        except ServerScanResultIncomplete as e:

            if retry < 3:
                retry += 1
                time.sleep(1)
                continue
            else:
                Output.error({'target': 'ssl://%s:%d' % (target['hostname'], target['port']), 'message': 'Scan did not run successfully: %s' % str(e)}) 

        break




