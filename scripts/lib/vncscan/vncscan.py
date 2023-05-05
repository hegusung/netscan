import sys
import os.path
import impacket
from time import sleep
import socket
import traceback
import struct
from datetime import datetime

from .vnc import VNC
from .vnc_utils import run_ducky

from utils.utils import AuthFailure
from utils.output import Output
from utils.dispatch import dispatch
from utils.db import DB

def vncscan_worker(target, actions, creds, timeout):
    try:
        auth = False
        version_printed = False

        vnc = VNC(target['hostname'], target['port'], timeout)

        vnc.connect()

        version = vnc.version
        Output.write({'target': vnc.url(), 'message': '%s\t[%s]' % (version, '; '.join(vnc.supported_security_types))})
        DB.insert_port({
            'hostname': target['hostname'],
            'port': target['port'],
            'protocol': 'tcp',
            'service': 'vnc',
            'version': version,
        })

        if "None" in vnc.supported_security_types:
            # try anonymous auth
            code, _ = vnc.auth("None")
            if code == 0:
                auth = True
                Output.vuln({'target': vnc.url(), 'message': 'Authentication success without credentials'})
                vuln_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'vnc',
                    'url': vnc.url(),
                    'name': 'Anonymous connection to service',
                    'description': 'Anonymous account can connect to VNC service: %s' % vnc.url(),
                }
                DB.insert_vulnerability(vuln_info)

        elif "VNC Authentication" in vnc.supported_security_types:
            if 'password' in creds:
                code, _ = vnc.auth("VNC Authentication", password=creds['password'])
                if code == 0:
                    auth = True
                    Output.success({'target': vnc.url(), 'message': 'Authentication success with password: %s' % creds['password']})
                    cred_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'vnc',
                        'url': vnc.url(),
                        'type': 'password',
                        'username': 'N/A',
                        'password': creds['password'],
                    }
                    DB.insert_credential(cred_info)

                else:
                    Output.minor({'target': vnc.url(), 'message': 'Authentication failure with password: %s' % creds['password']})
        elif 'password' in creds:
            Output.error({'target': vnc.url(), 'message': 'No supported authentication mechanism found: %s' % vnc.supported_security_types})

        if auth:
            if 'screenshot' in actions:
                img = vnc.screenshot()
                now = datetime.now()
                screenshot_name = "vnc_%s_%d_%s.jpg" % (target['hostname'], target['port'], now.strftime('%Y%m%d_%H%M%S'))
                screenshot_path = os.path.join(os.path.dirname(sys.argv[0]),"../screenshots", screenshot_name)
                screenshot_path = os.path.abspath(screenshot_path)
                img.save(screenshot_path)
                Output.highlight({'target': vnc.url(), 'message': 'Screenshot saved at: %s' % screenshot_path})
            if 'ducky' in actions:
                run_ducky(vnc, actions['ducky']['ducky_script'])
                Output.highlight({'target': vnc.url(), 'message': 'Ducky script executed'})

        if 'bruteforce' in actions:
            if "VNC Authentication" in vnc.supported_security_types:
                if 'password_file' in actions['bruteforce'] != None:
                    Output.highlight({'target': vnc.url(), 'message': 'Starting bruteforce:'})
                    for password in open(actions['bruteforce']['password_file']):
                        password = password.strip()
                        v = VNC(target['hostname'], target['port'], timeout)
                        v.connect()
                        code, _ = v.auth("VNC Authentication", password=password)
                        if code == 0:
                            Output.success({'target': vnc.url(), 'message': 'Authentication success with password: %s' % password})
                            cred_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'vnc',
                                'url': vnc.url(),
                                'type': 'password',
                                'username': 'N/A',
                                'password': password,
                            }
                            DB.insert_credential(cred_info)

                        v.disconnect()
                        sleep(0.5)
            else:
                Output.error({'target': vnc.url(), 'message': 'Unsupported authentication mechanism for bruteforce'})
    except ConnectionRefusedError:
        pass
    except OSError as e:
        pass
    except ConnectionRefusedError as e:
        Output.write({'target': vnc.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    except Exception as e:
        Output.write({'target': vnc.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        try:
            vnc.disconnect()
        except:
            pass

