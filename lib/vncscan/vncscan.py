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

def vncscan_worker(target, actions, creds, timeout):
    try:
        auth = False
        version_printed = False

        vnc = VNC(target['hostname'], target['port'], timeout)

        vnc.connect()

        version = vnc.version
        Output.write({'target': vnc.url(), 'message': version})

        if "None" in vnc.supported_security_types:
            # try anonymous auth
            code, _ = vnc.auth("None")
            if code == 0:
                auth = True
                Output.write({'target': vnc.url(), 'message': 'Authentication success without crdentials'})
        elif "VNC Authentication" in vnc.supported_security_types:
            if 'password' in creds:
                code, _ = vnc.auth("VNC Authentication", password=creds['password'])
                if code == 0:
                    auth = True
                    Output.write({'target': vnc.url(), 'message': 'Authentication success with password: %s' % creds['password']})
                else:
                    Output.write({'target': vnc.url(), 'message': 'Authentication failure with password: %s' % creds['password']})
        elif 'password' in creds:
            Output.write({'target': vnc.url(), 'message': 'No supported authentication mechanism found: %s' % vnc.supported_security_types})

        if auth:
            if 'screenshot' in actions:
                img = vnc.screenshot()
                now = datetime.now()
                screenshot_name = "vnc_%s_%d_%s.jpg" % (target['hostname'], target['port'], now.strftime('%Y%m%d_%H%M%S'))
                screenshot_path = os.path.join(os.path.dirname(sys.argv[0]),"screenshots", screenshot_name)
                screenshot_path = os.path.abspath(screenshot_path)
                img.save(screenshot_path)
                Output.write({'target': vnc.url(), 'message': 'Screenshot saved at: %s' % screenshot_path})
            if 'ducky' in actions:
                run_ducky(vnc, actions['ducky']['ducky_script'])
                Output.write({'target': vnc.url(), 'message': 'Ducky script executed'})

        if 'bruteforce' in actions:
            if "VNC Authentication" in vnc.supported_security_types:
                if 'password_file' in actions['bruteforce'] != None:
                    Output.write({'target': vnc.url(), 'message': 'Starting bruteforce:'})
                    for password in open(actions['bruteforce']['password_file']):
                        password = password.strip()
                        v = VNC(target['hostname'], target['port'], timeout)
                        v.connect()
                        code, _ = v.auth("VNC Authentication", password=password)
                        if code == 0:
                            Output.write({'target': vnc.url(), 'message': 'Authentication success with password: %s' % password})
                        v.disconnect()
                        sleep(0.5)
            else:
                Output.write({'target': vnc.url(), 'message': 'Unsupported authentication mechanism for bruteforce'})

    except OSError as e:
        Output.write({'target': vnc.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    except ConnectionRefusedError as e:
        Output.write({'target': vnc.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    except Exception as e:
        Output.write({'target': vnc.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        vnc.disconnect()

