import sys
import os.path
import impacket
from time import sleep
import socket
import traceback
import struct
from datetime import datetime

from .rtsp import RTSP

from utils.utils import AuthFailure
from utils.output import Output
from utils.dispatch import dispatch
from utils.db import DB

RTSP_URL_FILE = "lib/rtspscan/rtsp-urls.txt"

import os
os.environ['OPENCV_FFMPEG_CAPTURE_OPTIONS'] = 'rtsp_transport;udp'

def rtspscan_worker(target, actions, creds, timeout):
    try:
        auth = False
        version_printed = False

        rtsp = RTSP(target['hostname'], target['port'], timeout)
        
        status_code, headers = rtsp.connect('/')

        if status_code:
            Output.write({'target': rtsp.url(""), 'message': 'RTSP protocol'})
            DB.insert_port({
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'rtsp',
            })

            discovered_uris = {}
            screenshot_taken = False

            # Start uri discovery
            f = open(RTSP_URL_FILE)
            for line in f:
                line = line.strip()

                if len(line) == 0:
                    continue
                if line.startswith('#'):
                    continue

                status_code, headers = rtsp.connect(line)

                if status_code != 404 and status_code != None:
                    discovered_uris[line] = status_code

                    if status_code == 200:
                        Output.write({'target': rtsp.url(line), 'message': 'Video feed'})

                        if not screenshot_taken:
                            now = datetime.now()
                            screenshot_name = "rtsp_%s_%d_%s_%s.jpg" % (target['hostname'], target['port'], line.replace('/', '_'), now.strftime('%Y%m%d_%H%M%S'))
                            screenshot_path = os.path.join(os.path.dirname(sys.argv[0]),"../screenshots", screenshot_name)
                            screenshot_path = os.path.abspath(screenshot_path)

                            success = rtsp.screenshot(line, screenshot_path)

                            if success:
                                Output.write({'target': rtsp.url(line), 'message': 'Screenshot taken at %s' % screenshot_path})
                            screenshot_taken = True
                    elif status_code == 401:
                        Output.write({'target': rtsp.url(line), 'message': 'Authenticated video feed'})
                    else:
                        Output.write({'target': rtsp.url(line), 'message': 'Video feed (Unknown status: %d)' % status_code})

            f.close()

            #print(discovered_uris)

    except Exception as e:
        Output.write({'target': rtsp.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        try:
            rtsp.disconnect()
        except:
            pass

