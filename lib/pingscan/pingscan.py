import os.path
import re
import subprocess
import traceback
from time import sleep
from utils.output import Output
from utils.db import DB

ttl_pattern = re.compile("^\d+.+: icmp_seq=\d+ ttl=(\d+) \S+=\S+\s+ms.*$")
rtt_pattern = re.compile("^rtt\s+min/avg/max/mdev\s+=\s+(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)\s+ms.*$")

def pingscan_worker(target, timeout):
    try:
        pingscan = PingScan(target['hostname'], timeout)

        is_up, rtt, os = pingscan.check_up()

        if is_up:
            Output.write({'target': '%s' % target['hostname'], 'message': "Up => %.4f ms (%s)" % (rtt, os)})

            DB.insert_ip({
                'hostname': target['hostname'],
                'rtt': rtt,
            })
    except Exception as e:
        raise e

class PingScan:

    def __init__(self, hostname, timeout):
        self.hostname = hostname
        self.timeout = timeout

    def check_up(self):

        process = subprocess.Popen("ping -c 3 -i 0.2 %s -w %d" % (self.hostname, self.timeout), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process_output, _ = process.communicate()
        process.wait()
        process_returncode = process.returncode

        if process_returncode == 0:
            rtt = None
            os = 'Unknown'

            for line in process_output.decode().split('\n'):
                m = ttl_pattern.match(line)
                if m:
                    if int(m.group(1)) == 64:
                        os = 'Linux?'
                    elif int(m.group(1)) == 128:
                        os = 'Windows?'
                    elif int(m.group(1)) == 255:
                        os = 'AIX/FreeBSD?'
                    else:
                        os = 'Unknown (ttl=%s)' % m.group(1)

                m = rtt_pattern.match(line)
                if m:
                    rtt = float(m.group(2))
                    break

            return True, rtt, os

        return False, None, None
