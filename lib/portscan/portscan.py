import socket
import tempfile
import os.path
import subprocess
import traceback
from time import sleep
from operator import itemgetter
from utils.output import Output
import xml.etree.ElementTree as ET

nmap_bin = "nmap"

def portscan_worker(target, service_scan, timeout):
    portscan = PortScan(target['hostname'], target['port'], timeout)

    is_open = portscan.check_open()

    if is_open:
        if service_scan:
            for output in portscan.service_check():
                output["message_type"] = "port_service"
                output["target"] = "%s:%d" % (target['hostname'], target['port'])
                Output.write(output)
        else:
            Output.write({"target": "%s:%d" % (target['hostname'], target['port']), "message": "open"})


class PortScan:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

    def check_open(self):

        sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        result = sock.connect_ex((self.hostname, self.port))

        sock.close()

        if result == 0:
            return True
        else:
            return False

    def service_check(self):

        try:
            xml_output = os.path.join(tempfile.mkdtemp(), next(tempfile._get_candidate_names()))

            nmap_command = "%s -sV -Pn -T3 -p %d %s -oX %s" % (nmap_bin, self.port, self.hostname, xml_output)

            proc = subprocess.Popen(nmap_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.communicate()
            for output in self._parse_nmap_xml(xml_output):
                yield output
        except Exception as e:
            print("%s: %s\n%s" % (type(e), e, traceback.format_exc()))

        try:
            os.remove(xml_output)
        except FileNotFoundError:
            pass

    def _parse_nmap_xml(self, xml_output):
        try:
            root = ET.parse(xml_output).getroot()

            for host in root.findall('host'):
                if not host.find('status').get('state') == 'up':
                    continue

                addr = host.find('address').get('addr')

                for port_info in host.findall('ports/port'):
                    if not port_info.find('state').get('state') == 'open':
                        continue

                    protocol = port_info.get('protocol')
                    port = int(port_info.get('portid'))

                    data = {
                        "ip": addr,
                        "port": port,
                        "status": "open",
                    }

                    service_info = port_info.find('service')
                    if service_info != None:
                        service = service_info.get('name')
                        product = service_info.get('product')
                        version = service_info.get('version')
                        if product != None:
                            if version != None:
                                version = "%s %s" % (product, version)
                            else:
                                version = product
                        else:
                            version = ""

                        data["service"] = service
                        data["version"] = version
                    else:
                        data["service"] = ""
                        data["version"] = ""

                    yield data
        except ET.ParseError:
            # Unable to parse XML
            Output.write({"target": "%s:%d" % (target['hostname'], target['port']), "message": "Failed to parse nmap XML output (probably due to nmap core dump)"})

def top_ports(top_n, protocols=['tcp']):
    try:
        if top_n == None:
            return None

        top_n = int(top_n)

        ports = []

        # parse and sort file
        f = open(os.path.join(os.path.dirname(__file__), 'nmap-services'))
        for line in f:
            if line.startswith('#'):
                continue

            line = line.strip()
            parts = line.split()
            freq = float(parts[2])
            port = int(parts[1].split('/')[0])
            protocol = parts[1].split('/')[1]

            if protocol in protocols:
                ports.append({'port': port, 'freq': freq, 'protocol': protocol})

        f.close()
    except Exception as e:
        print("%s: %s\n%s" % (type(e), e, traceback.format_exc()))

    return [p['port'] for p in sorted(ports, key=itemgetter('freq'), reverse=True)[:top_n]]
