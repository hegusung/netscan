import socket
import tempfile
import os.path
import subprocess
import traceback
from time import sleep
from operator import itemgetter
from utils.output import Output
from utils.db import DB
import xml.etree.ElementTree as ET

nmap_bin = "nmap"

def portscan_worker(target, service_scan, actions, timeout):
    try:
        portscan = PortScan(target['hostname'], target['port'], timeout)

        is_open = portscan.check_open()

        if is_open:
            if service_scan:
                if 'scripts' in actions:
                    service_check = portscan.service_check(scripts=actions['scripts']['scripts'], args=actions['scripts']['args'])
                else:
                    service_check = portscan.service_check()
                for t, output in service_check:
                    if t == 'port':
                        output["message_type"] = "port"
                        output["target"] = "%s:%d" % (target['hostname'], target['port'])
                        Output.write(output)
                        data = {
                            'hostname': target['hostname'],
                            'port': target['port'],
                        }
                        if 'service' in output:
                            data['nmap_service'] = output['service']
                        if 'version' in output:
                            data['nmap_version'] = output['version']
                        DB.insert_port(data)
                    elif t == 'script':
                        message = "Script: %s\n%s" % (output['script']['name'], output['script']['output'])
                        Output.write({'target': '%s:%d' % (output['ip'], output['port']), 'message': message})
                        script_info = {
                            'hostname': output['ip'],
                            'port': output['port'],
                            'nmap_service': output['service'],
                            'url': '%s:%d' % (output['ip'], output['port']),
                            'name': output['script']['name'],
                            'output': output['script']['output'],
                        }
                        DB.insert_script(script_info)
                    elif t == 'vuln':
                        message = "Vulnerability: %s\n%s" % (output['vuln']['name'], output['vuln']['description'])
                        Output.write({'target': '%s:%d' % (output['ip'], output['port']), 'message': message})
                        vuln_info = {
                            'hostname': output['ip'],
                            'port': output['port'],
                            'service': output['service'],
                            'url': '%s:%d' % (output['ip'], output['port']),
                            'name': output['vuln']['name'],
                            'description': output['vuln']['description'],
                        }
                        DB.insert_vulnerability(vuln_info)

            else:
                Output.write({"target": "%s:%d" % (target['hostname'], target['port']), "message": "open"})
                DB.insert_port({
                    'hostname': target['hostname'],
                    'port': target['port'],
                })
    except Exception as e:
        if str(e) == 'Failed to parse nmap XML output (probably due to nmap core dump)':
            Output.write({"target": "%s:%d" % (target['hostname'], target['port']), "message": "Failed to parse nmap XML output (probably due to nmap core dump)"})
        else:
            raise e

class PortScan:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

    def check_open(self):

        retry = 0
        while True:
            sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            result = sock.connect_ex((self.hostname, self.port))
            #print("%s:%s => %s" % (self.hostname, self.port, result))

            sock.close()

            # Error 11: ressource temporaly unavailable
            if result == 0:
                return True
            elif result == 11:
                return False
            else:
                return False

    def service_check(self, scripts=None, args=None):

        try:
            xml_dir = tempfile.mkdtemp()
            xml_output = os.path.join(xml_dir, next(tempfile._get_candidate_names()))

            nmap_command = "%s -sV -Pn -T3 -p %d %s -oX %s" % (nmap_bin, self.port, self.hostname, xml_output)
            if scripts != None:
                nmap_command += " --script=\"%s\"" % scripts
                if args != None:
                    nmap_command += " --script-args=\"%s\"" % args

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

        try:
            os.rmdir(xml_dir)
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
                        extrainfo = service_info.get('extrainfo')
                        if product != None:
                            if version != None:
                                version = "%s %s" % (product, version)
                            else:
                                version = product
                        else:
                            version = ""

                        if extrainfo != None:
                            version = "%s (%s)" % (version, extrainfo)

                        data["service"] = service
                        data["version"] = version
                    else:
                        data["service"] = ""
                        data["version"] = ""

                    yield "port", data

                    if service_info != None:
                        for script_data in port_info.findall('script'):
                            script_name = script_data.get('id')
                            script_output = script_data.get('output')

                            script_info = {
                                    "ip": addr,
                                    "port": port,
                                    "service": service,
                                    "version": version,
                                    "script": {
                                        "name": script_name,
                                        "output": script_output,
                                    }
                            }
                            yield "script", script_info

                            # extract vulnerabilities
                            for vuln in script_data.findall('table'):
                                title = None
                                cve = None
                                state = "Unknown"
                                description = "No description"

                                if vuln.get('key') != None and vuln.get('key').startswith('CVE-'):
                                    cve = vuln.get('key')

                                for item in vuln:
                                    if item.tag == "elem":
                                        if item.get('key') == "title":
                                            title = item.text
                                        elif item.get('key') == "state":
                                            state = item.text
                                    elif item.tag == "table":
                                        if item.get('key') == "description":
                                            for subitem in item:
                                                if subitem.tag == "elem":
                                                    description = subitem.text

                                if state == "VULNERABLE" and title != None:
                                    if cve != None:
                                        title += " (%s)" % cve
                                    vuln_data = {
                                        "vuln": {
                                            "name": title,
                                            "description": description.strip(),
                                        },
                                        "ip": addr,
                                        "port": port,
                                        "service": service,
                                        "version": version,
                                    }
                                    yield "vuln", vuln_data


                # for smb
                hostscript = host.find('hostscript')
                if hostscript != None:
                    for script_data in hostscript.findall('script'):
                            script_name = script_data.get('id')
                            script_output = script_data.get('output')

                            if addr != None and port != None and protocol != None:

                                script_info = {
                                        "ip": addr,
                                        "port": port,
                                        "service": service,
                                        "script": {
                                            "name": script_name,
                                            "output": script_output,
                                        }
                                }
                                yield "script", script_info

                                # extract vulnerabilities
                                for vuln in script_data.findall('table'):
                                    title = None
                                    cve = None
                                    state = "Unknown"
                                    severity = "Unknown"
                                    description = "No description"

                                    if vuln.get('key') != None and vuln.get('key').startswith('CVE-'):
                                        cve = vuln.get('key')

                                    for item in vuln:
                                        if item.tag == "elem":
                                            if item.get('key') == "title":
                                                title = item.text
                                            elif item.get('key') == "state":
                                                state = item.text
                                        elif item.tag == "table":
                                            if item.get('key') == "description":
                                                for subitem in item:
                                                    if subitem.tag == "elem":
                                                        description = subitem.text

                                    if state == "VULNERABLE" and title != None:
                                        if cve != None:
                                            title += " (%s)" % cve
                                        vuln_data = {
                                            "vuln": {
                                                "name": title,
                                                "description": description.strip(),
                                            },
                                            "ip": addr,
                                            "port": port,
                                            "service": service,
                                            "version": version,
                                        }
                                        yield "vuln", vuln_data
        except ET.ParseError:
            # Unable to parse XML
            raise Exception("Failed to parse nmap XML output (probably due to nmap core dump)")

def top_ports(top_n, protocols=['tcp']):
    every_port = range(1,65536)
    try:
        if top_n == None:
            return None

        if '-' in top_n:
            top_start = int(top_n.split('-')[0])
            top_end = int(top_n.split('-')[-1])
        else:
            top_start = 0
            top_end = int(top_n)

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

    import time
    t = time.time()
    output = []

    top_port_list = [p['port'] for p in sorted(ports, key=itemgetter('freq'), reverse=True)]

    if top_start < len(top_port_list):
        output = top_port_list[top_start:top_end]

    count = len(output)
    total_top = top_end-top_start
    current_top = len(top_port_list)

    if total_top > count:
        for port in every_port: 
            if port in top_port_list:
                continue

            if current_top >= top_start and current_top < top_end:
                output.append(port)
                count += 1
    
            if total_top <= count:
                break

            current_top += 1

    return output
