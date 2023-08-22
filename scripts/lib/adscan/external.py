import subprocess
import json

from utils.utils import gen_random_string

def call_certipy(dc_ip, creds):

    output_file = "/tmp/netscan_%s" % gen_random_string()
    cmd_parts = ["certipy", "find", "-vulnerable", "-enabled", "-output", output_file, "-json", "-dc-ip", dc_ip]

    output_file += "_Certipy.json"

    if "kerberos" in creds:
        raise NotImplementedError("Certipy with kerberos not implemented")

    if not "username" in creds:
        raise Exception("certipy requires a username")

    user = "%s@%s" % (creds['username'], creds['domain'])

    cmd_parts += ["-u", user]

    if "password" in creds:
        cmd_parts += ["-p", creds['password']]

    elif "hash" in creds:
        cmd_parts += ['-hashes', creds['hash']]

    else:
        raise Exception("A password or a hash must be specified")

    proc = subprocess.Popen(cmd_parts, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc.communicate()

    f = open(output_file)
    certipy_json = json.loads(f.read())
    f.close()

    ca_vulns = []
    for key, cert in certipy_json['Certificate Authorities'].items():
        if '[!] Vulnerabilities' in cert:
            for vuln_name, description in cert['[!] Vulnerabilities'].items():
                ca_vulns.append({
                    'ca': cert['CA Name'],
                    'vuln_name': vuln_name,
                    'description': description,
                })

    template_vulns = []
    for key, cert in certipy_json['Certificate Templates'].items():
        if '[!] Vulnerabilities' in cert:
            for vuln_name, description in cert['[!] Vulnerabilities'].items():
                template_vulns.append({
                    'template': cert['Template Name'],
                    'vuln_name': vuln_name,
                    'description': description,
                })

    return ca_vulns, template_vulns
