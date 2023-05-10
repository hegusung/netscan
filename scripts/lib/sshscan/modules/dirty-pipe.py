from lib.sshscan.ssh import SSH

# Requirements to print
from utils.output import Output
# Requirements to ES
from utils.db import DB

class Module:
    name = 'DirtyPipe'
    description = 'Check Dirty Pipe vulnerability (CVE-2022-0847) [authenticated]'

    def run(self, target, args, creds, timeout):
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None

        Output.minor({'target': 'ssh://%s:%d' % (target['hostname'], target['port']), 'message': '[%s] Running module...' % self.name})

        check(target['hostname'], target['port'], user, password, timeout)


def check(hostname, port, user, password, timeout):

    # Command to check if vulnerable
    '''
    kernelversion=$(uname -r | awk -F"-" '{print $1}')
    kernelnumber=$(echo $kernelversion | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }')
    if [[ $kernelnumber -ge 5008000000 && $kernelnumber -lt 5017000000 ]]; then # if kernel version beteen 5.8 and 5.17
        echo "Vulnerable to CVE-2022-0847" | sed -${E} "s,.*,${SED_RED_YELLOW},"
        echo ""
    fi
    '''
    command = "echo -n a2VybmVsdmVyc2lvbj0kKHVuYW1lIC1yIHwgYXdrIC1GIi0iICd7cHJpbnQgJDF9JykKa2VybmVsbnVtYmVyPSQoZWNobyAka2VybmVsdmVyc2lvbiB8IGF3ayAtRi4gJ3sgcHJpbnRmKCIlZCUwM2QlMDNkJTAzZFxuIiwgJDEsJDIsJDMsJDQpOyB9JykKaWYgW1sgJGtlcm5lbG51bWJlciAtZ2UgNTAwODAwMDAwMCAmJiAka2VybmVsbnVtYmVyIC1sdCA1MDE3MDAwMDAwIF1dOyB0aGVuICMgaWYga2VybmVsIHZlcnNpb24gYmV0ZWVuIDUuOCBhbmQgNS4xNwogICAgZWNobyAiVnVsbmVyYWJsZSB0byBDVkUtMjAyMi0wODQ3IiAKICAgIGVjaG8gIiIKZmkK|base64 -d |bash"

    ssh = SSH(hostname, port, timeout)
    connected = ssh.auth(user, password)
    if connected:
        result = ssh.execute(command)
        if "Vulnerable" in result:
            # Write in terminal
            Output.vuln({'target': 'ssh://%s:%d' % (hostname, port), 'message': '[DirtyPipe] Vulnerable to CVE-2022-0847 (Dirty Pipe)'})

            # Push in ES
            vuln_info = {
                'hostname': hostname,
                'port': port,
                'service': 'ssh',
                'url': 'ssh://%s:%d' % (hostname, port),
                'name': 'CVE-2022-0847 (Dirty Pipe)',
                'description': 'Server ssh://%s:%d is vulnerable to CVE-2022-0847 (Dirty Pipe)' % (hostname, port),
            }
            DB.insert_vulnerability(vuln_info)

