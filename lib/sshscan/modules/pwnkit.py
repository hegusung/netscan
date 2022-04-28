from lib.sshscan.ssh import SSH

# Requirements to print
from utils.output import Output
# Requirements to ES
from utils.db import DB

class Module:
    name = 'Pwnkit'
    description = 'Check Pwnkit vulnerability (CVE-2021-4034)'

    def run(self, target, args, creds, timeout):
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None

        check(target['hostname'], target['port'], user, password, timeout)


def check(hostname, port, user, password, timeout):

    # Command to check if vulnerable
    '''
    if [ `command -v pkexec` ] && stat -c '%a' $(which pkexec) | grep -q 4755 && [ "$(stat -c '%Y' $(which pkexec))" -lt "1642035600" ]; then 
        echo "Vulnerable to CVE-2021-4034 (PwnKit)" 
        echo ""
    fi
    '''
    command = "echo -n aWYgWyBgY29tbWFuZCAtdiBwa2V4ZWNgIF0gJiYgc3RhdCAtYyAnJWEnICQod2hpY2ggcGtleGVjKSB8IGdyZXAgLXEgNDc1NSAmJiBbICIkKHN0YXQgLWMgJyVZJyAkKHdoaWNoIHBrZXhlYykpIiAtbHQgIjE2NDIwMzU2MDAiIF07IHRoZW4gCiAgICBlY2hvICJWdWxuZXJhYmxlIHRvIENWRS0yMDIxLTQwMzQgKFB3bktpdCkiIAogICAgZWNobyAiIgpmaQo= |base64 -d |bash"

    ssh = SSH(hostname, port, timeout)
    connected = ssh.auth(user, password)
    if connected:
        result = ssh.execute(command)
        if "Vulnerable" in result:
            # Write in terminal
            Output.vuln({'target': 'ssh://%s:%d' % (hostname, port), 'message': 'Vulnerable to CVE-2021-4034 (Pwnkit)'})

            # Push in ES
            vuln_info = {
                'hostname': hostname,
                'port': port,
                'service': 'ssh',
                'url': 'ssh://%s:%d' % (hostname, port),
                'name': 'CVE-2021-4034 (Pwnkit)',
                'description': 'Server ssh://%s:%d is vulnerable to CVE-2021-4034 (Pwnkit)' % (hostname, port),
            }
            DB.insert_vulnerability(vuln_info)

