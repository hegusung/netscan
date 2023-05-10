from lib.sshscan.ssh import SSH
from utils.output import Output
from utils.db import DB

class Module:
    name = 'Squash'
    description = 'Check no_root_squash in NFS share [authenticated]'

    def run(self, target, args, creds, timeout):
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None

        Output.minor({'target': 'ssh://%s:%d' % (target['hostname'], target['port']), 'message': '[%s] Running module...' % self.name})

        check(target['hostname'], target['port'], user, password, timeout)


def check(hostname, port, user, password, timeout):

    # Command to check if vulnerable
    command = "cat /etc/exports |grep no_root_squash"

    ssh = SSH(hostname, port, timeout)
    connected = ssh.auth(user, password)
    if connected:
        result = ssh.execute(command).strip()
        if "rw" in result:
            # Write in terminal
            Output.vuln({'target': 'ssh://%s:%d' % (hostname, port), 'message': '[Squash] Vulnerable to no_root_squash'})
            for line in result.split("\n"):
                Output.highlight({'message': " "*60+"- %s" % line.strip()})

            # Push in ES
            vuln_info = {
                'hostname': hostname,
                'port': port,
                'service': 'ssh',
                'url': 'ssh://%s:%d' % (hostname, port),
                'name': 'No root squash',
                'description': 'Server ssh://%s:%d is vulnerable to no_root_squash' % (hostname, port),
            }
            DB.insert_vulnerability(vuln_info)
        if "ro" in result and "rw" not in result:
            Output.vuln({'target': 'ssh://%s:%d' % (hostname, port), 'message': '[Squash] Vulnerable to no_root_squash \033[1mbut read only\033[0m'})
            for line in result.split("\n"):
                Output.highlight({'message': " "*60+"- %s" % line.strip()})

