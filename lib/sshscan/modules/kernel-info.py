from lib.sshscan.ssh import SSH

# Requirements to print
from utils.output import Output

class Module:
    name = 'Kernel'
    description = 'Get kernel informations'

    def run(self, target, args, creds, timeout):
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None

        check(target['hostname'], target['port'], user, password, timeout)


def check(hostname, port, user, password, timeout):

    # Command to get kernel info
    command = "uname -a"

    ssh = SSH(hostname, port, timeout)
    connected = ssh.auth(user, password)
    if connected:
        result = ssh.execute(command)
        if result != '':
            # Write in terminal
            Output.highlight({'target': 'ssh://%s:%d' % (hostname, port), 'message': '%s' % result.strip()})