from lib.sshscan.ssh import SSH

# Requirements to print
from utils.output import Output

class Module:
    name = 'Sudo-privs'
    description = 'Get sudo privileges list [authenticated]'

    def run(self, target, args, creds, timeout):
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None

        Output.minor({'target': 'ssh://%s:%d' % (target['hostname'], target['port']), 'message': '[%s] Running module...' % self.name})

        check(target['hostname'], target['port'], user, password, timeout)


def check(hostname, port, user, password, timeout):

    # Command to get sudo privileges
    command = "echo '%s\n' | sudo -l -S | grep -i \"NOPASSWD\\|root\"" % password

    ssh = SSH(hostname, port, timeout)
    connected = ssh.auth(user, password)
    if connected:
        result = ssh.execute(command)
        if result != '':
            result = result.strip().split("\n")
            for rule in result:
            # Write in terminal
                if "tty" in rule.lower():
                    Output.highlight({'target': 'ssh://%s:%d' % (hostname, port), 'message': '[Sudo-privs] Can\'t check: no tty'})
                if "root" in rule or "nopasswd" in rule.lower():
                    Output.highlight({'target': 'ssh://%s:%d' % (hostname, port), 'message': '[Sudo-privs] %s' % rule.strip()})
