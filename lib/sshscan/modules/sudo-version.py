from lib.sshscan.ssh import SSH

# Requirements to print
from utils.output import Output

class Module:
    name = 'Sudo-version'
    description = 'Check sudo version'

    def run(self, target, args, creds, timeout):
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None

        check(target['hostname'], target['port'], user, password, timeout)


def check(hostname, port, user, password, timeout):

    # Command to check sudo version
    '''
    sudo --version | grep "Sudo ver" "
    '''
    command = "echo -n c3VkbyAtLXZlcnNpb24gfCBncmVwICJTdWRvIHZlciIgCg==|base64 -d | $0 2>/dev/null || echo -n c3VkbyAtLXZlcnNpb24gfCBncmVwICJTdWRvIHZlciIgCg==|base64 -d |sh 2>/dev/null"

    ssh = SSH(hostname, port, timeout)
    connected = ssh.auth(user, password)
    if connected:
        result = ssh.execute(command)
        if result != '':
            # Write in terminal
            Output.highlight({'target': 'ssh://%s:%d' % (hostname, port), 'message': '%s' % result.strip()})
