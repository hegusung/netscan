from lib.sshscan.ssh import SSH

# Requirements to print
from utils.output import Output

class Module:
    name = 'Interfaces'
    description = 'List network interfaces [authenticated]'

    def run(self, target, args, creds, timeout):
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None

        Output.minor({'target': 'ssh://%s:%d' % (target['hostname'], target['port']), 'message': '[%s] Running module...' % self.name})

        check(target['hostname'], target['port'], user, password, timeout)


def check(hostname, port, user, password, timeout):

    # Command to get ip and mask of each interfaces
    command = "bash -c \"export PATH=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin:/bin/ && ip addr | grep -oP \'(?<=inet\\s)\\d+(\\.\\d+){3}\\/\\d{1,2}\'\""
    
    ssh = SSH(hostname, port, timeout)
    connected = ssh.auth(user, password)
    if connected:
        result = ssh.execute(command).strip()
        #print(result)
        result = result.replace("\n", " | ")
        if result != '' and 'invalid' not in result:
            # Write in terminal
            Output.highlight({'target': 'ssh://%s:%d' % (hostname, port), 'message': 'Network interfaces : \033[1m %s \033[0m' % result.strip()})
