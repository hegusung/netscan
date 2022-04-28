from lib.sshscan.ssh import SSH

# Requirements to print
from utils.output import Output

class Module:
    name = 'Interfaces'
    description = 'List network interfaces'

    def run(self, target, args, creds, timeout):
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None

        check(target['hostname'], target['port'], user, password, timeout)


def check(hostname, port, user, password, timeout):

    # Command to check sudo version
    '''
    sudo --version | grep "Sudo ver" "
    '''
    command = "bash -c \"ip addr | grep -oP \'(?<=inet\\s)\\d+(\\.\\d+){3}\'\""

    ssh = SSH(hostname, port, timeout)
    connected = ssh.auth(user, password)
    if connected:
        result = ssh.execute(command).strip()
        #print(result)
        result = result.replace("\n", " | ")
        if result != '' and 'invalid' not in result:
            # Write in terminal
            Output.highlight({'target': 'ssh://%s:%d' % (hostname, port), 'message': 'Network interfaces : \033[1m %s \033[0m' % result.strip()})