from lib.sshscan.ssh import SSH

# Requirements to print
from utils.output import Output
import paramiko

class Module:
    name = 'Linpeas'
    description = 'Run linpeas'

    def run(self, target, args, creds, timeout):
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None

        check(target['hostname'], target['port'], user, password, timeout)



def check(hostname, port, user, password, timeout):

    ssh = SSH(hostname, port, timeout)
    connected = ssh.auth(user, password)
    if connected:

        # Upload linpeas
        try:
            ssh.upload_file("lib/sshscan/linpeas.sh", "/tmp/linpeas.sh")
            Output.highlight({'target': 'ssh://%s:%d' % (hostname, port), 'message': 'Linpeas is running...'})
        except Exception as e:
            print("%s: %s" % (type(e), str(e)))

        # Execute the script 
        try:
            out = ssh.execute("chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh > /tmp/linpeas_output.txt", timeout=300)
        except Exception as e:
            print("%s: %s" % (type(e), str(e)))

        Output.highlight({'target': 'ssh://%s:%d' % (hostname, port), 'message': 'Linpeas is finished, printing result : '})

        # Print the result
        print(ssh.read_file("/tmp/linpeas_output.txt"))