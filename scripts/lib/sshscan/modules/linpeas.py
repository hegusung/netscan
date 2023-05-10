from lib.sshscan.ssh import SSH

# Requirements to print
from utils.output import Output
import paramiko

class Module:
    name = 'Linpeas'
    description = 'Run linpeas [authenticated]'

    def run(self, target, args, creds, timeout):
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None

        Output.minor({'target': 'ssh://%s:%d' % (target['hostname'], target['port']), 'message': '[%s] Running module...' % self.name})

        check(target['hostname'], target['port'], user, password, timeout)



def check(hostname, port, user, password, timeout):

    ssh = SSH(hostname, port, timeout)
    connected = ssh.auth(user, password)
    if connected:

        # Upload linpeas
        try:
            ssh.upload_file("scripts/lib/sshscan/linpeas.sh", "/tmp/linpeas.sh")
            Output.highlight({'target': 'ssh://%s:%d' % (hostname, port), 'message': '[Linpeas] Running linpeas...'})
        except Exception as e:
            Output.error({'target': 'ssh://%s:%d' % (hostname, port), 'message': "[Linpeas] %s: %s" % (type(e), str(e))})

        # Execute the script 
        try:
            out = ssh.execute("chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh > /tmp/linpeas_output.txt", timeout=300)
        except Exception as e:
            Output.error({'target': 'ssh://%s:%d' % (hostname, port), 'message': "[Linpeas] %s: %s" % (type(e), str(e))})

        Output.highlight({'target': 'ssh://%s:%d' % (hostname, port), 'message': '[Linpeas] Finished, printing result : \n%s' % ssh.read_file("/tmp/linpeas_output.txt")})

        # Deleting the result
        try:
            out = ssh.execute("rm /tmp/linpeas.sh /tmp/linpeas_output.txt", timeout=300)
        except Exception as e:
            Output.error({'target': 'ssh://%s:%d' % (hostname, port), 'message': "[Linpeas] %s: %s" % (type(e), str(e))})
