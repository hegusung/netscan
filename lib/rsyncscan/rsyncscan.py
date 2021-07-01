import socket
import subprocess
import traceback
from time import sleep
from utils.output import Output
from utils.db import DB

def rsyncscan_worker(target, timeout):
    rsync = RSync(target['hostname'], target['port'], timeout)

    try:
        version, welcome = rsync.version()

        Output.write({'target': rsync.url(), 'message': 'RSync server: %s' % version})
        DB.insert_port({
            'hostname': target['hostname'],
            'port': target['port'],
            'protocol': 'tcp',
            'service': 'rsync',
            'version': version,
        })

        shares = rsync.list_shares()
        output = 'Rsync shares:\n'
        for share in shares:
            if share['anon'] == True:
                output += ' '*60+'- %s   %s  (Anonymous access !!!)\n' % (share['name'].ljust(30), share['description'].ljust(60))
                vuln_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'rsync',
                    'url': rsync.url(),
                    'name': 'Anonymous connection to service',
                    'description': 'Anonymous account can connect to rsync service: %s/%s' % (rsync.url(), share['name']),
                }
                DB.insert_vulnerability(vuln_info)

                Output.vuln({'target': rsync.url(), 'message': 'Anonymous account can connect to rsync service: %s' % share['name']})

            else:
                output += ' '*60+'- %s   %s  (%s)\n' % (share['name'].ljust(30), share['description'].ljust(60), share['auth_message'])

            db_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'url': rsync.url(),
                'service': 'rsync',
                'share': share['name'],
                'comment': share['description'],
                'path': '/',
            }
            if share['anon'] == True:
                db_info['access'] = ['READ']
            DB.insert_content(db_info)
        Output.write({'target': rsync.url(), 'message': output})

    except OSError:
        pass
    except ConnectionRefusedError:
        pass
    except Exception as e:
        if str(e) == 'Not a rsync server':
            pass
        else:
            Output.write({'target': rsync.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})

class RSync:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.sock = None

    def url(self):
        return 'rsync://%s:%d' % (self.hostname, self.port)

    def version(self, disconnect=True, timeout=None):
        banner = self.connect(timeout=timeout)

        banner = banner.decode()
        if not banner.startswith('@RSYNCD:'):
            raise Exception('Not a rsync server')

        banner = banner.strip()
        version = banner.split()[-1]

        try:
            welcome = self.sock.recv(1024*5)
            welcome = welcome.decode()
        except socket.timeout:
            welcome = None

        if disconnect:
            self.disconnect()

        return version, welcome

    def list_shares(self):
        version, _ = self.version(disconnect=False)

        self.sock.send(('@RSYNCD: %s\n' % version).encode())
        self.sock.send(b'#list\n')

        shares_txt = self.recv_until(b'@RSYNCD: EXIT')

        self.disconnect()

        shares = []
        for line in shares_txt.decode().split('\n'):
            if line.startswith('@RSYNCD: EXIT'):
                break
            share_name = line.split('\t', 1)[0].strip()
            share_desc = line.split('\t', 1)[-1].strip()

            anon_allowed, message = self.check_anon_access(share_name)
            
            shares.append({'name': share_name, 'description': share_desc, 'anon': anon_allowed, 'auth_message': message})

        return shares

    def recv_until(self, end_b):
        received = b''
        while True:
            received += self.sock.recv(1024)
            if end_b in received:
                break

        return received

    def check_anon_access(self, share):
        version, _ = self.version(disconnect=False)

        self.sock.send(('@RSYNCD: %s\n' % version).encode())
        self.sock.send(('%s\n' % share).encode())

        try:
            response = self.sock.recv(1024)
            response = response.decode()

            self.disconnect()

            if response.startswith('@ERROR:'):
                return False, response.strip().split(' ', 1)[-1]
            elif response.startswith('@RSYNCD: OK'):
                return True, 'OK'
            elif response.startswith('@RSYNCD: AUTHREQD'):
                return False, 'Authentication required'
            else:
                return False, 'Unknown message \'%s\'' % response.strip()
        except socket.timeout:
            return False, 'timeout...' % response.strip()

    def connect(self, timeout=None):
        if self.sock:
            self.disconnect()

        if not timeout:
            timeout = self.timeout

        self.sock = socket.socket()
        self.sock.settimeout(timeout)
        self.sock.connect((self.hostname, self.port))

        banner = self.sock.recv(1024)

        return banner

    def disconnect(self):
        if self.sock:
            self.sock.close()
        self.sock = None

