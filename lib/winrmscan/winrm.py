from utils.utils import AuthFailure
from pypsrp.client import Client

class WinRMScan:

    def __init__(self, hostname, timeout):
        self.hostname = hostname
        self.timeout = timeout

        self.conn = None

        #TODO: use requests to check in http server for winrm is running

    def auth(self, domain=None, username=None, password=None, hash=None):

        if not username:
            raise AuthFailure('Username not specified')
        if not password and not hash:
            raise AuthFailure('Password or hash not specified')
        if not domain:
            domain = 'WORKGROUP'
        if hash != None and not ':' in hash:
            lmhash = '00000000000000000000000000000000:'
            hash = lmhash + hash

        try:
            if password:
                self.conn = Client(self.hostname, auth='ntlm', username=username, password=password, ssl=False, connection_timeout=self.timeout)
            else:
                self.conn = Client(self.hostname, auth='ntlm', username=username, password=hash, ssl=False, connection_timeout=self.timeout)

            # check if it works
            self.conn.execute_ps("hostname")

            return True
        except Exception as e:
            print('%s: %s' % (type(e), e))
            return False

    def execute(self, command, get_output=False):
        try:
            r = self.conn.execute_cmd(command)
        except:
            r = self.conn.execute_ps(command)
        return r[0]

    def ps_execute(self, command, get_output=False):
        r = self.conn.execute_ps(command)
        return r[0]

    def disconnect(self):
        pass
