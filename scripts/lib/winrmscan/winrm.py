from utils.utils import AuthFailure
from pypsrp.client import Client
import pypsrp
import requests

class WinRMScan:

    def __init__(self, hostname, port, timeout, ssl=False):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.ssl = ssl

        self.conn = None

        #TODO: use requests to check in http server for winrm is running

    def url(self):
        scheme = 'https' if self.ssl else 'http'
        return '%s://%s:%d/wsman' % (scheme, self.hostname, self.port)

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
                self.conn = Client(self.hostname, auth='ntlm', username=username, password=password, ssl=self.ssl, port=self.port, cert_validation=False, connection_timeout=self.timeout)
            else:
                self.conn = Client(self.hostname, auth='ntlm', username=username, password=hash, ssl=self.ssl, port=self.port, cert_validation=False, connection_timeout=self.timeout)

            # check if it works
            self.conn.execute_ps("hostname")

            return True
        except requests.exceptions.ConnectionError:
            return False
        except pypsrp.exceptions.AuthenticationError:
            return False
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
