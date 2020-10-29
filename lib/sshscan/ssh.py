import socket
import time
import paramiko
from utils.utils import AuthFailure

class SSH:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.conn = None

    def url(self):
        return 'ssh://%s:%d' % (self.hostname, self.port)

    def get_version(self):
        try:
            sock = socket.socket()
            sock.settimeout(self.timeout)
            sock.connect((self.hostname, self.port))

            banner_raw = sock.recv(1024)

            if banner_raw[:3] == b"SSH":
                try:
                    return banner_raw.decode().rstrip()
                except UnicodeDecodeError:
                    return None
            else:
                return None
        except ConnectionRefusedError:
            return None
        except OSError:
            return None

    def auth(self, username, password):
        self.conn = paramiko.Transport((self.hostname, self.port))
        self.conn.connect(username=username, password=password)

        return True

    def execute(self, command):
        chan = self.conn.open_channel("session")
        chan.settimeout(self.timeout)

        result = ''

        chan.exec_command(command)
        stdin = chan.makefile_stdin("wb", -1)
        stdout = chan.makefile("r", -1)
        stderr = chan.makefile_stderr("r", -1)

        result = stdout.read()
        result += stderr.read()

        chan.close()

        return result.decode()

    def disconnect(self):
        if self.conn:
            self.conn.close()
        self.conn = None
