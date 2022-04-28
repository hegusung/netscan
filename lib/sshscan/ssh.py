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

    def upload_file(self, local_path, remote_path):
        # Function to upload files on server
        sftp = paramiko.SFTPClient.from_transport(self.conn)
        sftp.put(local_path, remote_path)
        sftp.close()

    def download_file(self, remote_path, local_path):
        # Function to download files on server
        sftp = paramiko.SFTPClient.from_transport(self.conn)
        sftp.put(remote_path, local_path)
        sftp.close()

    def read_file(self, remote_path):
        # Function to upload files on server
        sftp = paramiko.SFTPClient.from_transport(self.conn)
        remote_file = sftp.open(remote_path)
        content = ''
        try:
            for line in remote_file:
                content += line
            return content
        finally:
            remote_file.close()

    def execute(self, command, timeout=None):
        if timeout == None:
            timeout = self.timeout

        chan = self.conn.open_channel("session")
        chan.settimeout(timeout)

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
