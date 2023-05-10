import ftplib
import socket
import os.path
import traceback
from utils.output import Output

class FTPScan:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.ftp = None

    def url(self):
        return "ftp://%s:%d" % (self.hostname, self.port)

    def grab_banner(self):
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((self.hostname, self.port))
            banner = s.recv(1024)

            banner = banner.decode().strip()
            banner_parts = banner.split(' ', 1)

            if len(banner_parts) < 2:
                return None, None

            ftp_code = int(banner_parts[0].split('-')[0])
            version = banner_parts[1]

        except socket.timeout:
            return None, None
        except OSError:
            return None, None
        except Exception as e:
            Output.write({'target': self.url(), 'message': "%s: %s" % (type(e), e)})
            return None, None

        return ftp_code, version

    def auth(self, username=None, password=None):
        if self.ftp != None:
            self.disconnect()

        self.ftp = ftplib.FTP()
        self.ftp.set_pasv(False)
        self.ftp.connect(self.hostname, self.port, timeout=self.timeout)

        try:
            if username == None:
                self.ftp.login()
            else:
                self.ftp.login(username, password)

            return True
        except ftplib.error_perm:
            return False

    def disconnect(self):
        if self.ftp != None:
            try:
                self.ftp.quit()
                self.ftp.close()
            except socket.timeout:
                pass
            except OSError:
                pass
            finally:
                self.ftp = None

    def list_content(self, path="/", recurse=3):
        try:
            has_content = False

            contents = self.ftp.nlst(path)

            for content in contents:
                has_content = True
                if not content.startswith('/'):
                    content = os.path.join(path, content)

                file_size = None
                try:
                    self.ftp.cwd(content)
                    file_type = 'folder'
                    if not content.endswith('/'):
                        content += '/'

                    data = {'type': file_type, 'name': content}
                    yield data
                    if recurse <= 0:
                        pass
                    else:
                        for data in self.list_content(path=content, recurse=recurse-1):
                            yield data

                except Exception as e:
                    self.ftp.voidcmd("TYPE I")
                    file_size = self.ftp.size(content)
                    file_type = 'file'

                    data = {'type': file_type, 'name': content}
                    if file_size != None:
                        data['size'] = file_size

                    yield data

            #if not has_content and path != '/':
            #    yield {'type': 'folder', 'name': path}
        except ftplib.error_perm:
            return
        except ftplib.error_temp:
            return
