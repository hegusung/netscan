import ftplib
import os.path
from time import sleep
import socket
import traceback

from utils.output import Output

def ftpscan_worker(target, actions, creds, timeout):
    try:
        ftpscan = FTPScan(target['hostname'], target['port'], timeout)

        ftp_code, version = ftpscan.grab_banner()
        if ftp_code:
            Output.write({'target': ftpscan.url(), 'message': '%d   %s' % (ftp_code, version)})

            if creds[0] != None and creds[1] != None:
                success = ftpscan.auth(creds[0], creds[1])
            else:
                success = ftpscan.auth()
            if success:
                if creds[0] != None and creds[1] != None:
                    Output.write({'target': ftpscan.url(), 'message': 'Successful connection with credentials %s:%s' % creds})
                else:
                    Output.write({'target': ftpscan.url(), 'message': 'Successful anonymous connection'})

                if 'list' in actions:
                    try:
                        ftp_dir = '/'
                        contents = ""
                        for content in ftpscan.list_content(ftp_dir, recurse=actions['list']['recurse']):
                            if 'size' in content:
                                contents += " "*80+"- %s %s\n" % (content['name'].ljust(30), sizeof_fmt(content['size']))
                            else:
                                contents += " "*80+"- %s\n" % content['name']
                        Output.write({'target': ftpscan.url(), 'message': 'Contents of %s\n%s' % (ftp_dir, contents)})
                    except socket.timeout as e:
                        Output.write({'target': ftpscan.url(), 'message': 'Timeout while listing folder, do you have a firewall enabled ?'})
    except Exception as e:
        Output.write({'target': ftpscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        ftpscan.disconnect()


def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f %s%s" % (num, 'Yi', suffix)

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

            ftp_code = int(banner_parts[0])
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

                    if recurse <= 0:
                        data = {'type': file_type, 'name': content}
                        if file_size != None:
                            data['size'] = file_size

                        yield data
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

            if not has_content and path != '/':
                yield {'type': 'folder', 'name': path}
        except ftplib.error_perm:
            return
        except ftplib.error_temp:
            return
