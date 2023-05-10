import os
import re
import base64
import hashlib

def list_ressources():
    ressource_list = []

    for f in os.listdir(os.path.join(os.path.dirname(__file__), '..', '..', 'server_data', 'ressources')):
        ressource_list.append(f)

    return ressource_list

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def powershell_encode_base64(data):
    blank_command = bytes()
    powershell_command = ""
    n = re.compile(u'(\xef|\xbb|\xbf)')
    for char in (n.sub("", data)):
        blank_command += char.encode("ascii") + "\x00".encode("ascii")

    powershell_command = base64.b64encode(blank_command)
    return powershell_command.decode("ascii")

def get_ressource_md5(filename):
    path = os.path.join(os.path.dirname(__file__), '..', '..', 'server_data', 'ressources', filename)

    return md5(path)

if __name__ == '__main__':
    for f in list_ressources():
        print(f)
