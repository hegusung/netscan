import socket
from time import sleep
from utils.output import Output

def portscan_worker(target, timeout):
    portscan = PortScan(target['hostname'], target['port'], timeout)

    is_open = portscan.check_open()

    if is_open:
        Output.write({"target": "%s:%d" % (target['hostname'], target['port']), "message": "open"})

class PortScan:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

    def check_open(self):

        sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        result = sock.connect_ex((self.hostname, self.port))

        sock.close()

        if result == 0:
            return True
        else:
            return False

