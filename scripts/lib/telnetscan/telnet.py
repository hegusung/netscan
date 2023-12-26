import socket
import time
import re
import telnetlib

# Taken from metasploit
regex_login = re.compile(b'(?:log[io]n( name|)|user( ?name|id|))\\s*\\:', re.IGNORECASE)
regex_password = re.compile(b'(?:password|passwd)\\s*\\:', re.IGNORECASE)
regex_busy = re.compile(b'(?:Another\\ telnet\\ session\\ is\\ in\\ progress|Disconnecting\\.\\.\\.)', re.IGNORECASE | re.MULTILINE)
regex_waiting = re.compile(b'(?:.*please\\ wait.*|.*one\\ minute.*)', re.IGNORECASE | re.MULTILINE)
regex_failure = re.compile(b'(?:Incorrect|Unknown|Fail|Invalid|Login|Password|Passwd|Username|Unable|Error|Denied|Reject|Sorry|^http|html|Not\\ on\\ system\\ console|Enter\\ username\\ and\\ password|Auto\\ Apply\\ On|YOU\\ LOGGED\\ IN\\ USING\\ ALL\\ UPPERCASE\\ CHARACTERS|\n\\*$|(Login ?|User ?)(name|):|^\\s*\\<[a-f0-9]+\\>\\s*$|^\\s*220.*FTP|not\\ allowed\\ to\\ log\\ in)', re.IGNORECASE | re.MULTILINE)
regex_false_failure = re.compile(b'(?:(^\\s*last)\\ login *\\:|allows only\\ .*\\ Telnet\\ Client\\ License)', re.IGNORECASE|re.MULTILINE)
regex_success = re.compile(b'(?:list\\ of\\ built-in|sh.*[\\#\\$]\\s*$|\\[\\/\\]\\s*$|or\\ the\\ MENU\\ system|Password\\ is\\ not\\ set|logging\\ in\\ as\\ visitor|Login\\ successful)', re.IGNORECASE | re.MULTILINE)

class Telnet:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.conn = telnetlib.Telnet(self.hostname, self.port, self.timeout)

        self.step = 'connect'

    def url(self):
        return 'telnet://%s:%d' % (self.hostname, self.port)

    def connect(self):
        if not self.step in ['connect']:
            raise Exception('Not at the correct step')

        # Read until login or busy
        res = self.conn.expect([regex_login, regex_password, regex_busy], self.timeout)
        match = res[1]

        if not match:
            raise Exception('Unable to get a login prompt: %s' % res[2])

        banner = '\n'.join(res[2].decode().split('\n')[:-1]) # Remove last part

        if res[0] == 0:
            # Login input found
            self.step = 'login'
            return banner
        elif res[0] == 1:
            # Password input found
            self.step = 'password'
            return banner
        else:
            # Busy found
            raise Exception('Telnet is busy')


    def auth(self, username, password):
        if not self.step in ['login', 'password']:
            raise Exception('Not at the correct step')

        if self.step == 'login':
            self.conn.write(username.encode() + b'\r\n')

            # expecting a password form
            res = self.conn.expect([regex_password], self.timeout)
            match = res[1]

            if not match:
                raise Exception('Unable to get a password prompt: %s' % res[2])

            self.step = 'password'

        if self.step == 'password':
            self.conn.write(password.encode() + b'\r\n')

            # We need to received the whole answer before going further to make sure we didn't miss anything
            data = b''
            while True:
                res = self.conn.read_until(b'\n', 2)
                if len(res) == 0:
                    break
                data += res

            data = data.strip()

            if len(data) == 0:
                # Very probably login fail
                return False
            elif regex_success.search(data):
                # login success:
                self.step = 'shell'
                return True
            elif regex_failure.search(data):
                # Login fail
                if regex_false_failure.search(data):
                    # False positive ! login success
                    self.step = 'shell'
                    return True
                self.step = 'end'
                return False
            else:
                # Nothing matched, may result in FP
                return True

        return False


    def execute(self, command):
        # Lets get prompt first

        self.conn.write(b'\n')
        prompt = b''
        while True:
            res = self.conn.read_until(b'\n', 0.5)
            if len(res) == 0:
                break
            prompt += res
        prompt = prompt.strip()

        # Every command which changes directory will make this approach fail but well...

        self.conn.write(command.encode() + b'\n')
        res = self.conn.read_until(prompt, 60)
        res = res.strip()
        if res.endswith(prompt):
            res = res[:-len(prompt)]
            res = res.strip()

        return res.decode()

    def disconnect(self):
        if self.conn:
            self.conn.close()
        self.conn = None
