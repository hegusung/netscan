import sys
import os
import copy
from datetime import datetime
from multiprocessing import Queue, Manager
from threading import Thread
from utils.config import Config
import tqdm
from tqdm import tqdm

# Sometimes tqdm hangs during write
#tqdm.get_lock().locks = []
from utils.dispatch import pg_lock
tqdm.set_lock(pg_lock)

# Colors:
GREY = "\033[90m"
LIGHT_GREY = "\033[37m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
RESET = "\033[0m"

time_format = "%Y/%m/%d %H:%M:%S"
log_time_format = "%Y%m%d"
simple_output_format =         "[{time}]     {color}{message}{reset}"
target_output_format =         "[{time}]     {color}{target:50} {message}{reset}"
http_output_format =           "[{time}]     {color}{target:50} {code}   {server:40} {title}{reset}"
dns_output_format =            "[{time}]     {color}{target:50} {query_type:5}   {resolved}{reset}"
port_service_output_format =   "[{time}]     {color}{target:50} {service:30} {version}{reset}"
smb_output_format =            "[{time}]     {color}{target:50} {domain:30} {hostname:30} {server_os}{reset}"
mssql_output_format =          "[{time}]     {color}{target:50} {version}{reset}"
mysql_output_format =          "[{time}]     {color}{target:50} {version}{reset}"
postgresql_output_format =     "[{time}]     {color}{target:50} {version}{reset}"

class Output:

    @classmethod
    def setup(self):
        manager = Manager()
        self.output_queue = manager.Queue()

        self.output_thread = Thread(target=self.output_worker, args=(self.output_queue,))
        self.output_thread.daemon = True
        self.output_thread.start()

    @classmethod
    def stop(self):
        self.output_queue.put(None)
        self.output_thread.join()

    @classmethod
    def write(self, message):
        self.output_queue.put(message)

    @classmethod
    def vuln(self, message):
        if type(message) == str:
            message = {'message': message}
        message['type'] = 'vuln'
        self.write(message)

    @classmethod
    def major(self, message):
        if type(message) == str:
            message = {'message': message}
        message['type'] = 'major'
        self.write(message)

    @classmethod
    def success(self, message):
        if type(message) == str:
            message = {'message': message}
        message['type'] = 'success'
        self.write(message)

    @classmethod
    def highlight(self, message):
        if type(message) == str:
            message = {'message': message}
        message['type'] = 'highlight'
        self.write(message)

    @classmethod
    def minor(self, message):
        if type(message) == str:
            message = {'message': message}
        message['type'] = 'minor'
        self.write(message)

    @classmethod
    def error(self, message):
        if type(message) == str:
            message = {'message': message}
        message['type'] = 'error'
        self.write(message)

    @classmethod
    def log(self, message, output_format):
        if Config.config.get('Logging', 'enabled') in ['true', 'True']:
            script_name = os.path.basename(sys.argv[0]).split('.')[0]
            now = datetime.now()

            log_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), Config.config.get('Logging', 'folder'), "log_%s_%s.log" % (script_name, now.strftime(log_time_format)))

            # remove all colors
            message['color'] = ''
            message['reset'] = ''

            message = output_format.format(**message)

            logfile = open(log_path, 'a')
            logfile.write(message + '\n')
            logfile.close()

    @classmethod
    def color(self, message, message_type):
        if message_type in ['vuln', 'major']:
            message['color'] = RED
        elif message_type in ['success']:
            message['color'] = GREEN
        elif message_type in ['highlight']:
            message['color'] = YELLOW
        elif message_type in ['minor']:
            message['color'] = BLUE
        elif message_type in ['error']:
            message['color'] = BOLD + RED
        else:
            message['color'] = WHITE

        message['reset'] = RESET

        return message

    @classmethod
    def output_worker(self, output_queue):
        while True:
            message = output_queue.get()
            if message == None:
                break

            if type(message) == str:
                message = {'message': message}

            if not 'time' in message:
                now = datetime.now()
                message['time'] = now.strftime(time_format)

            # Select the correct formating

            if 'message_type' in message and message['message_type'] == 'http':
                output_format = http_output_format
            elif 'message_type' in message and message['message_type'] == 'dns':
                output_format = dns_output_format
            elif 'message_type' in message and message['message_type'] == 'port_service':
                output_format = port_service_output_format
            elif 'message_type' in message and message['message_type'] == 'smb':
                output_format = smb_output_format
            elif 'message_type' in message and message['message_type'] == 'mssql':
                output_format = mssql_output_format
            elif 'message_type' in message and message['message_type'] == 'mysql':
                output_format = mysql_output_format
            elif 'message_type' in message and message['message_type'] == 'postgresql':
                output_format = postgresql_output_format
            elif 'target' in message:
                output_format = target_output_format
            else:
                output_format = simple_output_format

            if 'type' in message:
                message_type = message['type']
            else:
                message_type = None

            # Log to a file before coloring
            self.log(message, output_format)

            self.color(message, message_type)

            # Remove control characters which breaks terminal
            message = output_format.format(**message)
            message = ''.join([c if ord(c) not in [0x9d, 0x9e, 0x9f] else '\\x%x' % ord(c) for c in message])

            tqdm.write(message)
            sys.stdout.flush()
