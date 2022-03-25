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
from utils.dispatch import pg_lock
tqdm.set_lock(pg_lock)

# Colors:
color_dict = {
    'grey': "\033[90m",
    'light_grey': "\033[37m",
    'red': "\033[91m",
    'green': "\033[92m",
    'yellow': "\033[93m",
    'blue': "\033[94m",
    'magenta': "\033[95m",
    'cyan': "\033[96m",
    'white': "\033[97m",
    'bold': "\033[1m",
}
RESET = "\033[0m"

log_time_format = "%Y%m%d"

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
        try:
            color = Config.config.get('Color', message_type)
        except KeyError:
            color = 'normal'

        color_pattern = ''
        for c in color.split():
            try:
                color_pattern += color_dict[c]
            except:
                pass

        if len(color_pattern) == 0:
            color_pattern = color_dict['white']

        message['color'] = color_pattern
        message['reset'] = RESET

        return message

    @classmethod
    def output_worker(self, output_queue):
        try:
            while True:
                message = output_queue.get()
                if message == None:
                    break

                if type(message) == str:
                    message = {'message': message}

                if not 'time' in message:
                    now = datetime.now()
                    message['time'] = now.strftime(Config.config.get('Format', 'time'))

                # Select the correct formating
                try:
                    output_format = Config.config.get('Format', message['message_type'])
                except KeyError:
                    if 'target' in message:
                        output_format = Config.config.get('Format', 'target')
                    else:
                        output_format = Config.config.get('Format', 'default')
     
                if 'type' in message:
                    message_type = message['type']
                else:
                    message_type = 'normal'

                # Log to a file before coloring
                self.log(message, output_format)

                self.color(message, message_type)

                # Remove control characters which breaks terminal
                message = output_format.format(**message)
                message = ''.join([c if ord(c) not in [0x9d, 0x9e, 0x9f] else '\\x%x' % ord(c) for c in message])

                tqdm.write(message)
                sys.stdout.flush()
        except EOFError:
            pass
