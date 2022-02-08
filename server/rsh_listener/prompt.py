import readline
import time
import shlex
import queue
import threading

class Prompt:

    def __init__(self, listener):
        self.listener = listener
        self.state = ('base',)

        self.recv_t = threading.Thread(target=self.receiver_thread)
        self.recv_t.daemon = True
        self.recv_t.start()

    def start(self):
        while True:
            command = input(self.prompt())
            cmd = shlex.split(command)

            if self.state[0] == 'base':
                if len(cmd) < 1:
                    continue

                if cmd[0] == 'list':
                    for conn_id, conn in self.listener.connection_dict.items():
                        print(" - %d: %s" % (conn_id, conn['client']))

                elif cmd[0] == 'get':
                    conn_id = int(cmd[1])

                    if not conn_id in self.listener.connection_dict:
                        print("\033[92mUnable to find connection with ID %d\033[0m" % conn_id)

                    self.state = ('interact', conn_id)

            elif self.state[0] == 'interact':
                if command == 'bg':
                    print("")
                    self.state = ('base',)
                else:
                    command = '%s\n' % command
                    self.listener.connection_dict[conn_id]['conn'].send(command.encode())


    def prompt(self):
        if self.state[0] == 'base':
            return "\033[92mrshl> \033[0m"
        else:
            return ""

    def receiver_thread(self):

        while True:
            time.sleep(0.01)

            if self.state[0] == 'interact':
                conn_id = self.state[1]

                try:
                    data = self.listener.connection_dict[conn_id]['received_queue'].get(block=False)
                    print(data.decode(), end='', flush=True)
                except queue.Empty:
                    pass



