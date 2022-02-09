import readline
import time
import shlex
import queue
import threading
import sys
import socket
from utils.output import Output
from server.payload_manager import PayloadManager

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

                try:

                    if cmd[0] == 'list':
                        for conn_id, conn in self.listener.connection_dict.items():
                            print(" - %d: %s" % (conn_id, conn['client']))

                    elif cmd[0] == 'use':
                        conn_id = int(cmd[1])

                        if not conn_id in self.listener.connection_dict:
                            print("\033[91mUnable to find connection with ID %d\033[0m" % conn_id)
                            continue

                        self.state = ('interact', conn_id)

                    elif cmd[0] == 'kill':
                        conn_id = int(cmd[1])

                        if not conn_id in self.listener.connection_dict:
                            print("\033[91mUnable to find connection with ID %d\033[0m" % conn_id)
                            continue

                        self.listener.connection_dict[conn_id]['conn'].shutdown(socket.SHUT_RDWR)
                        self.listener.connection_dict[conn_id]['conn'].close()

                    elif cmd[0] == 'payloads':
                        print("\033[92mWindows payloads: \033[0m")
                        modules = PayloadManager.list_payloads('cmd')
                        for name, module in modules.items():
                            print(" - %s %s" % (module.name, ' '.join(['<%s>' % s for s in module.args])))
                        print("\033[92mLinux payloads: \033[0m")
                        modules = PayloadManager.list_payloads('sh')
                        for name, module in modules.items():
                            print(" - %s %s" % (module.name, ' '.join(['<%s>' % s for s in module.args])))

                    elif cmd[0] == 'exec':
                        conn_id = int(cmd[1])

                        if not conn_id in self.listener.connection_dict:
                            print("\033[91mUnable to find connection with ID %d\033[0m" % conn_id)
                            continue

                        payload = PayloadManager.generate_payload(cmd[2], cmd[3:])
                        print("\033[92mExecuting payload \"%s\" on reverse shell %d: \033[0m" % (payload, conn_id))

                        payload = '%s\n' % payload
                        self.listener.connection_dict[conn_id]['conn'].send(payload.encode())


                    elif cmd[0] == 'quit':
                        Output.stop()
                        sys.exit()

                    elif cmd[0] == 'help':
                        print("\033[92mNormal mode: \033[0m")
                        print("  - list:                        List all available reverse_shell")
                        print("  - use <id>:                    Interact with a specific reverse shell")
                        print("  - kill <id>:                   Kill the reverse shell")
                        print("  - exec <id> <payload> <args>*: Execute a specific payload")
                        print("  - payloads:                    List available payloads")
                        print("  - quit:                        Stop the reverse listener")
                        print("\033[92mInteract mode: \033[0m")
                        print("  - bg:                          Stop interacting, go back to normal mode")

                except IndexError:
                    print("\033[91mError while executing command \033[0m")
                except ValueError:
                    print("\033[91mError while executing command \033[0m")

            elif self.state[0] == 'interact':
                if command == 'bg':
                    print("")
                    self.state = ('base',)
                else:
                    command = '%s\n' % command
                    self.listener.connection_dict[conn_id]['conn'].send(command.encode())


    def prompt(self):
        if self.state[0] == 'base':
            return "\033[94mrshl> \033[0m"
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
                except KeyError:
                    self.state = ('base',)
                    # The connection closed
                    pass



