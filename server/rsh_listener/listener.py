import threading
import socket
import queue
import time

class Listener:

    def __init__(self, bind_ip, bind_port):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.connection_dict = {}

    def start(self):
        self.thread = threading.Thread(target=self.thread_func)
        self.thread.daemon = True
        self.thread.start()

    def thread_func(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.bind_ip, self.bind_port))
        s.listen()

        print('\033[92mlistening on %s:%d\033[0m' % (self.bind_ip, self.bind_port))

        while True:
            conn, addr = s.accept()

            if len(self.connection_dict.keys()) > 0:
                conn_id = max(self.connection_dict.keys())+1
            else:
                conn_id = 1

            print('\033[94mNew reverse shell from %s => ID: %d\033[0m' % (addr, conn_id))

            t = threading.Thread(target=self.reverse_shell_thread, args=(conn_id,))
            t.daemon = True

            self.connection_dict[conn_id] = {
                'client': addr,
                'conn': conn,
                'thread': t,
                'received_queue': queue.Queue(),
                'last_line': '',
            }

            t.start()

    def reverse_shell_thread(self, conn_id):
        conn = self.connection_dict[conn_id]['conn']
        q = self.connection_dict[conn_id]['received_queue']

        while True:
            try:
                data = conn.recv(1024)
                q.put(data)
            except socket.timeout:
                time.sleep(0.01)
            except ConnectionResetError:
                print('\033[93mReverse shell %d died\033[0m' % conn_id)
                del self.connection_dict[conn_id]
                break

