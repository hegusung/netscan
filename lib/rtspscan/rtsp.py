#!/usr/bin/python3

import cv2
import socket
import logging
from time import sleep
import requests

class RTSP(object):

    def __init__(self, ip, port, timeout):

        self.ip = ip
        self.port = port
        self.timeout = timeout

    def url(self, uri='/'):
        return 'rtsp://%s:%d%s' % (self.ip, self.port, uri)

    def connect(self, uri='/'):
        try:

            describe_payload = "DESCRIBE %s RTSP/1.0\r\nCSeq: 1\r\n\r\n" % self.url(uri)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.ip, self.port))

            sock.send(describe_payload.encode())

            describe_result = sock.recv(4096)

            sock.close()

            try:
                describe_result = describe_result.decode()
            except UnicodeDecodeError:
                return None, None

            if not describe_result.startswith('RTSP'):
                return None, None

            #print(describe_result)

            status_code = -1
            headers = {}
            for i, line in enumerate(describe_result.split('\r\n')):
                    if len(line) == 0:
                        break

                    if i == 0:
                        items = line.split()

                        status_code = int(items[1])
                    else:
                        items = line.split(": ")
                        headers[items[0]] = items[1]

            return status_code, headers
        except ConnectionRefusedError:
            return None, None
        except OSError:
            return None, None

    def disconnect(self):
        pass

    def screenshot(self, uri='/', filename=None):
        if filename == None:
            return False

        cap = cv2.VideoCapture(self.url(uri=uri))

        frameId = cap.get(1)
        ret, frame = cap.read()

        if (ret != True):
            return False

        cv2.imwrite(filename, frame)

        return True

