#!/usr/bin/python3

# Author: Hegusung

import socket
import logging
from time import sleep
from Crypto.Cipher import DES
from PIL import Image, ImageDraw

from .keyboard import key_codes

def socket_receive(sock, size):
    res = b""
    while len(res) < size:
        res += sock.recv(size-len(res))

    return res

class VNCException(Exception):
    pass

class VNC(object):

    def __init__(self, ip, port, timeout):

        self.ip = ip
        self.port = port
        self.timeout = timeout

    def url(self):
        return 'vnc://%s:%d' % (self.ip, self.port)

    def connect(self):
        self.sock = socket.create_connection((self.ip, self.port), timeout=self.timeout)

        # == Banner ==

        resp = socket_receive(self.sock, 12)

        if resp[:3] != b"RFB":
            raise Exception("Wrong protocol")

        self.version = resp[:11].decode('ascii')

        logging.info("Server version : %s" % self.version)

        major, minor = int(self.version[6]), int(self.version[10])

        if (major, minor) in [(3, 8), (4, 1)]:
            proto = b'RFB 003.008\n'
        elif (major, minor) == (3, 7):
            proto = b'RFB 003.007\n'
        else:
            proto = b'RFB 003.003\n'

        self.sock.sendall(proto)

        sleep(0.5)

        # == Security types ==


        self.supported_security_types = []

        if major == 4 or (major, minor) in [(3, 7), (3, 8)]:
            resp = socket_receive(self.sock, 1)

            if len(resp) == 0:
                raise VNCException("Protocol error")

            nb_security_types = ord(resp)

            if nb_security_types == 0:
                resp = socket_receive(self.sock, 4)

                msg_len = int.from_bytes(resp, byteorder="big")
                resp = socket_receive(self.sock, msg_len)

                msg = resp.decode("utf-8")
                raise VNCException(msg)

            logging.info("%s Security types" % nb_security_types)

            resp = socket_receive(self.sock, nb_security_types)

            for index in range(0, nb_security_types):
                sec_type_id = int(resp[index])
                self.supported_security_types.append(security_type_from_id(sec_type_id))
                logging.info("> %s" % security_type_from_id(sec_type_id))
        else:
            resp = socket_receive(self.sock, 4)

            if len(resp) == 0:
                raise VNCException("Protocol error")

            sec_type_id = ord(resp[3:4])

            if sec_type_id == 0:
                resp = socket_receive(self.sock, 4)

                msg_len = int.from_bytes(resp, byteorder="big")
                resp = socket_receive(self.sock, msg_len)

                msg = resp.decode("utf-8")
                raise VNCException(msg)

            self.supported_security_types.append(security_type_from_id(sec_type_id))
            logging.info("> %s" % security_type_from_id(sec_type_id))

    def auth(self, auth_type, password=None):

        major, minor = int(self.version[6]), int(self.version[10])

        if auth_type == "None":
            if major == 4 or (major == 3 and minor >= 8):
                self.sock.sendall(b"\x01")
                self.authenticated = True
            elif major == 3 and minor == 7:
                self.sock.sendall(b"\x01")
                self.authenticated = True
                return 0, 'OK'
            else:
                self.authenticated = True
                return 0, 'OK'
        elif auth_type == "VNC Authentication":
            if major == 4 or (major == 3 and minor >= 7):
                self.sock.sendall(b"\x02")

            challenge = socket_receive(self.sock, 16)

            if len(challenge) != 16:
                raise VNCException("Wrong challenge length")

            logging.debug('challenge: %s' % challenge)
            password = password.ljust(8, '\x00')[:8] # make sure it is 8 chars long, zero padded

            key = self.gen_key(password)
            logging.debug('key: %s' % key)

            des = DES.new(key, DES.MODE_ECB)
            enc = des.encrypt(challenge)

            logging.debug('enc: %s' % enc)
            self.sock.sendall(enc)

        resp = socket_receive(self.sock, 4)
        logging.debug('resp: %s' % repr(resp))

        response_code = ord(resp[3:4])
        mesg = resp[8:].decode('ascii', 'ignore')

        if response_code == 0:
            self.authenticated = True
            self.init()
            return response_code, 'OK'
        else:
            if major == 4 or (major == 3 and minor >= 8):
                resp = socket_receive(self.sock, 4)

                msg_len = int.from_bytes(resp, byteorder="big")
                resp = socket_receive(self.sock, msg_len)

                msg = resp.decode("utf-8")
                return response_code, msg

            else:
                if response_code == 1:
                    return response_code, "failed"
                elif response_code == 2:
                    return response_code, "failed, too many attempts"
                else:
                    raise VNCException('Unknown response: %d' % (code))

    def gen_key(self, key):
        newkey = []
        for ki in range(len(key)):
            bsrc = ord(key[ki])
            btgt = 0
            for i in range(8):
                if bsrc & (1 << i):
                    btgt = btgt | (1 << 7-i)
            newkey.append(btgt)
        return bytes(newkey)

    def init(self):

        self.sock.sendall(b'\x01')

        resp = socket_receive(self.sock, 20)

        self.frame_width = int.from_bytes(resp[:2], "big")
        self.frame_height = int.from_bytes(resp[2:4], "big")

        resp = socket_receive(self.sock, 4)
        name_len = int.from_bytes(resp, "big")
        resp = socket_receive(self.sock, name_len)
        self.name = resp.decode()

        logging.info("Server name: %s" % self.name)

        # set pixel mode

        payload = b"\x00"
        payload += b"\x00\x00\x00" # Padding
        payload += (32).to_bytes(1, byteorder="big") # Pixel size
        payload += (24).to_bytes(1, byteorder="big") # Depth
        payload += (0).to_bytes(1, byteorder="big") # Big endian flag
        payload += (1).to_bytes(1, byteorder="big") # True color flag
        payload += (255).to_bytes(2, byteorder="big") # Red maximum
        payload += (255).to_bytes(2, byteorder="big") # Green maximum
        payload += (255).to_bytes(2, byteorder="big") # Blue maximum
        payload += (0).to_bytes(1, byteorder="big") # Red shift
        payload += (8).to_bytes(1, byteorder="big") # Green shift
        payload += (16).to_bytes(1, byteorder="big") # Blue shift
        payload += b"\x00\x00\x00" # Padding
        self.sock.sendall(payload)

        # set encoding

        payload = b"\x02"
        payload += b"\x00" # Padding
        payload += (1).to_bytes(2, byteorder="big") # Number encoding
        payload += (0).to_bytes(4, byteorder="big") # - Raw
        self.sock.sendall(payload)


    def typeSpecial(self, key_tuple):

        for key in key_tuple:

            # press all key in tuple
            keycode = getSpecialKeyCode(key)

            pressed_payload = b"\x04"
            pressed_payload += b"\x01"
            pressed_payload += b"\x00\x00"
            pressed_payload += bytes([0, 0, int((keycode/0x100)%0x100), int(keycode % 0x100)])
            self.sock.sendall(pressed_payload)

        for key in key_tuple:
            # release all key in tuple
            keycode = getSpecialKeyCode(key)

            release_payload = b"\x04"
            release_payload += b"\x00"
            release_payload += b"\x00\x00"
            release_payload += bytes([0, 0, int((keycode/0x100)%0x100), int(keycode % 0x100)])
            self.sock.sendall(release_payload)

    def typeString(self, message):

        for char in message:

            pressed_payload = b"\x04"
            pressed_payload += b"\x01"
            pressed_payload += b"\x00\x00"
            pressed_payload += bytes([0, 0, 0, ord(char)])

            self.sock.sendall(pressed_payload)

            release_payload = b"\x04"
            release_payload += b"\x00"
            release_payload += b"\x00\x00"
            release_payload += bytes([0, 0, 0, ord(char)])

            self.sock.sendall(release_payload)

    def screenshot(self):

        self.typeSpecial(("escape",))

        sleep(1)

        # get screenshot

        # Do it 2 times, sometimes 1st time is only a black screen
        for _ in range(2):
            screenshot = Image.new("RGBA", (self.frame_width, self.frame_height))

            draw = ImageDraw.Draw(screenshot)

            payload = b"\x03"
            payload += b"\x00" # Padding
            payload += (0).to_bytes(2, byteorder="big") # X offset
            payload += (0).to_bytes(2, byteorder="big") # Y offset
            payload += (self.frame_width).to_bytes(2, byteorder="big") # Width
            payload += (self.frame_height).to_bytes(2, byteorder="big") # Height
            self.sock.sendall(payload)

            res = socket_receive(self.sock, 4)
            rect_nb = int.from_bytes(res[2:4], byteorder="big")

            for _ in range(rect_nb):
                res = socket_receive(self.sock, 12)
                rect_x = int.from_bytes(res[:2], byteorder="big")
                rect_y = int.from_bytes(res[2:4], byteorder="big")
                rect_width = int.from_bytes(res[4:6], byteorder="big")
                rect_height = int.from_bytes(res[6:8], byteorder="big")
                encoding = int.from_bytes(res[8:12], byteorder="big")

                if encoding != 0:
                    raise VNCException("Unsupported encoding")

                res = socket_receive(self.sock, rect_width*rect_height*4)

                rect = Image.frombytes("RGBA", (rect_width, rect_height), res)

                screenshot.paste(rect, box=(rect_x, rect_y, rect_x+rect_width, rect_y+rect_height))

        return screenshot.convert('RGB')

    def disconnect(self):
        self.sock.close()

def security_type_from_id(sec_type_id):
    if sec_type_id == 0:
        return "Invalid"
    elif sec_type_id == 1:
        return "None"
    elif sec_type_id == 2:
        return "VNC Authentication"
    elif sec_type_id >= 3 and sec_type_id <= 15:
        return "RealVNC"
    elif sec_type_id == 16:
        return "Tight"
    elif sec_type_id == 17:
        return "Ultra"
    elif sec_type_id == 18:
        return "TLS"
    elif sec_type_id == 19:
        return "VeNCrypt"
    elif sec_type_id == 20:
        return "GTK-VNC SASL"
    elif sec_type_id == 21:
        return "MD5 hash authentication"
    elif sec_type_id == 22:
        return "Colin Dean xvp"
    elif sec_type_id == 23:
        return "Secure Tunnel"
    elif sec_type_id == 24:
        return "Integrated SSH"
    elif sec_type_id >= 25 and sec_type_id <= 29:
        return "Unassigned"
    elif sec_type_id >= 30 and sec_type_id <= 35:
        return "Apple Inc."
    elif sec_type_id >= 36 and sec_type_id <= 127:
        return "Unassigned"
    elif sec_type_id >= 128 and sec_type_id <= 255:
        return "RealVNC"

def getSpecialKeyCode(key):

    key_lower = key.lower()

    if key_lower in ["gui", "super", "windows"]:
        return key_codes["XK_Super_L"]
    if key_lower in ["alt"]:
        return key_codes["XK_Alt_L"]
    if key_lower in ["shift"]:
        return key_codes["XK_Shift_L"]
    if key_lower in ["control", "ctrl"]:
        return key_codes["XK_Control_L"]
    if key_lower in ["enter"]:
        return key_codes["XK_Return"]
    if key_lower in ["tab"]:
        return key_codes["XK_Tab"]
    if key_lower in ["backspace"]:
        return key_codes["XK_BackSpace"]
    if key_lower in ["clear"]:
        return key_codes["XK_Clear"]
    if key_lower in ["delete", "del"]:
        return key_codes["XK_Delete"]
    if key_lower in ["escape"]:
        return key_codes["XK_Escape"]
    if key_lower in ["space"]:
        return key_codes["XK_space"]
    if key_lower in ["downarrow", "down"]:
        return key_codes["XK_Down"]
    if key_lower in ["uparrow", "up"]:
        return key_codes["XK_Up"]
    elif len(key) == 1:
        return ord(key)
    else:
        return key_codes["XK_%s" % key]

