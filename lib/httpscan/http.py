import re
import requests
import traceback
from bs4 import BeautifulSoup
import urllib3
from urllib.parse import urljoin
import ssl
from requests.adapters import HTTPAdapter
from requests.auth import HTTPDigestAuth, HTTPBasicAuth
from requests.packages.urllib3.poolmanager import PoolManager
from requests.cookies import RequestsCookieJar

# Cert related imports
import idna
from socket import socket
from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID

urllib3.disable_warnings()

auth_pattern = re.compile(r'''\s*(.*)\s+realm=['"]?([^'"]+)['"]?''', re.IGNORECASE)

class HTTP:

    def __init__(self, method, hostname, port, useragent, proxy, connect_timeout, headers=None, auth=None, cookies={}, read_timeout=60):
        self.method = method
        self.hostname = hostname
        self.port = port
        self.connect_timeout = connect_timeout
        self.useragent = useragent
        self.proxy = proxy
        self.read_timeout = read_timeout
        self.headers = headers
        self.cookies = cookies

        if auth == None:
            self.auth = None
        elif type(auth) == tuple:
            self.auth = auth
        elif ':' in auth:
            self.auth = (auth.split(':', 1)[0], auth.split(':', 1)[-1])
        else:
            self.auth = None

    def url(self, path, params=None):
        if '://' in path:
            return path
        if self.method == 'http' and self.port == 80 or self.method == 'https' and self.port == 443:
            url = "%s://%s%s" % (self.method, self.hostname, path)
        else:
            url =  "%s://%s:%d%s" % (self.method, self.hostname, self.port, path)

        if params:
            url = "%s?%s" % (url, '&'.join(['%s=%s' % (k, v) for k, v in params.items()]))

        return url

    def get(self, path, params=None, data=None, ssl_version=ssl.PROTOCOL_TLS_CLIENT, auth=None, cookies={}, headers={}):

        response_data = self.request('GET', path, params=params, data=data, ssl_version=ssl_version, auth=auth, cookies=cookies, headers=headers)

        return response_data

    def put(self, path, data, ssl_version=ssl.PROTOCOL_TLS_CLIENT, auth=None, cookies={}, headers={}):
        response_data = self.request('PUT', path, ssl_version=ssl_version, data=data, auth=auth, cookies=cookies, headers=headers)

        return response_data

    def post(self, path, data, ssl_version=ssl.PROTOCOL_TLS_CLIENT, auth=None, cookies={}, headers={}):
        response_data = self.request('POST', path, ssl_version=ssl_version, data=data, auth=auth, cookies=cookies, headers=headers)

        return response_data

    def send_form(self, path, form, html=None, ssl_version=ssl.PROTOCOL_TLS_CLIENT, auth=None, cookies={}, headers={}):
        base_url = self.url(path)
        # extract base url if any
        if html != None:
            try:
                soup = BeautifulSoup(html, 'html.parser')
                base_url = urljoin(self.url(path), soup.find('base')['href'])
            except:
                pass

        method = 'GET'
        if 'method' in form:
            method = form['method']

        if 'action' in form:
            url = urljoin(base_url, form['action'])
        else:
            url = base_url

        return self.request(method, url, ssl_version=ssl_version, data=form['args'], auth=auth, cookies=cookies, headers=headers)

    def request(self, method, path, params=None, ssl_version=ssl.PROTOCOL_TLS_CLIENT, data=None, auth=None, cookies={}, recurse=6, headers={}):
        if auth == None and self.auth != None:
            auth = self.auth

        # add general cookies present in option
        for key, value in self.cookies.items():
            if type(cookies) == dict:
                if not key in cookies:
                    cookies[key] = value
            elif type(cookies) == RequestsCookieJar:
                if not key in cookies:
                    cookies.set(key, value)

        try:
            if not '://' in path:
                url = self.url(path)
            else:
                url = path

            if self.proxy:
                proxies = {
                    'http': self.proxy,
                    'https': self.proxy,
                }
            else:
                proxies = {}

            headers['User-Agent'] = self.useragent
            headers['Connection'] = 'close' # no need to keep the connection opened once we got our answer
            if self.headers != None:
                for key, value in self.headers.items():
                    headers[key] = value

            # TODO: if basic/digest not specified, make an initial request to get auth 
            r_auth = None
            if auth == None:
                pass
            elif len(auth) == 0:
                pass
            elif len(auth) == 2:
                # Get auth type
                res = self.request(method, path, params, ssl_version, data, (), cookies, recurse, headers)
                if not res:
                    return res
                if not 'auth_type' in res:
                    return res

                if res['auth_type'].lower() == 'basic':
                    r_auth = HTTPBasicAuth(auth[0], auth[1])
                elif res['auth_type'].lower() == 'digest':
                    r_auth = HTTPDigestAuth(auth[0], auth[1])
                else:
                    raise Exception('Unknown auth method: %s' % res['auth_type'])
            elif len(auth) == 3:
                if auth[0].lower() == 'basic':
                    r_auth = HTTPBasicAuth(auth[1], auth[2])
                elif auth[0].lower() == 'digest':
                    r_auth = HTTPDigestAuth(auth[1], auth[2])
                else:
                    raise Exception('Unknown auth method: %s' % auth[0])
            else:
                raise Exception('Unknown auth method: %s' % auth[0])

            with requests.Session() as session:
                if type(cookies) == dict:
                    cj = RequestsCookieJar()
                    for c in cookies:
                        cj.set(c, cookies[c])
                    cookies = cj
                if cookies != None:
                    session.cookies = cookies
                session.mount('https://', SSLAdapter(ssl_version))
                req = requests.Request(method, url, params=params, data=data, headers=headers, auth=r_auth, cookies=cookies)
                prepped = session.prepare_request(req)
                res = session.send(prepped,
                    stream=True,
                    verify=False,
                    proxies=proxies,
                    timeout=(self.connect_timeout, self.read_timeout),
                )
                response_data = self.parse_response(session, res)

        except requests.exceptions.ConnectTimeout:
            response_data = None
        except requests.exceptions.ConnectionError as e:
            response_data = None
        except requests.exceptions.ReadTimeout:
            response_data = None

        return response_data

    def get_cert_hostnames(self):
        if self.method != 'https':
            return None

        hostname_idna = idna.encode(self.hostname)

        sock = socket()

        sock.connect((self.hostname, self.port))
        peername = sock.getpeername()
        ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE

        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        sock_ssl.do_handshake()
        cert = sock_ssl.get_peer_certificate()
        try:
            cert = cert.to_cryptography()
        except ValueError:
            return []
        sock_ssl.close()
        sock.close()

        names = []
        try:
            name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            names.append(name[0].value)
        except x509.ExtensionNotFound:
            pass
        except IndexError:
            pass

        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names += ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        except ValueError:
            pass

        return list(set(names))

    def parse_response(self, session, res):
        code = res.status_code
        headers = res.headers

        server = headers['server'].strip() if 'server' in headers else 'N/A'
        content_type = headers['content-type'].strip() if 'content-type' in headers else None

        encoding = 'utf-8'
        if content_type:
            if 'charset=' in content_type:
                encoding = content_type.split('charset=')[-1]
            content_type = content_type.split(';')[0]

        html = ""
        max_size = 1024*1000
        try:
            for chunk in res.iter_content(chunk_size=1024, decode_unicode=True):
                if type(chunk) == bytes:
                    chunk = chunk.decode(encoding, 'replace')
                html += chunk
                if len(html) >= max_size:
                    break
        except requests.exceptions.ChunkedEncodingError:
            pass
        except LookupError:
            pass

        auth_type = None
        if code == 401:
            try:
                m = auth_pattern.match(headers["WWW-Authenticate"])
            except KeyError:
                m = None
            if not m:
                title = 'N/A'
            else:
                title = m.group(2)
                auth_type = m.group(1)
        else:
            title = self.parse_title(html)

        forms = self.parse_forms(html)

        out = {
            'code': code,
            'server': server,
            'title': title,
            'html': html,
            'headers': headers,
            #'cookies': res.cookies,
            'cookies': session.cookies,
            'forms': forms,
            'response_url': res.url,
        }
        if content_type != None:
            out['content-type'] = content_type
        else:
            out['content-type'] = None
        if auth_type != None:
            out['auth_type'] = auth_type

        return out

    def parse_title(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.find('title')

        if title != None and title.string != None:
            return title.string.strip()
        else:

            return 'N/A'

    def parse_forms(self, html):
        soup = BeautifulSoup(html, 'html.parser')

        forms = []
        for f in soup.findAll("form"):
            form = {'args': {}}

            try:
                form['action'] = f['action']
            except:
                pass

            try:
                form['method'] = f['method']
            except:
                pass

            try:
                form['name'] = f['name']
            except:
                pass

            try:
                form['id'] = f['id']
            except:
                pass

            for i in f.findAll('input'):
                try:
                    form['args'][i['name']] = i['value']
                except KeyError:
                    try:
                        form['args'][i['name']] = None
                    except KeyError:
                        pass

            forms.append(form)

        return forms

class SSLAdapter(HTTPAdapter):
    '''An HTTPS Transport Adapter that uses an arbitrary SSL version.'''
    def __init__(self, ssl_version=None, **kwargs):
        self.ssl_version = ssl_version

        super(SSLAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        ssl_context = ssl.create_default_context()
        ssl_context.options &= ~ssl.OP_NO_TLSv1_3 & ~ssl.OP_NO_TLSv1_2 & ~ssl.OP_NO_TLSv1_1
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1
        ssl_context.check_hostname = False
        ssl_context.set_ciphers('DEFAULT@SECLEVEL=1')
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=self.ssl_version,
                                       ssl_context=ssl_context)
