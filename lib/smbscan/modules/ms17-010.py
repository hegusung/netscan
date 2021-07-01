import os.path
from urllib.parse import urljoin
from ctypes import *
import socket
import struct
import logging

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds

# source: https://gist.github.com/mdawsonuk/caac9ec724abe4e70277c6a2478629

class Module:
    name = 'MS17-010'
    description = 'Check for MS17-010 (EternalBlue)'

    def run(self, target, args, timeout):
        vulnerable = check(target['hostname'], target['port'], timeout)

        if vulnerable:
            Output.vuln({'target': 'smb://%s:%d' % (target['hostname'], target['port']), 'message': 'Vulnerable to MS17-010 (EternalBlue)'})

            vuln_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'service': 'smb',
                'url': 'smb://%s:%d' % (target['hostname'], target['port']),
                'name': 'MS17-010 (EternalBlue)',
                'description': 'Server smb://%s:%d is vulnerable to MS17-010 (EternalBlue)' % (target['hostname'], target['port']),
            }
            DB.insert_vulnerability(vuln_info)

class SMB_HEADER(Structure):
  """SMB Header decoder.
  """

  _pack_ = 1  # Alignment

  _fields_ = [
    ("server_component", c_uint32),
    ("smb_command", c_uint8),
    ("error_class", c_uint8),
    ("reserved1", c_uint8),
    ("error_code", c_uint16),
    ("flags", c_uint8),
    ("flags2", c_uint16),
    ("process_id_high", c_uint16),
    ("signature", c_uint64),
    ("reserved2", c_uint16),
    ("tree_id", c_uint16),
    ("process_id", c_uint16),
    ("user_id", c_uint16),
    ("multiplex_id", c_uint16)
  ]

  def __new__(self, buffer=None):
    return self.from_buffer_copy(buffer)

  def __init__(self, buffer):
      pass


def generate_smb_proto_payload(*protos):
    """Generate SMB Protocol. Pakcet protos in order.
    """
    hexdata = []
    for proto in protos:
        hexdata.extend(proto)
    return b"".join(hexdata)


def calculate_doublepulsar_xor_key(s):
    """Calaculate Doublepulsar Xor Key
    """
    x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)))
    x = x & 0xffffffff  # this line was added just to truncate to 32 bits
    return x


def negotiate_proto_request():
    """Generate a negotiate_proto_request packet.
    """
    netbios = [
      b'\x00',              # 'Message_Type'
      b'\x00\x00\x54'       # 'Length'
    ]

    smb_header = [
      b'\xFF\x53\x4D\x42',  # 'server_component': .SMB
      b'\x72',              # 'smb_command': Negotiate Protocol
      b'\x00\x00\x00\x00',  # 'nt_status'
      b'\x18',              # 'flags'
      b'\x01\x28',          # 'flags2'
      b'\x00\x00',          # 'process_id_high'
      b'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      b'\x00\x00',          # 'reserved'
      b'\x00\x00',          # 'tree_id'
      b'\x2F\x4B',          # 'process_id'
      b'\x00\x00',          # 'user_id'
      b'\xC5\x5E'           # 'multiplex_id'
    ]

    negotiate_proto_request = [
      b'\x00',              # 'word_count'
      b'\x31\x00',          # 'byte_count'

      # Requested Dialects
      b'\x02',              # 'dialet_buffer_format'
      b'\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00',   # 'dialet_name': LANMAN1.0

      b'\x02',              # 'dialet_buffer_format'
      b'\x4C\x4D\x31\x2E\x32\x58\x30\x30\x32\x00',   # 'dialet_name': LM1.2X002

      b'\x02',              # 'dialet_buffer_format'
      b'\x4E\x54\x20\x4C\x41\x4E\x4D\x41\x4E\x20\x31\x2E\x30\x00',  # 'dialet_name3': NT LANMAN 1.0

      b'\x02',              # 'dialet_buffer_format'
      b'\x4E\x54\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00'   # 'dialet_name4': NT LM 0.12
    ]

    return generate_smb_proto_payload(netbios, smb_header, negotiate_proto_request)


def session_setup_andx_request():
    """Generate session setuo andx request.
    """
    netbios = [
      b'\x00',              # 'Message_Type'
      b'\x00\x00\x63'       # 'Length'
    ]

    smb_header = [
      b'\xFF\x53\x4D\x42',  # 'server_component': .SMB
      b'\x73',              # 'smb_command': Session Setup AndX
      b'\x00\x00\x00\x00',  # 'nt_status'
      b'\x18',              # 'flags'
      b'\x01\x20',          # 'flags2'
      b'\x00\x00',          # 'process_id_high'
      b'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      b'\x00\x00',          # 'reserved'
      b'\x00\x00',          # 'tree_id'
      b'\x2F\x4B',          # 'process_id'
      b'\x00\x00',          # 'user_id'
      b'\xC5\x5E'           # 'multiplex_id'
    ]

    session_setup_andx_request = [
      b'\x0D',              # Word Count
      b'\xFF',              # AndXCommand: No further command
      b'\x00',              # Reserved
      b'\x00\x00',          # AndXOffset
      b'\xDF\xFF',          # Max Buffer
      b'\x02\x00',          # Max Mpx Count
      b'\x01\x00',          # VC Number
      b'\x00\x00\x00\x00',  # Session Key
      b'\x00\x00',          # ANSI Password Length
      b'\x00\x00',          # Unicode Password Length
      b'\x00\x00\x00\x00',  # Reserved
      b'\x40\x00\x00\x00',  # Capabilities
      b'\x26\x00',          # Byte Count
      b'\x00',              # Account
      b'\x2e\x00',          # Primary Domain
      b'\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00',    # Native OS: Windows 2000 2195
      b'\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00',        # Native OS: Windows 2000 5.0
    ]

    return generate_smb_proto_payload(netbios, smb_header, session_setup_andx_request)


def tree_connect_andx_request(ip, userid):
    """Generate tree connect andx request.
    """

    netbios = [
      b'\x00',              # 'Message_Type'
      b'\x00\x00\x47'       # 'Length'
    ]

    smb_header = [
      b'\xFF\x53\x4D\x42',  # 'server_component': .SMB
      b'\x75',              # 'smb_command': Tree Connect AndX
      b'\x00\x00\x00\x00',  # 'nt_status'
      b'\x18',              # 'flags'
      b'\x01\x20',          # 'flags2'
      b'\x00\x00',          # 'process_id_high'
      b'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      b'\x00\x00',          # 'reserved'
      b'\x00\x00',          # 'tree_id'
      b'\x2F\x4B',          # 'process_id'
      userid,              # 'user_id'
      b'\xC5\x5E'           # 'multiplex_id'
    ]

    ipc = "\\\\{}\IPC$\x00".format(ip)

    tree_connect_andx_request = [
      b'\x04',              # Word Count
      b'\xFF',              # AndXCommand: No further commands
      b'\x00',              # Reserved
      b'\x00\x00',          # AndXOffset
      b'\x00\x00',          # Flags
      b'\x01\x00',          # Password Length
      b'\x1A\x00',          # Byte Count
      b'\x00',              # Password
      ipc.encode(),        # \\xxx.xxx.xxx.xxx\IPC$
      b'\x3f\x3f\x3f\x3f\x3f\x00'   # Service
    ]

    length = len(b"".join(smb_header)) + len(b"".join(tree_connect_andx_request))
    # netbios[1] = '\x00' + struct.pack('>H', length)
    netbios[1] = struct.pack(">L", length)[-3:]

    return generate_smb_proto_payload(netbios, smb_header, tree_connect_andx_request)


def peeknamedpipe_request(treeid, processid, userid, multiplex_id):
    """Generate tran2 request
    """
    netbios = [
      b'\x00',              # 'Message_Type'
      b'\x00\x00\x4a'       # 'Length'
    ]

    smb_header = [
      b'\xFF\x53\x4D\x42',  # 'server_component': .SMB
      b'\x25',              # 'smb_command': Trans2
      b'\x00\x00\x00\x00',  # 'nt_status'
      b'\x18',              # 'flags'
      b'\x01\x28',          # 'flags2'
      b'\x00\x00',          # 'process_id_high'
      b'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      b'\x00\x00',          # 'reserved'
      treeid,
      processid,
      userid,
      multiplex_id
    ]

    tran_request = [
      b'\x10',              # Word Count
      b'\x00\x00',          # Total Parameter Count
      b'\x00\x00',          # Total Data Count
      b'\xff\xff',          # Max Parameter Count
      b'\xff\xff',          # Max Data Count
      b'\x00',              # Max Setup Count
      b'\x00',              # Reserved
      b'\x00\x00',          # Flags
      b'\x00\x00\x00\x00',  # Timeout: Return immediately
      b'\x00\x00',          # Reversed
      b'\x00\x00',          # Parameter Count
      b'\x4a\x00',          # Parameter Offset
      b'\x00\x00',          # Data Count
      b'\x4a\x00',          # Data Offset
      b'\x02',              # Setup Count
      b'\x00',              # Reversed
      b'\x23\x00',          # SMB Pipe Protocol: Function: PeekNamedPipe (0x0023)
      b'\x00\x00',          # SMB Pipe Protocol: FID
      b'\x07\x00',
      b'\x5c\x50\x49\x50\x45\x5c\x00'  # \PIPE\
    ]

    return generate_smb_proto_payload(netbios, smb_header, tran_request)


def trans2_request(treeid, processid, userid, multiplex_id):
    """Generate trans2 request.
    """
    netbios = [
      b'\x00',              # 'Message_Type'
      b'\x00\x00\x4f'       # 'Length'
    ]

    smb_header = [
      b'\xFF\x53\x4D\x42',  # 'server_component': .SMB
      b'\x32',              # 'smb_command': Trans2
      b'\x00\x00\x00\x00',  # 'nt_status'
      b'\x18',              # 'flags'
      b'\x07\xc0',          # 'flags2'
      b'\x00\x00',          # 'process_id_high'
      b'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      b'\x00\x00',          # 'reserved'
      treeid,
      processid,
      userid,
      multiplex_id
    ]

    trans2_request = [
      b'\x0f',              # Word Count
      b'\x0c\x00',          # Total Parameter Count
      b'\x00\x00',          # Total Data Count
      b'\x01\x00',          # Max Parameter Count
      b'\x00\x00',          # Max Data Count
      b'\x00',              # Max Setup Count
      b'\x00',              # Reserved
      b'\x00\x00',          # Flags
      b'\xa6\xd9\xa4\x00',  # Timeout: 3 hours, 3.622 seconds
      b'\x00\x00',          # Reversed
      b'\x0c\x00',          # Parameter Count
      b'\x42\x00',          # Parameter Offset
      b'\x00\x00',          # Data Count
      b'\x4e\x00',          # Data Offset
      b'\x01',              # Setup Count
      b'\x00',              # Reserved
      b'\x0e\x00',          # subcommand: SESSION_SETUP
      b'\x00\x00',          # Byte Count
      b'\x0c\x00' + b'\x00' * 12
    ]

    return generate_smb_proto_payload(netbios, smb_header, trans2_request)

def check(ip, port, timeout):
    """Check if MS17_010 SMB Vulnerability exists.
    """
    if True:
    #try:
        buffersize = 1024

        # Send smb request based on socket.
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect((ip, port))

        # SMB - Negotiate Protocol Request
        raw_proto = negotiate_proto_request()
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        # SMB - Session Setup AndX Request
        raw_proto = session_setup_andx_request()
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        netbios = tcp_response[:4]
        smb_header = tcp_response[4:36]   # SMB Header: 32 bytes
        smb = SMB_HEADER(smb_header)

        user_id = struct.pack('<H', smb.user_id)

        # parse native_os from Session Setup Andx Response
        session_setup_andx_response = tcp_response[36:]
        native_os = session_setup_andx_response[9:].split(b'\x00')[0]

        # SMB - Tree Connect AndX Request
        raw_proto = tree_connect_andx_request(ip, user_id)
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        netbios = tcp_response[:4]
        smb_header = tcp_response[4:36]   # SMB Header: 32 bytes
        smb = SMB_HEADER(smb_header)

        tree_id = struct.pack('<H', smb.tree_id)
        process_id = struct.pack('<H', smb.process_id)
        user_id = struct.pack('<H', smb.user_id)
        multiplex_id = struct.pack('<H', smb.multiplex_id)

        # SMB - PeekNamedPipe Request
        raw_proto = peeknamedpipe_request(tree_id, process_id, user_id, multiplex_id)
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        netbios = tcp_response[:4]
        smb_header = tcp_response[4:36]
        smb = SMB_HEADER(smb_header)

        # nt_status = smb_header[5:9]
        nt_status = struct.pack('BBH', smb.error_class, smb.reserved1, smb.error_code)

        # 0xC0000205 - STATUS_INSUFF_SERVER_RESOURCES - vulnerable
        # 0xC0000008 - STATUS_INVALID_HANDLE
        # 0xC0000022 - STATUS_ACCESS_DENIED

        vulnerable = False

        if nt_status == b'\x05\x02\x00\xc0':
            #log.info("[+] [{}] is likely VULNERABLE to MS17-010! ({})".format(ip, native_os.decode()))

            vulnerable = True

            """
            # vulnerable to MS17-010, check for DoublePulsar infection
            raw_proto = trans2_request(tree_id, process_id, user_id, multiplex_id)
            client.send(raw_proto)
            tcp_response = client.recv(buffersize)

            netbios = tcp_response[:4]
            smb_header = tcp_response[4:36]
            smb = SMB_HEADER(smb_header)

            if smb.multiplex_id == 0x0051:
              key = calculate_doublepulsar_xor_key(smb.signature)
              print("Host is likely INFECTED with DoublePulsar! - XOR Key: {}".format(key.decode()))
            """

        elif nt_status in (b'\x08\x00\x00\xc0', b'\x22\x00\x00\xc0'):
            vulnerable = False
            #log.info("[-] [{}] does NOT appear vulnerable".format(ip))
        else:
            vulnerable = False
            #log.info("[-] [{}] Unable to detect if this host is vulnerable".format(ip))

    #except Exception as err:
    #    log.error("[-] [{}] Exception: {}".format(ip, err))
    #finally:
        client.close()

        return vulnerable

## References

# https://blogs.technet.microsoft.com/msrc/2017/04/14/protecting-customers-and-evaluating-risk/
# https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_ms17_010
# https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/smb/smb_ms17_010.rb
# https://www.symantec.com/security_response/vulnerability.jsp?bid=96707
# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SMB2/[MS-SMB2]-151016.pdf
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365233(v=vs.85).aspx
# https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
# https://community.rapid7.com/community/metasploit/blog/2017/04/03/introducing-rubysmb-the-protocol-library-nobody-else-wanted-to-write
# https://msdn.microsoft.com/en-us/library/ee441741.aspx
# https://github.com/countercept/doublepulsar-detection-script/blob/master/detect_doublepulsar_smb.py
# http://stackoverflow.com/questions/38735421/packing-an-integer-number-to-3-bytes-in-python
# https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html
# https://github.com/worawit/MS17-010/blob/master/BUG.txt
