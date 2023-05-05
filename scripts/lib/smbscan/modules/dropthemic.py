import os.path
from urllib.parse import urljoin
from ctypes import *
import socket
import struct
import logging
import calendar
import time
import re

from utils.output import Output
from utils.db import DB

import impacket
from impacket import version
from impacket.examples.logger import ImpacketFormatter
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import *
from impacket.ntlm import AV_PAIRS, NTLMSSP_AV_TIME, NTLMSSP_AV_FLAGS, NTOWFv2, NTLMSSP_AV_TARGET_NAME, NTLMSSP_AV_HOSTNAME,USE_NTLMv2, hmac_md5

# source: https://github.com/fox-it/cve-2019-1040-scanner

class Module:
    name = 'DropTheMic'
    description = 'Check for DropTheMic (CVE-2019-1040) (not compatible with kerberos)'

    def run(self, target, args, creds, timeout):
        domain = creds['domain'] if 'domain' in creds else None
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None
        ntlm_hash = creds['hash'] if 'hash' in creds else ''

        if not user:
            Output.error({'target': 'smb://%s:%d' % (target['hostname'], target['port']), 'message': 'Module DropTheMic requires valid credentials'})
            return

        vulnerable = check(target['hostname'], target['port'], domain, user, password, ntlm_hash)

        if vulnerable:
            Output.vuln({'target': 'smb://%s:%d' % (target['hostname'], target['port']), 'message': 'Vulnerable to CVE-2019-1040 (DropTheMic)'})

            vuln_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'service': 'smb',
                'url': 'smb://%s:%d' % (target['hostname'], target['port']),
                'name': 'CVE-2019-1040 (DropTheMic)',
                'description': 'Server smb://%s:%d is vulnerable to CVE-2019-1040 (DropTheMic)' % (target['hostname'], target['port']),
            }
            DB.insert_vulnerability(vuln_info)

# Slightly modified version of impackets computeResponseNTLMv2
def mod_computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                              nthash='', use_ntlmv2=USE_NTLMv2, check=False):

    responseServerVersion = b'\x01'
    hiResponseServerVersion = b'\x01'
    responseKeyNT = NTOWFv2(user, password, domain, nthash)

    av_pairs = AV_PAIRS(serverName)
    av_pairs[NTLMSSP_AV_TARGET_NAME] = 'cifs/'.encode('utf-16le') + av_pairs[NTLMSSP_AV_HOSTNAME][1]
    if av_pairs[NTLMSSP_AV_TIME] is not None:
        aTime = av_pairs[NTLMSSP_AV_TIME][1]
    else:
        aTime = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000))
        av_pairs[NTLMSSP_AV_TIME] = aTime
    av_pairs[NTLMSSP_AV_FLAGS] = b'\x02' + b'\x00' * 3
    serverName = av_pairs.getData()

    temp = responseServerVersion + hiResponseServerVersion + b'\x00' * 6 + aTime + clientChallenge + b'\x00' * 4 + \
           serverName + b'\x00' * 4

    ntProofStr = hmac_md5(responseKeyNT, serverChallenge + temp)

    ntChallengeResponse = ntProofStr + temp
    lmChallengeResponse = hmac_md5(responseKeyNT, serverChallenge + clientChallenge) + clientChallenge
    sessionBaseKey = hmac_md5(responseKeyNT, ntProofStr)

    return ntChallengeResponse, lmChallengeResponse, sessionBaseKey

"""
orig_type1 = ntlm.getNTLMSSPType1
# Wrapper to remove signing flags
def mod_getNTLMSSPType1(workstation='', domain='', signingRequired = False, use_ntlmv2 = USE_NTLMv2):
    return orig_type1(workstation, domain, False, use_ntlmv2)
"""

def check(remote_host, port, domain, username, password, ntlm_hash):
    if ntlm_hash:
        lmhash, nthash = ntlm_hash.split(':')
    else:
        lmhash = ''
        nthash = ''

    try:
        smbClient = mod_SMBConnection(remote_host, remote_host, sess_port=int(port)) #, preferredDialect=SMB2_DIALECT_21
    except:
        return

    # This isn't really compatible.... with multithreading
    #ntlm.computeResponseNTLMv2 = mod_computeResponseNTLMv2
    try:
        smbClient.login(username, password, domain, lmhash, nthash)

        try:
            server_os = str(smbClient._SMBConnection.get_server_lanman())
        except:
            server_os = str(smbClient.getServerOS())

        # Needs to be a windows server
        if not server_os.startswith("Windows "):
            return False

        # smbserver.py and samba false positives
        if server_os in ["Windows 255.255 Build 65535", "Windows 6.1 Build 0"]:
            return False

        return True
    except SessionError as exc:
        if 'STATUS_INVALID_PARAMETER' in str(exc):
            pass
        else:
            Output.error('Unexpected Exception while authenticating to %s: %s' % (remote_host, exc))

        return False

    smbClient.close()

## Put the modified impacket functions/classes here so it does not affect the impacket library

from impacket import ntlm
from impacket.ntlm import *

def mod_computeResponse(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='', nthash='', use_ntlmv2=USE_NTLMv2):
    if use_ntlmv2:
        return mod_computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password,
                                     lmhash, nthash, use_ntlmv2=use_ntlmv2)
    else:
        return computeResponseNTLMv1(flags, serverChallenge, clientChallenge, serverName, domain, user, password,
                                     lmhash, nthash, use_ntlmv2=use_ntlmv2)

def mod_getNTLMSSPType3(type1, type2, user, password, domain, lmhash = '', nthash = '', use_ntlmv2 = USE_NTLMv2):

    # Safety check in case somebody sent password = None.. That's not allowed. Setting it to '' and hope for the best.
    if password is None:
        password = ''

    # Let's do some encoding checks before moving on. Kind of dirty, but found effective when dealing with
    # international characters.
    import sys
    encoding = sys.getfilesystemencoding()
    if encoding is not None:
        try:
            user.encode('utf-16le')
        except:
            user = user.decode(encoding)
        try:
            password.encode('utf-16le')
        except:
            password = password.decode(encoding)
        try:
            domain.encode('utf-16le')
        except:
            domain = user.decode(encoding)

    ntlmChallenge = NTLMAuthChallenge(type2)

    # Let's start with the original flags sent in the type1 message
    responseFlags = type1['flags']

    # Token received and parsed. Depending on the authentication 
    # method we will create a valid ChallengeResponse
    ntlmChallengeResponse = NTLMAuthChallengeResponse(user, password, ntlmChallenge['challenge'])

    clientChallenge = b("".join([random.choice(string.digits+string.ascii_letters) for _ in range(8)]))

    serverName = ntlmChallenge['TargetInfoFields']

    ntResponse, lmResponse, sessionBaseKey = mod_computeResponse(ntlmChallenge['flags'], ntlmChallenge['challenge'],
                                                             clientChallenge, serverName, domain, user, password,
                                                             lmhash, nthash, use_ntlmv2)

    # Let's check the return flags
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) == 0:
        # No extended session security, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_128 ) == 0:
        # No support for 128 key len, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_128
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH) == 0:
        # No key exchange supported, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_KEY_EXCH
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_SEAL) == 0:
        # No sign available, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_SEAL
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_SIGN) == 0:
        # No sign available, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_SIGN
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN) == 0:
        # No sign available, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_ALWAYS_SIGN

    keyExchangeKey = KXKEY(ntlmChallenge['flags'], sessionBaseKey, lmResponse, ntlmChallenge['challenge'], password,
                           lmhash, nthash, use_ntlmv2)

    # Special case for anonymous login
    if user == '' and password == '' and lmhash == '' and nthash == '':
      keyExchangeKey = b'\x00'*16

    # If we set up key exchange, let's fill the right variables
    if ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH:
       # not exactly what I call random tho :\
       # exportedSessionKey = this is the key we should use to sign
       exportedSessionKey = b("".join([random.choice(string.digits+string.ascii_letters) for _ in range(16)]))
       #exportedSessionKey = "A"*16
       #print "keyExchangeKey %r" % keyExchangeKey
       # Let's generate the right session key based on the challenge flags
       #if responseFlags & NTLMSSP_NTLM2_KEY:
           # Extended session security enabled
       #    if responseFlags & NTLMSSP_KEY_128:
               # Full key
       #        exportedSessionKey = exportedSessionKey
       #    elif responseFlags & NTLMSSP_KEY_56:
               # Only 56-bit key
       #        exportedSessionKey = exportedSessionKey[:7]
       #    else:
       #        exportedSessionKey = exportedSessionKey[:5]
       #elif responseFlags & NTLMSSP_KEY_56:
           # No extended session security, just 56 bits key
       #    exportedSessionKey = exportedSessionKey[:7] + '\xa0'
       #else:
       #    exportedSessionKey = exportedSessionKey[:5] + '\xe5\x38\xb0'

       encryptedRandomSessionKey = generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey)
    else:
       encryptedRandomSessionKey = None
       # [MS-NLMP] page 46
       exportedSessionKey        = keyExchangeKey

    ntlmChallengeResponse['flags'] = responseFlags
    ntlmChallengeResponse['domain_name'] = domain.encode('utf-16le')
    ntlmChallengeResponse['host_name'] = type1.getWorkstation().encode('utf-16le')
    if lmResponse == '':
        ntlmChallengeResponse['lanman'] = b'\x00'
    else:
        ntlmChallengeResponse['lanman'] = lmResponse
    ntlmChallengeResponse['ntlm'] = ntResponse
    if encryptedRandomSessionKey is not None: 
        ntlmChallengeResponse['session_key'] = encryptedRandomSessionKey

    return ntlmChallengeResponse, exportedSessionKey

from impacket.smbconnection import SMBConnection
from impacket import smb, smb3, nmb, nt_errors, LOG, crypto

class mod_SMBConnection(SMBConnection):

    def negotiateSession(self, preferredDialect=None,
                         flags1=smb.SMB.FLAGS1_PATHCASELESS | smb.SMB.FLAGS1_CANONICALIZED_PATHS,
                         flags2=smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES,
                         negoData='\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00'):
        """
        Perform protocol negotiation

        :param string preferredDialect: the dialect desired to talk with the target server. If None is specified the highest one available will be used
        :param string flags1: the SMB FLAGS capabilities
        :param string flags2: the SMB FLAGS2 capabilities
        :param string negoData: data to be sent as part of the nego handshake

        :return: True, raises a Session Error if error.
        """

        # If port 445 and the name sent is *SMBSERVER we're setting the name to the IP. This is to help some old
        # applications still believing
        # *SMSBSERVER will work against modern OSes. If port is NETBIOS_SESSION_PORT the user better know about i
        # *SMBSERVER's limitations
        if self._sess_port == nmb.SMB_SESSION_PORT and self._remoteName == '*SMBSERVER':
            self._remoteName = self._remoteHost
        elif self._sess_port == nmb.NETBIOS_SESSION_PORT and self._remoteName == '*SMBSERVER':
            # If remote name is *SMBSERVER let's try to query its name.. if can't be guessed, continue and hope for the best
            nb = nmb.NetBIOS()
            try:
                res = nb.getnetbiosname(self._remoteHost)
            except:
                pass
            else:
                self._remoteName = res

        if self._sess_port == nmb.NETBIOS_SESSION_PORT:
            negoData = '\x02NT LM 0.12\x00\x02SMB 2.002\x00'

        hostType = nmb.TYPE_SERVER
        if preferredDialect is None:
            # If no preferredDialect sent, we try the highest available one.
            packet = self.negotiateSessionWildcard(self._myName, self._remoteName, self._remoteHost, self._sess_port,
                                                   self._timeout, True, flags1=flags1, flags2=flags2, data=negoData)
            if packet[0:1] == b'\xfe':
                # Answer is SMB2 packet
                self._SMBConnection = mod_SMB3(self._remoteName, self._remoteHost, self._myName, hostType,
                                                self._sess_port, self._timeout, session=self._nmbSession,
                                                negSessionResponse=SMB2Packet(packet))
            else:
                # Answer is SMB packet, sticking to SMBv1
                self._SMBConnection = mod_SMB(self._remoteName, self._remoteHost, self._myName, hostType,
                                              self._sess_port, self._timeout, session=self._nmbSession,
                                              negPacket=packet)
        else:
            if preferredDialect == smb.SMB_DIALECT:
                self._SMBConnection = mod_SMB(self._remoteName, self._remoteHost, self._myName, hostType,
                                              self._sess_port, self._timeout)
            elif preferredDialect in [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, SMB2_DIALECT_311]:
                self._SMBConnection = mod_SMB3(self._remoteName, self._remoteHost, self._myName, hostType,
                                                self._sess_port, self._timeout, preferredDialect=preferredDialect)
            else:
                raise Exception("Unknown dialect %s")

        # propagate flags to the smb sub-object, except for Unicode (if server supports)
        # does not affect smb3 objects
        if isinstance(self._SMBConnection, smb.SMB):
            if self._SMBConnection.get_flags()[1] & smb.SMB.FLAGS2_UNICODE:
                flags2 |= smb.SMB.FLAGS2_UNICODE
            self._SMBConnection.set_flags(flags1=flags1, flags2=flags2)

        return True

from struct import unpack
from six import indexbytes, b
from binascii import a2b_hex
from impacket.smb3structs import *
from impacket.nt_errors import STATUS_SUCCESS, STATUS_MORE_PROCESSING_REQUIRED, STATUS_INVALID_PARAMETER, \
    STATUS_NO_MORE_FILES, STATUS_PENDING, STATUS_NOT_IMPLEMENTED, ERROR_MESSAGES
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp, ASN1_OID, asn1encode, ASN1_AID

class mod_SMB3(smb3.SMB3):

    def login(self, user, password, domain = '', lmhash = '', nthash = ''):
        # If we have hashes, normalize them
        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:     lmhash = '0%s' % lmhash
            if len(nthash) % 2:     nthash = '0%s' % nthash
            try: # just in case they were converted already
                lmhash = a2b_hex(lmhash)
                nthash = a2b_hex(nthash)
            except:
                pass

        self.__userName = user
        self.__password = password
        self.__domain   = domain
        self.__lmhash   = lmhash
        self.__nthash   = nthash
        self.__aesKey   = ''
        self.__TGT      = None
        self.__TGS      = None

        sessionSetup = SMB2SessionSetup()
        if self.RequireMessageSigning is True:
           sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_REQUIRED
        else:
           sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED

        sessionSetup['Flags'] = 0
        #sessionSetup['Capabilities'] = SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_LEASING | SMB2_GLOBAL_CAP_DFS

        # Let's build a NegTokenInit with the NTLMSSP
        # TODO: In the future we should be able to choose different providers

        blob = SPNEGO_NegTokenInit()

        # NTLMSSP
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        auth = ntlm.getNTLMSSPType1(self._Connection['ClientName'],domain, self._Connection['RequireSigning'])
        blob['MechToken'] = auth.getData()

        sessionSetup['SecurityBufferLength'] = len(blob)
        sessionSetup['Buffer']               = blob.getData()

        # ToDo:
        # If this authentication is for establishing an alternative channel for an existing Session, as specified
        # in section 3.2.4.1.7, the client MUST also set the following values:
        # The SessionId field in the SMB2 header MUST be set to the Session.SessionId for the new
        # channel being established.
        # The SMB2_SESSION_FLAG_BINDING bit MUST be set in the Flags field.
        # The PreviousSessionId field MUST be set to zero.

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data']    = sessionSetup

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if self._Connection['Dialect'] == SMB2_DIALECT_311:
            self.__UpdatePreAuthHash (ans.rawData)

        if ans.isValidAnswer(STATUS_MORE_PROCESSING_REQUIRED):
            self._Session['SessionID']       = ans['SessionID']
            self._Session['SigningRequired'] = self._Connection['RequireSigning']
            self._Session['UserCredentials'] = (user, password, domain, lmhash, nthash)
            self._Session['Connection']      = self._NetBIOSSession.get_socket()
            sessionSetupResponse = SMB2SessionSetup_Response(ans['Data'])
            respToken = SPNEGO_NegTokenResp(sessionSetupResponse['Buffer'])

            # Let's parse some data and keep it to ourselves in case it is asked
            ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])
            if ntlmChallenge['TargetInfoFields_len'] > 0:
                av_pairs = ntlm.AV_PAIRS(ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']])
                if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
                   try:
                       self._Session['ServerName'] = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
                   except:
                       # For some reason, we couldn't decode Unicode here.. silently discard the operation
                       pass
                if av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] is not None:
                   try:
                       if self._Session['ServerName'] != av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le'):
                           self._Session['ServerDomain'] = av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le')
                   except:
                       # For some reason, we couldn't decode Unicode here.. silently discard the operation
                       pass
                if av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] is not None:
                   try:
                       self._Session['ServerDNSDomainName'] = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1].decode('utf-16le')
                   except:
                       # For some reason, we couldn't decode Unicode here.. silently discard the operation
                       pass

                if av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] is not None:
                   try:
                       self._Session['ServerDNSHostName'] = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME][1].decode('utf-16le')
                   except:
                       # For some reason, we couldn't decode Unicode here.. silently discard the operation
                       pass

                if self._strict_hostname_validation:
                    self.perform_hostname_validation()

                # Parse Version to know the target Operating system name. Not provided elsewhere anymore
                if 'Version' in ntlmChallenge.fields:
                    version = ntlmChallenge['Version']

                    if len(version) >= 4:
                        self._Session['ServerOS'] = "Windows %d.%d Build %d" % (indexbytes(version,0), indexbytes(version,1), struct.unpack('<H',version[2:4])[0])
                        self._Session["ServerOSMajor"] = indexbytes(version,0)
                        self._Session["ServerOSMinor"] = indexbytes(version,1)
                        self._Session["ServerOSBuild"] = struct.unpack('<H',version[2:4])[0]

            type3, exportedSessionKey = mod_getNTLMSSPType3(auth, respToken['ResponseToken'], user, password, domain, lmhash, nthash)



            respToken2 = SPNEGO_NegTokenResp()
            respToken2['ResponseToken'] = type3.getData()

            # Reusing the previous structure
            sessionSetup['SecurityBufferLength'] = len(respToken2)
            sessionSetup['Buffer']               = respToken2.getData()

            packetID = self.sendSMB(packet)
            packet = self.recvSMB(packetID)

            # Let's calculate Key Materials before moving on
            if exportedSessionKey is not None:
                self._Session['SessionKey']  = exportedSessionKey
                if self._Session['SigningRequired'] is True and self._Connection['Dialect'] >= SMB2_DIALECT_30:
                    # If Connection.Dialect is "3.1.1", the case-sensitive ASCII string "SMBSigningKey" as the label;
                    # otherwise, the case - sensitive ASCII string "SMB2AESCMAC" as the label.
                    # If Connection.Dialect is "3.1.1", Session.PreauthIntegrityHashValue as the context; otherwise,
                    # the case-sensitive ASCII string "SmbSign" as context for the algorithm.
                    if self._Connection['Dialect'] == SMB2_DIALECT_311:
                        self._Session['SigningKey'] = crypto.KDF_CounterMode (exportedSessionKey,
                                                                              b"SMBSigningKey\x00",
                                                                              self._Session['PreauthIntegrityHashValue'],
                                                                              128)
                    else:
                        self._Session['SigningKey'] = crypto.KDF_CounterMode (exportedSessionKey, b"SMB2AESCMAC\x00",
                                                                              b"SmbSign\x00", 128)
            try:
                if packet.isValidAnswer(STATUS_SUCCESS):
                    sessionSetupResponse = SMB2SessionSetup_Response(packet['Data'])
                    self._Session['SessionFlags'] = sessionSetupResponse['SessionFlags']
                    self._Session['SessionID']    = packet['SessionID']

                    # Do not encrypt anonymous connections
                    if user == '' or self.isGuestSession():
                        self._Connection['SupportsEncryption'] = False

                    # Calculate the key derivations for dialect 3.0
                    if self._Session['SigningRequired'] is True:
                        self._Session['SigningActivated'] = True
                    if self._Connection['Dialect'] >= SMB2_DIALECT_30 and self._Connection['SupportsEncryption'] is True:
                        # SMB 3.0. Encryption available. Let's enforce it if we have AES CCM available
                        self._Session['SessionFlags'] |= SMB2_SESSION_FLAG_ENCRYPT_DATA
                        # Application Key
                        # If Connection.Dialect is "3.1.1",the case-sensitive ASCII string "SMBAppKey" as the label;
                        # otherwise, the case-sensitive ASCII string "SMB2APP" as the label. Session.PreauthIntegrityHashValue
                        # as the context; otherwise, the case-sensitive ASCII string "SmbRpc" as context for the algorithm.
                        # Encryption Key
                        # If Connection.Dialect is "3.1.1",the case-sensitive ASCII string "SMBC2SCipherKey" as # the label;
                        # otherwise, the case-sensitive ASCII string "SMB2AESCCM" as the label. Session.PreauthIntegrityHashValue
                        # as the context; otherwise, the case-sensitive ASCII string "ServerIn " as context for the algorithm
                        # (note the blank space at the end)
                        # Decryption Key
                        # If Connection.Dialect is "3.1.1", the case-sensitive ASCII string "SMBS2CCipherKey" as the label;
                        # otherwise, the case-sensitive ASCII string "SMB2AESCCM" as the label. Session.PreauthIntegrityHashValue
                        # as the context; otherwise, the case-sensitive ASCII string "ServerOut" as context for the algorithm.
                        if self._Connection['Dialect'] == SMB2_DIALECT_311:
                            self._Session['ApplicationKey']  = crypto.KDF_CounterMode(exportedSessionKey, b"SMBAppKey\x00",
                                                                             self._Session['PreauthIntegrityHashValue'], 128)
                            self._Session['EncryptionKey']   = crypto.KDF_CounterMode(exportedSessionKey, b"SMBC2SCipherKey\x00",
                                                                             self._Session['PreauthIntegrityHashValue'], 128)
                            self._Session['DecryptionKey'] = crypto.KDF_CounterMode (exportedSessionKey, b"SMBS2CCipherKey\x00",
                                                                             self._Session['PreauthIntegrityHashValue'], 128)

                        else:
                            self._Session['ApplicationKey'] = crypto.KDF_CounterMode (exportedSessionKey, b"SMB2APP\x00",
                                                                                      b"SmbRpc\x00", 128)
                            self._Session['EncryptionKey'] = crypto.KDF_CounterMode (exportedSessionKey, b"SMB2AESCCM\x00",
                                                                                     b"ServerIn \x00", 128)
                            self._Session['DecryptionKey'] = crypto.KDF_CounterMode (exportedSessionKey, b"SMB2AESCCM\x00",
                                                                                     b"ServerOut\x00", 128)
                    self._Session['CalculatePreAuthHash'] = False
                    return True
            except:
                # We clean the stuff we used in case we want to authenticate again
                # within the same connection
                self._Session['UserCredentials']   = ''
                self._Session['Connection']        = 0
                self._Session['SessionID']         = 0
                self._Session['SigningRequired']   = False
                self._Session['SigningKey']        = ''
                self._Session['SessionKey']        = ''
                self._Session['SigningActivated']  = False
                self._Session['CalculatePreAuthHash'] = False
                self._Session['PreauthIntegrityHashValue'] = a2b_hex(b'0'*128)
                raise

from impacket.smb import SMB

class mod_SMB(SMB):

    def login_extended(self, user, password, domain = '', lmhash = '', nthash = '', use_ntlmv2 = True ):

        from impacket.smb import NewSMBPacket, SMBCommand, SMBSessionSetupAndX_Extended_Parameters, SMBSessionSetupAndX_Extended_Data, SMBSessionSetupAndX_Extended_Response_Parameters, SMBSessionSetupAndX_Extended_Response_Data, SMBSessionSetupAndXResponse_Parameters
        from impacket.structure import Structure
        
        # login feature does not support unicode
        # disable it if enabled
        flags2 = self._SMB__flags2
        if flags2 & SMB.FLAGS2_UNICODE:
            self._SMB__flags2 = flags2 & (flags2 ^ SMB.FLAGS2_UNICODE)

        # Once everything's working we should join login methods into a single one
        smb = NewSMBPacket()
        # Are we required to sign SMB? If so we do it, if not we skip it
        if self._SignatureRequired:
           smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE

        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize']        = 61440
        sessionSetup['Parameters']['MaxMpxCount']          = 2
        sessionSetup['Parameters']['VcNumber']             = 1
        sessionSetup['Parameters']['SessionKey']           = 0
        sessionSetup['Parameters']['Capabilities']         = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE | SMB.CAP_LARGE_READX | SMB.CAP_LARGE_WRITEX


        # Let's build a NegTokenInit with the NTLMSSP
        # TODO: In the future we should be able to choose different providers

        blob = SPNEGO_NegTokenInit()

        # NTLMSSP
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        auth = ntlm.getNTLMSSPType1(self.get_client_name(),domain,self._SignatureRequired, use_ntlmv2 = use_ntlmv2)
        blob['MechToken'] = auth.getData()

        sessionSetup['Parameters']['SecurityBlobLength']  = len(blob)
        sessionSetup['Parameters'].getData()
        sessionSetup['Data']['SecurityBlob']       = blob.getData()

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS']      = 'Unix'
        sessionSetup['Data']['NativeLanMan']  = 'Samba'

        smb.addCommand(sessionSetup)
        self.sendSMB(smb)

        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX):
            # We will need to use this uid field for all future requests/responses
            self._uid = smb['Uid']

            # Now we have to extract the blob to continue the auth process
            sessionResponse   = SMBCommand(smb['Data'][0])
            sessionParameters = SMBSessionSetupAndX_Extended_Response_Parameters(sessionResponse['Parameters'])
            sessionData       = SMBSessionSetupAndX_Extended_Response_Data(flags = smb['Flags2'])
            sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
            sessionData.fromString(sessionResponse['Data'])
            respToken = SPNEGO_NegTokenResp(sessionData['SecurityBlob'])

            # Let's parse some data and keep it to ourselves in case it is asked
            ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])
            if ntlmChallenge['TargetInfoFields_len'] > 0:
                av_pairs = ntlm.AV_PAIRS(ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']])
                if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
                   try:
                       self.__server_name = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
                   except UnicodeDecodeError:
                       # For some reason, we couldn't decode Unicode here.. silently discard the operation
                       pass
                if av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] is not None:
                   try:
                       if self.__server_name != av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le'):
                           self.__server_domain = av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le')
                   except UnicodeDecodeError:
                       # For some reason, we couldn't decode Unicode here.. silently discard the operation
                       pass
                if av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] is not None:
                   try:
                       self.__server_dns_domain_name = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1].decode('utf-16le')
                   except UnicodeDecodeError:
                       # For some reason, we couldn't decode Unicode here.. silently discard the operation
                       pass

                if av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] is not None:
                   try:
                       self.__server_dns_host_name = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME][1].decode('utf-16le')
                   except UnicodeDecodeError:
                       # For some reason, we couldn't decode Unicode here.. silently discard the operation
                       pass

            if self._strict_hostname_validation:
                self.perform_hostname_validation()

            # Parse Version to know the target Operating system name. Not provided elsewhere anymore
            if 'Version' in ntlmChallenge.fields:
                version = ntlmChallenge['Version']

                if len(version) >= 4:
                   self.__server_os_major, self.__server_os_minor, self.__server_os_build = unpack('<BBH',version[:4])

            type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, respToken['ResponseToken'], user, password, domain, lmhash, nthash, use_ntlmv2 = use_ntlmv2)

            if exportedSessionKey is not None:
                self._SigningSessionKey = exportedSessionKey

            smb = NewSMBPacket()

            # Are we required to sign SMB? If so we do it, if not we skip it
            if self._SignatureRequired:
               smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE

            respToken2 = SPNEGO_NegTokenResp()
            respToken2['ResponseToken'] = type3.getData()

            # Reusing the previous structure
            sessionSetup['Parameters']['SecurityBlobLength'] = len(respToken2)
            sessionSetup['Data']['SecurityBlob'] = respToken2.getData()

            # Storing some info for later use
            self.__server_os     = sessionData['NativeOS']
            self.__server_lanman = sessionData['NativeLanMan']

            smb.addCommand(sessionSetup)
            self.sendSMB(smb)

            smb = self.recvSMB()
            self._uid = 0
            if smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX):
                self._uid = smb['Uid']
                sessionResponse   = SMBCommand(smb['Data'][0])
                sessionParameters = SMBSessionSetupAndXResponse_Parameters(sessionResponse['Parameters'])

                self._action = sessionParameters['Action']
                # If smb sign required, let's enable it for the rest of the connection
                if self._dialects_parameters['SecurityMode'] & SMB.SECURITY_SIGNATURES_REQUIRED:
                   self._SignSequenceNumber = 2
                   self._SignatureEnabled = True

                # restore unicode flag if needed
                if flags2 & SMB.FLAGS2_UNICODE:
                    self._SMB__flags2 |= SMB.FLAGS2_UNICODE

                return 1
        else:
            raise Exception('Error: Could not login successfully')


