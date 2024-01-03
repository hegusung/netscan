from datetime import datetime
from impacket.ldap.ldaptypes import LDAP_SID
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
#from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
#from cryptography.hazmat.backends.openssl.dsa import _DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePublicKey

from lib.adscan.accesscontrol import parse_accesscontrol, parse_sd, process_sid

class ADCS:
    # https://www.pkisolutions.com/object-identifiers-oid-in-pki/
    oid_map = {
        "1.3.6.1.4.1.311.76.6.1": "Windows Update",
        "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
        "1.3.6.1.4.1.311.10.3.25": "Windows Third Party Application Component",
        "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
        "1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification",
        "1.3.6.1.4.1.311.61.4.1": "Early Launch Antimalware Drive",
        "1.3.6.1.4.1.311.10.3.23": "Windows TCB Component",
        "1.3.6.1.4.1.311.61.1.1": "Kernel Mode Code Signing",
        "1.3.6.1.4.1.311.10.3.26": "Windows Software Extension Verification",
        "2.23.133.8.3": "Attestation Identity Key Certificate",
        "1.3.6.1.4.1.311.76.3.1": "Windows Store",
        "1.3.6.1.4.1.311.10.6.1": "Key Pack Licenses",
        "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
        "1.3.6.1.5.2.3.5": "KDC Authentication",
        "1.3.6.1.5.5.7.3.7": "IP security use",
        "1.3.6.1.4.1.311.10.3.8": "Embedded Windows System Component Verification",
        "1.3.6.1.4.1.311.10.3.20": "Windows Kits Component",
        "1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
        "1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
        "1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
        "1.3.6.1.4.1.311.10.3.39": "Windows Hardware Driver Extended Verification",
        "1.3.6.1.4.1.311.10.6.2": "License Server Verification",
        "1.3.6.1.4.1.311.10.3.5.1": "Windows Hardware Driver Attested Verification",
        "1.3.6.1.4.1.311.76.5.1": "Dynamic Code Generato",
        "1.3.6.1.5.5.7.3.8": "Time Stamping",
        "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
        "1.3.6.1.4.1.311.2.6.1": "SpcRelaxedPEMarkerCheck",
        "2.23.133.8.1": "Endorsement Key Certificate",
        "1.3.6.1.4.1.311.2.6.2": "SpcEncryptedDigestRetryCount",
        "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
        "1.3.6.1.5.5.7.3.1": "Server Authentication",
        "1.3.6.1.4.1.311.61.5.1": "HAL Extension",
        "1.3.6.1.5.5.7.3.4": "Secure Email",
        "1.3.6.1.5.5.7.3.5": "IP security end system",
        "1.3.6.1.4.1.311.10.3.9": "Root List Signe",
        "1.3.6.1.4.1.311.10.3.30": "Disallowed List",
        "1.3.6.1.4.1.311.10.3.19": "Revoked List Signe",
        "1.3.6.1.4.1.311.10.3.21": "Windows RT Verification",
        "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
        "1.3.6.1.4.1.311.10.3.12": "Document Signing",
        "1.3.6.1.4.1.311.10.3.24": "Protected Process Verification",
        "1.3.6.1.4.1.311.80.1": "Document Encryption",
        "1.3.6.1.4.1.311.10.3.22": "Protected Process Light Verification",
        "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
        "1.3.6.1.4.1.311.21.5": "Private Key Archival",
        "1.3.6.1.4.1.311.10.5.1": "Digital Rights",
        "1.3.6.1.4.1.311.10.3.27": "Preview Build Signing",
        "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
        "2.23.133.8.2": "Platform Certificate",
        "1.3.6.1.4.1.311.20.1": "CTL Usage",
        "1.3.6.1.5.5.7.3.9": "OCSP Signing",
        "1.3.6.1.5.5.7.3.3": "Code Signing",
        "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
        "1.3.6.1.4.1.311.10.3.2": "Microsoft Time Stamping",
        "1.3.6.1.4.1.311.76.8.1": "Microsoft Publishe",
        "1.3.6.1.5.5.7.3.2": "Client Authentication",
        "1.3.6.1.5.2.3.4": "PKIINIT Client Authentication",
        "1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
        "2.5.29.37.0": "Any Purpose",
        "1.3.6.1.4.1.311.64.1.1": "Server Trust",
        "1.3.6.1.4.1.311.10.3.7": "OEM Windows System Component Verification",
    }

    certificate_name_flag_map = {
        0x1: 'ENROLLEE_SUPPLIES_SUBJECT',
        0x2: 'ADD_EMAIL',
        0x4: 'ADD_OBJ_GUID',
        0x8: 'OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME',
        0x100: 'ADD_DIRECTORY_PATH',
        0x10000: 'ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME',
        0x400000: 'SUBJECT_ALT_REQUIRE_DOMAIN_DNS',
        0x800000: 'SUBJECT_ALT_REQUIRE_SPN',
        0x1000000: 'SUBJECT_ALT_REQUIRE_DIRECTORY_GUID',
        0x2000000: 'SUBJECT_ALT_REQUIRE_UPN',
        0x4000000: 'SUBJECT_ALT_REQUIRE_EMAIL',
        0x8000000: 'SUBJECT_ALT_REQUIRE_DNS',
        0x10000000: 'SUBJECT_REQUIRE_DNS_AS_CN',
        0x20000000: 'SUBJECT_REQUIRE_EMAIL',
        0x40000000: 'SUBJECT_REQUIRE_COMMON_NAME',
        0x80000000: 'SUBJECT_REQUIRE_DIRECTORY_PATH',
    }

    enrollment_flag_map = {
        0x1: 'INCLUDE_SYMMETRIC_ALGORITHMS',
        0x2: 'PEND_ALL_REQUESTS',
        0x4: 'PUBLISH_TO_KRA_CONTAINER',
        0x8: 'PUBLISH_TO_DS',
        0x10: 'AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE',
        0x20: 'AUTO_ENROLLMENT',
        0x80: 'CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED',
        0x40: 'PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT',
        0x100: 'USER_INTERACTION_REQUIRED',
        0x200: 'ADD_TEMPLATE_NAME',
        0x400: 'REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE',
        0x800: 'ALLOW_ENROLL_ON_BEHALF_OF',
        0x1000: 'ADD_OCSP_NOCHECK',
        0x2000: 'ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL',
        0x4000: 'NOREVOCATIONINFOINISSUEDCERTS',
        0x8000: 'INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS',
        0x10000: 'ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT',
        0x20000: 'ISSUANCE_POLICIES_FROM_REQUEST',
        0x40000: 'SKIP_AUTO_RENEWAL',
    }


    @classmethod
    def list_adcs_servers(self, ldap):
        sbase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,%s" % ldap.configurationnamingcontext
        search_filter="(objectClass=pKIEnrollmentService)"
        attributes = ['distinguishedName', 'name', 'dNSHostName', 'certificateTemplates']

        for attr in ldap.query_generator(sbase, search_filter, attributes, query_sd=True):

            domain = ldap.dn_to_domain(str(attr['distinguishedName']))

            if 'certificateTemplates' in attr:
                if not type(attr['certificateTemplates']) == list:
                    attr['certificateTemplates'] = [attr['certificateTemplates']]

                templates = [str(t) for t in attr['certificateTemplates']]
            else:
                templates = []


            yield {
                'name': str(attr['name']),
                'domain': domain,
                'dns': str(attr['dNSHostName']),
                'templates': templates,
            }

    @classmethod
    def list_adcs_certs(self, ldap):
        sbase = 'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,%s' % ldap.configurationnamingcontext
        search_filter = '(cn=*)'
        attributes = ['distinguishedName', 'cACertificate']

        for attr in ldap.query_generator(sbase, search_filter, attributes, query_sd=True):

            if type(attr['cACertificate']) != list:
                attr['cACertificate'] = [attr['cACertificate']]

            for cert_bytes in attr['cACertificate']:
                cert_bytes = bytes(cert_bytes)
                cert = x509.load_der_x509_certificate(cert_bytes)

                common_names = [cn.value for cn in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)]

                public_key = cert.public_key()
                if type(public_key) in [RSAPublicKey, _RSAPublicKey]:
                    cert_algo = "RSA %d" % public_key.key_size
                    #elif type(public_key) in [DSAPublicKey, _DSAPublicKey]:
                    #cert_algo = "DSA %d" % public_key.key_size
                elif type(public_key) in [EllipticCurvePublicKey, _EllipticCurvePublicKey]:
                    cert_algo = "EC %d" % public_key.key_size
                else:
                    cert_algo = "Unknown: %s" % type(public_key)

                yield {
                    'algo': cert_algo,
                    'common_names': common_names,
                }

    @classmethod
    def list_adcs_templates(self, ldap):
        sbase = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,%s' % ldap.configurationnamingcontext
        search_filter = '(objectClass=pKICertificateTemplate)'
        attributes = ['distinguishedName', 'name', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'nTSecurityDescriptor']

        for attr in ldap.query_generator(sbase, search_filter, attributes, query_sd=True):

            name = str(attr['name'])

            eku = []
            if 'pKIExtendedKeyUsage' in attr:
                if type(attr['pKIExtendedKeyUsage']) != list:
                    attr['pKIExtendedKeyUsage'] = [attr['pKIExtendedKeyUsage']]

                for oid in attr['pKIExtendedKeyUsage']:
                    if str(oid) in self.oid_map:
                        eku.append(self.oid_map[str(oid)])
                    else:
                        eku.append(str(oid))

            cert_name_flag = []
            if 'msPKI-Certificate-Name-Flag' in attr:
                for val, n in self.certificate_name_flag_map.items():
                    if val & int(attr['msPKI-Certificate-Name-Flag']) == val:
                        cert_name_flag.append(n)

            enrollment_flag = []
            if 'msPKI-Enrollment-Flag' in attr:
                for val, n in self.enrollment_flag_map.items():
                    if val & int(attr['msPKI-Enrollment-Flag']) == val:
                        enrollment_flag.append(n)

            authorized_signature_required = False
            if 'msPKI-RA-Signature' in attr:
                if int(attr['msPKI-RA-Signature']) > 0:
                    authorized_signature_required = True

            enrollment_rights = []
            privileges = []
            if 'nTSecurityDescriptor' in attr:
                sd = bytes(attr['nTSecurityDescriptor'])
            else:
                return

            for ace in parse_accesscontrol(sd, (ldap.conn, ldap.defaultdomainnamingcontext)):
                ace['target'] = name
                if 'Certificate-Enrollment' in ace['rights']:
                    if ace['type'] == 'ALLOWED':
                        enrollment_rights.append(ace)

                    continue

                if 'guid' in ace:
                    ace['parameter'] = ldap.resolve_guid(ace['guid'])

                privileges.append(ace)

            yield {
                'name': name,
                'eku': eku, 
                'cert_name_flag': cert_name_flag,
                'enrollment_flag': enrollment_flag,
                'enrollment_rights': enrollment_rights,
                'authorized_signature_required': authorized_signature_required,
                'privileges': privileges,
            }


"""
    # ====================
    # === Trust object ===
    # ====================

    def __init__(self, ldap, attr):
        self.domain = str(attr['name'])

        attr['trustDirection'] = int(str(attr['trustDirection']))
        if attr['trustDirection'] == 0:
            self.direction = 'Disabled'
        elif attr['trustDirection'] == 1:
            self.direction = 'Incoming'
        elif attr['trustDirection'] == 2:
            self.direction = 'Outgoing'
        elif attr['trustDirection'] == 3:
            self.direction = 'Bidirectional'
        else:
            self.direction = 'Unknown'

        attr['trustType'] = int(str(attr['trustType']))
        if attr['trustType'] == 1:
            self.trust_type = 'Windows NT'
        elif attr['trustType'] == 2:
            self.trust_type = 'Active Directory'
        elif attr['trustType'] == 3:
            self.trust_type = 'MIT/KRB realm trust'
        else:
            self.trust_type = 'Unknown'

        self.tags = []
        attr['trustAttributes'] = int(str(attr['trustAttributes']))
        if attr['trustAttributes'] & 1 != 0:
            self.tags.append('Non-Transitive')
        if attr['trustAttributes'] & 2 != 0:
            self.tags.append('Uplevel clients only (Windows 2000 or newer)')
        if attr['trustAttributes'] & 4 != 0:
            self.tags.append('Quarantined Domain (External)')
        if attr['trustAttributes'] & 8 != 0:
            self.tags.append('Forest Trust')
        if attr['trustAttributes'] & 16 != 0:
            self.tags.append('Cross-Organizational Trust (Selective Authentication)')
        if attr['trustAttributes'] & 32 != 0:
            self.tags.append('Intra-Forest Trust (trust within the forest)')
        if attr['trustAttributes'] & 64 != 0:
            self.tags.append('Inter-Forest Trust (trust with another forest)')

    def to_json(self):
        return {
            'domain': self.domain,
            'direction': self.direction,
            'type': self.trust_type,
            'tags': self.tags,
        }
"""
