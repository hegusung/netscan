from datetime import datetime
from impacket.ldap.ldaptypes import LDAP_SID
from lib.adscan.accesscontrol import parse_sd, process_sid
from lib.adscan.ou import OU
from lib.adscan.gpo import GPO

import hashlib
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

class CertificateTemplate:
    attributes = ['distinguishedName', 'name', 'displayName', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'nTSecurityDescriptor', 'description', 'whenCreated', 'objectGUID', 'msPKI-RA-Application-Policies', 'msPKI-Certificate-Application-Policy', 'msPKI-RA-Policies', 'msPKI-Cert-Template-OID', 'msPKI-Template-Schema-Version', 'pKIExpirationPeriod', 'pKIOverlapPeriod']
    schema_guid_attributes = ['PKI-Certificate-Template', 'ms-PKI-Certificate-Name-Flag', 'ms-PKI-Enrollment-Flag']

    @classmethod
    def list_certificate_templates(self, ldap):
        schema_guid_dict = ldap._get_schema_guid_dict(self.schema_guid_attributes)
        sbase = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,%s' % ldap.configurationnamingcontext
        search_filter = '(objectClass=pKICertificateTemplate)'

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            certificate_template = CertificateTemplate(ldap, attr, schema_guid_dict)

            yield certificate_template


    # ==========================================
    # ====== Certificate Template object =======
    # ==========================================

    def __init__(self, ldap, attr, schema_guid_dict):

        self.domain = ldap.dn_to_domain(str(attr['distinguishedName']))
        self.name = str(attr['name'])
        self.displayname = str(attr['displayName'])
        self.description = str(attr['description']) if 'description' in attr else ''
        self.dn = str(attr['distinguishedName'])
        self.guid = ldap.parse_guid(bytes(attr['objectGUID']))

        try:
            self.created_date = datetime.strptime(str(attr['whenCreated']), '%Y%m%d%H%M%S.0Z') 
        except KeyError:
            self.created_date = None

        # Check the ACEs
        try:
            self.aces = parse_sd(bytes(attr['nTSecurityDescriptor']), self.domain.upper(), 'pKICertificateTemplate', schema_guid_dict)
        except KeyError:
            self.aces = {}

        self.eku = []
        if 'pKIExtendedKeyUsage' in attr:
            if type(attr['pKIExtendedKeyUsage']) != list:
                attr['pKIExtendedKeyUsage'] = [attr['pKIExtendedKeyUsage']]

            for oid in attr['pKIExtendedKeyUsage']:
                self.eku.append(str(oid))


        self.cert_name_flag = []
        if 'msPKI-Certificate-Name-Flag' in attr:
            for val, n in self.certificate_name_flag_map.items():
                if val & int(attr['msPKI-Certificate-Name-Flag']) == val:
                    self.cert_name_flag.append(n)
        #self.enrolleesuppliessubject = 'ENROLLEE_SUPPLIES_SUBJECT' in self.cert_name_flag
        #self.subjectaltrequireupn = 'SUBJECT_ALT_REQUIRE_UPN' in self.cert_name_flag

        self.enrollment_flag = []
        if 'msPKI-Enrollment-Flag' in attr:
            for val, n in self.enrollment_flag_map.items():
                if val & int(attr['msPKI-Enrollment-Flag']) == val:
                    self.enrollment_flag.append(n)
        #self.requiresmanagerapproval = 'PEND_ALL_REQUESTS' in self.enrollment_flag
        #self.nosecurityextension = 'NO_SECURITY_EXTENSION' in self.enrollment_flag

        self.authorizedsignature = 0
        if 'msPKI-RA-Signature' in attr:
            self.authorizedsignature = int(attr['msPKI-RA-Signature'])

        self.applicationpolicies = []
        if 'msPKI-Certificate-Application-Policy' in attr:
            if type(attr['msPKI-Certificate-Application-Policy']) != list:
                attr['msPKI-Certificate-Application-Policy'] = [attr['msPKI-Certificate-Application-Policy']]

            for item in attr['msPKI-Certificate-Application-Policy']:
               self.applicationpolicies.append(str(item))

        self.certificateapplicationpolicy = []
        if 'msPKI-Certificate-Application-Policy' in attr:
            if type(attr['msPKI-Certificate-Application-Policy']) != list:
                attr['msPKI-Certificate-Application-Policy'] = [attr['msPKI-Certificate-Application-Policy']]

            for item in attr['msPKI-Certificate-Application-Policy']:
               self.certificateapplicationpolicy.append(str(item))

        self.issuancepolicies = []
        if 'msPKI-RA-Policies' in attr:
            if type(attr['msPKI-RA-Policies']) != list:
                attr['msPKI-RA-Policies'] = [attr['msPKI-RA-Policies']]

            for item in attr['msPKI-RA-Policies']:
               self.issuancepolicies.append(str(item))

        self.oid = str(attr['msPKI-Cert-Template-OID'])

        self.schemaversion = int(attr['msPKI-Template-Schema-Version']) if 'msPKI-Template-Schema-Version' in attr else 0

        self.validityperiod = humanize_pki_period(bytes(attr['pKIExpirationPeriod']))
        self.renewalperiod = humanize_pki_period(bytes(attr['pKIOverlapPeriod']))

        if self.schemaversion == 1 and len(self.eku) > 0:
            self.effectiveekus = self.eku
        else:
            self.effectiveekus = self.certificateapplicationpolicy


    def to_json(self):
        return {
            'domain': self.domain,
            'name': self.name,
            'displayname': self.displayname,
            'created_date': self.created_date,
            'description': self.description,
            'dn': self.dn,
            'guid': self.guid,
            'aces': self.aces,
            'validityperiod': self.validityperiod,
            'renewalperiod': self.renewalperiod,
            'schemaversion': self.schemaversion,
            'oid': self.oid,
            'enrollment_flag': self.enrollment_flag,
            'cert_name_flag': self.cert_name_flag,
            'eku': self.eku, 
            'certificateapplicationpolicy': self.certificateapplicationpolicy,
            'authorizedsignature': self.authorizedsignature,
            'applicationpolicies': self.applicationpolicies,
            'issuancepolicies': self.issuancepolicies,
            'effectiveekus': self.effectiveekus,
            'authenticationenabled': any(auth_oid in self.effectiveekus for auth_oid in self.authentication_oids)

            #'enrollment_rights': self.enrollment_rights,
            #'authorized_signature_required': self.authorized_signature_required,
            #'privileges': self.privileges,
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

    authentication_oids = [
            "1.3.6.1.5.5.7.3.2",  # ClientAuthentication,
            "1.3.6.1.5.2.3.4", # PKINITClientAuthentication
            "1.3.6.1.4.1.311.20.2.2", # SmartcardLogon
            "2.5.29.37.0", # AnyPurpose
    ]

from typing import Union

def _to_int(v: Union[int, str, bytes, bytearray]) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, (bytes, bytearray)):
        # pKIExpirationPeriod is a 64-bit signed little-endian LARGE_INTEGER
        if len(v) >= 8:
            return int.from_bytes(v[:8], byteorder="little", signed=True)
        # Fallback: treat short bytes as an ASCII integer
        return int(v.decode("ascii").strip())
    return int(str(v).strip())

def _plural(n: int, unit: str) -> str:
    return f"{n} {unit}" + ("" if n == 1 else "s")

def humanize_pki_period(pki_expiration_period: Union[int, str, bytes]) -> str:
    """
    Convert AD CS pKIExpirationPeriod (LargeInteger in 100ns ticks, usually negative)
    into a human-readable duration string like '1 year' or '6 weeks'.
    """
    ticks = abs(_to_int(pki_expiration_period))  # value is typically negative
    total_seconds = ticks / 10_000_000  # 100ns -> seconds

    # Choose the most natural single unit
    # (approximate: years=365d, months=30d)
    minute = 60
    hour = 60 * minute
    day = 24 * hour
    week = 7 * day
    month = 30 * day
    year = 365 * day

    if total_seconds == 0:
        return "0 seconds"

    if total_seconds >= year:
        n = round(total_seconds / year)
        return _plural(n, "year")
    if total_seconds >= month:
        n = round(total_seconds / month)
        return _plural(n, "month")
    if total_seconds >= week:
        n = round(total_seconds / week)
        return _plural(n, "week")
    if total_seconds >= day:
        n = round(total_seconds / day)
        return _plural(n, "day")
    if total_seconds >= hour:
        n = round(total_seconds / hour)
        return _plural(n, "hour")
    if total_seconds >= minute:
        n = round(total_seconds / minute)
        return _plural(n, "minute")
    else:
        n = round(total_seconds)
        return _plural(n, "second")
