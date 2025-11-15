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

class CA:
    attributes = ['name', 'distinguishedName', 'objectGUID', 'cACertificate', 'nTSecurityDescriptor', 'description', 'whenCreated', 'crossCertificatePair']
    schema_guid_attributes = ['Certification-Authority', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name']

    @classmethod
    def list_ntauthstores(self, ldap):
        schema_guid_dict = ldap._get_schema_guid_dict(self.schema_guid_attributes)
        sbase = 'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,%s' % ldap.configurationnamingcontext
        search_filter = '(cn=*)'

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            ca = CA(ldap, attr, schema_guid_dict)

            yield ca

    @classmethod
    def list_rootcas(self, ldap):
        schema_guid_dict = ldap._get_schema_guid_dict(self.schema_guid_attributes)
        sbase = 'CN=Certification Authorities,CN=Public Key Services,CN=Services,%s' % ldap.configurationnamingcontext
        search_filter = '(objectClass=certificationAuthority)'

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            ca = CA(ldap, attr, schema_guid_dict)

            yield ca

    @classmethod
    def list_aiacas(self, ldap):
        schema_guid_dict = ldap._get_schema_guid_dict(self.schema_guid_attributes)
        sbase = 'CN=AIA,CN=Public Key Services,CN=Services,%s' % ldap.configurationnamingcontext
        search_filter = '(objectClass=certificationAuthority)'

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            ca = CA(ldap, attr, schema_guid_dict)

            yield ca




    # ========================
    # ====== CA object =======
    # ========================

    def __init__(self, ldap, attr, schema_guid_dict):
        self.domain = ldap.dn_to_domain(str(attr['distinguishedName']))
        self.name = str(attr['name'])
        self.description = str(attr['description']) if 'description' in attr else ''
        self.dn = str(attr['distinguishedName'])
        self.guid = ldap.parse_guid(bytes(attr['objectGUID']))

        try:
            self.created_date = datetime.strptime(str(attr['whenCreated']), '%Y%m%d%H%M%S.0Z') 
        except KeyError:
            self.created_date = None

        # Check the ACEs
        try:
            self.aces = parse_sd(bytes(attr['nTSecurityDescriptor']), self.domain.upper(), 'certificationAuthority', schema_guid_dict)
        except KeyError:
            self.aces = {}

        if type(attr['cACertificate']) != list:
            attr['cACertificate'] = [attr['cACertificate']]

        self.certthumbprints = []
        for cert_bytes in attr['cACertificate']:
            sha1 = hashlib.sha1(bytes(cert_bytes)).hexdigest().upper()

            cert = x509.load_der_x509_certificate(bytes(cert_bytes))

            self.cert_name = sha1
            self.certthumbprints.append(sha1)
            self.cert_chain = [sha1]  # TODO: Actually parse the certificate, Rusthound does this but it is not correct

            self.has_bc, self.path_len = get_basic_constraints(cert)


            """
            cert_bytes = bytes(cert_bytes)
            cert = x509.load_der_x509_certificate(cert_bytes)

            self.common_names = [cn.value for cn in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)]

            public_key = cert.public_key()
            if type(public_key) in [RSAPublicKey]:
                self.cert_algo = "RSA %d" % public_key.key_size
            elif type(public_key) in [DSAPublicKey]:
                self.cert_algo = "DSA %d" % public_key.key_size
            elif type(public_key) in [EllipticCurvePublicKey]:
                self.cert_algo = "EC %d" % public_key.key_size
            else:
                self.cert_algo = "Unknown: %s" % type(public_key)
            """

        if len(self.certthumbprints) == 1:
            self.certthumbprints = self.certthumbprints[0]

        if 'crossCertificatePair' in attr:
            self.hascrosscertificatepair = True

            self.crosscertificatepair = []
            if type(attr['crossCertificatePair']) != list:
                attr['crossCertificatePair'] = [attr['crossCertificatePair']]

            for item in attr['crossCertificatePair']:
                self.crosscertificatepair.append(str(item))
        else:
            self.hascrosscertificatepair = False
            self.crosscertificatepair = []

    def to_json(self):
        return {
            'domain': self.domain,
            'name': self.name,
            'created_date': self.created_date,
            'description': self.description,
            'dn': self.dn,
            'guid': self.guid,
            'aces': self.aces,
            'certthumbprints': self.certthumbprints,
            'certname': self.cert_name,
            'certchain': self.cert_chain,
            'hasbasicconstraints': self.has_bc,
            'basicconstraintpathlength': self.path_len,
            'hascrosscertificatepair': self.hascrosscertificatepair,
            'crosscertificatepair': self.crosscertificatepair,
            #'algo': self.cert_algo,
            #'common_names': self.common_names,
        }

def get_basic_constraints(cert: x509.Certificate):
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        return True, bc.path_length if bc.path_length != None else 0
    except x509.ExtensionNotFound:
        return False, 0
