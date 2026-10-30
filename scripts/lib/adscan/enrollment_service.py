from datetime import datetime
from impacket.ldap.ldaptypes import LDAP_SID
from lib.adscan.accesscontrol import parse_sd, process_sid
from lib.adscan.ou import OU
from lib.adscan.gpo import GPO

from lib.smbscan.smb import SMBScan

import time
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

import impacket
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.rpcrt import DCERPCException



class EnrollmentService:
    attributes = ['name', 'distinguishedName', 'objectGUID', 'cACertificate', 'nTSecurityDescriptor', 'description', 'whenCreated', 'flags', 'certificateTemplates', 'dNSHostName']
    schema_guid_attributes = ['pKIEnrollmentService', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name']

    @classmethod
    def list_enrollment_services(self, ldap):
        schema_guid_dict = ldap._get_schema_guid_dict(self.schema_guid_attributes)
        sbase = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,%s' % ldap.configurationnamingcontext
        search_filter = '(objectClass=pKIEnrollmentService)'

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            enrollment_service = EnrollmentService(ldap, attr, schema_guid_dict)

            yield enrollment_service

    # ========================================
    # ====== Enrollment Service object =======
    # ========================================

    def __init__(self, ldap, attr, schema_guid_dict):
        self.domain = ldap.dn_to_domain(str(attr['distinguishedName']))
        self.name = str(attr['name'])
        self.description = str(attr['description']) if 'description' in attr else ''
        self.dn = str(attr['distinguishedName'])
        self.guid = ldap.parse_guid(bytes(attr['objectGUID']))

        self.caname = self.dn.split(',')[0].split('=')[1]
        self.dnshostname = str(attr['dNSHostName'])

        try:
            self.created_date = datetime.strptime(str(attr['whenCreated']), '%Y%m%d%H%M%S.0Z') 
        except KeyError:
            self.created_date = None

        # Check the ACEs
        try:
            self.aces = parse_sd(bytes(attr['nTSecurityDescriptor']), self.domain.upper(), 'pKIEnrollmentService', schema_guid_dict)
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

        if len(self.certthumbprints) == 1:
            self.certthumbprints = self.certthumbprints[0]

        self.flags = []
        if int(attr['flags']) & 0x1 != 0:
            self.flags.append('NO_TEMPLATE_SUPPORT')
        if int(attr['flags']) & 0x2 != 0:
            self.flags.append('SUPPORTS_NT_AUTHENTICATION')
        if int(attr['flags']) & 0x4 != 0:
            self.flags.append('CA_SUPPORTS_MANUAL_AUTHENTICATION')
        if int(attr['flags']) & 0x8 != 0:
            self.flags.append('CA_SERVERTYPE_ADVANCED')


        self.certificate_templates = []
        for template in attr['certificateTemplates']:
            self.certificate_templates.append(str(template))

        # Registry
        casecurity_raw, enrollmentagentrights_raw, isissuerspecifiessamenabled_raw = self.get_smb_registry(ldap)

        if type(casecurity_raw) == str:
            self.casecurity = casecurity_raw
        else:
            self.casecurity = parse_sd(bytes(casecurity_raw), self.domain.upper(), 'pKIEnrollmentService', schema_guid_dict)

        if type(enrollmentagentrights_raw) == str:
            self.enrollmentagentrights = enrollmentagentrights_raw
        elif enrollmentagentrights_raw == None:
            self.enrollmentagentrights = []
        else:
            raise NotImplementedError("enrollmentagentrights parsing")

        if type(isissuerspecifiessamenabled_raw) == str:
            self.isissuerspecifiessamenabled = isissuerspecifiessamenabled_raw
        else:
            self.isissuerspecifiessamenabled = (isissuerspecifiessamenabled_raw & 0x00040000) == 0x00040000

    def get_smb_registry(self, ldap):

        try:
            smbConnection = SMBConnection(self.dnshostname, self.dnshostname, sess_port=445)
        except OSError:
            failure = "Error: Could not connect to the server"
            return failure, failure, failure

        try:
            smbConnection.login(ldap.username, ldap.password, ldap.domain, ldap.lm_hash, ldap.nt_hash)
        except DCERPCException as e:
            if 'rpc_s_access_denied' in str(e):
                failure = "Error: Authentication failure"
                return failure, failure, failure
            else:
                failure = "Error: %s" % str(e)
                return failure, failure, failure

        remoteOps = RemoteOperations(smbConnection, False)

        remoteOps.connectWinReg()
        
        try:
            tid = smbConnection.connectTree('IPC$')
            smbConnection.openFile(tid, r'\winreg', 0x12019f, creationOption=0x40, fileAttributes=0x80)
        except SessionError:
            pass

        time.sleep(2)

        dce = remoteOps.getRRP()

        # All good ! now query the registry:

       
        # HKLM
        ans = rrp.hOpenLocalMachine(dce)
        hRootKey = ans['phKey']

        # CASecurity
        # HKLM SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}  Security
        casecurity_raw = self.query_registry(dce, hRootKey, "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s" % self.caname, "Security")

        # AgentEnrollmentRights
        # HKLM SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}  EnrollmentAgentRights
        enrollmentagentrights_raw = self.query_registry(dce, hRootKey, "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s" % self.caname, "EnrollmentAgentRights")

        # IsUserSpecifiesSamEnabled
        # HKLM SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy   EditFlags
        isissuerspecifiessamenabled_raw = self.query_registry(dce, hRootKey, "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy" % self.caname, "EditFlags")

        remoteOps.finish()
        return casecurity_raw, enrollmentagentrights_raw, isissuerspecifiessamenabled_raw


    def query_registry(self, dce, hRootKey, subKey, entry):
        try:
            ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS | rrp.KEY_QUERY_VALUE)
        except impacket.dcerpc.v5.rrp.DCERPCSessionError as e:
            if 'ERROR_FILE_NOT_FOUND' in str(e):
                return "Error: Registry key not found"
            else:
                return "Error: %s" % str(e)
        except DCERPCException as e:
            if 'rpc_s_access_denied' in str(e):
                return "Error: Registry key couldn't be accessed"
            else:
                return "Error: %s" % str(e)

        try:
            value = rrp.hBaseRegQueryValue(dce, ans2['phkResult'], entry)
        except impacket.dcerpc.v5.rrp.DCERPCSessionError as e:
            if 'ERROR_FILE_NOT_FOUND' in str(e):
                return None
            else:
                return "Error: %s" % str(e)
        
        return value[1]


    def to_json(self):
        return {
            'domain': self.domain,
            'name': self.name,
            'created_date': self.created_date,
            'description': self.description,
            'dn': self.dn,
            'dnshostname': self.dnshostname,
            'guid': self.guid,
            'aces': self.aces,
            'certthumbprints': self.certthumbprints,
            'certname': self.cert_name,
            'certchain': self.cert_chain,
            'caname': self.caname,
            'hasbasicconstraints': self.has_bc,
            'basicconstraintpathlength': self.path_len,
            'flags': self.flags,
            'certificate_templates': self.certificate_templates,
            #'algo': self.cert_algo,
            #'common_names': self.common_names,
            'casecurity': self.casecurity,
            'enrollmentagentrights': self.enrollmentagentrights,
            'isissuerspecifiessamenabled': self.isissuerspecifiessamenabled,
        }


def get_basic_constraints(cert: x509.Certificate):
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        return True, bc.path_length if bc.path_length != None else 0
    except x509.ExtensionNotFound:
        return False, 0


class RemoteOperations:
    def __init__(self, smbConnection, doKerberos, kdcHost=None):
        self.__smbConnection = smbConnection
        self.__smbConnection.setTimeout(5 * 60)
        self.__serviceName = 'RemoteRegistry'
        self.__stringBindingWinReg = r'ncacn_np:445[\pipe\winreg]'
        self.__rrp = None
        self.__regHandle = None

        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost

        self.__disabled = False
        self.__shouldStop = False
        self.__started = False

        self.__stringBindingSvcCtl = r'ncacn_np:445[\pipe\svcctl]'
        self.__scmr = None

    def getRRP(self):
        return self.__rrp

    def __connectSvcCtl(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingSvcCtl)
        rpc.set_smb_connection(self.__smbConnection)
        self.__scmr = rpc.get_dce_rpc()
        self.__scmr.connect()
        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)

    def connectWinReg(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingWinReg)
        rpc.set_smb_connection(self.__smbConnection)
        self.__rrp = rpc.get_dce_rpc()
        self.__rrp.connect()
        self.__rrp.bind(rrp.MSRPC_UUID_RRP)

    def __checkServiceStatus(self):
        # Open SC Manager
        ans = scmr.hROpenSCManagerW(self.__scmr)
        self.__scManagerHandle = ans['lpScHandle']
        # Now let's open the service
        ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__serviceName)
        self.__serviceHandle = ans['lpServiceHandle']
        # Let's check its status
        ans = scmr.hRQueryServiceStatus(self.__scmr, self.__serviceHandle)
        if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            logging.info('Service %s is in stopped state' % self.__serviceName)
            self.__shouldStop = True
            self.__started = False
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            logging.debug('Service %s is already running' % self.__serviceName)
            self.__shouldStop = False
            self.__started = True
        else:
            raise Exception('Unknown service state 0x%x - Aborting' % ans['CurrentState'])

        # Let's check its configuration if service is stopped, maybe it's disabled :s
        if self.__started is False:
            ans = scmr.hRQueryServiceConfigW(self.__scmr, self.__serviceHandle)
            if ans['lpServiceConfig']['dwStartType'] == 0x4:
                logging.info('Service %s is disabled, enabling it' % self.__serviceName)
                self.__disabled = True
                scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType=0x3)
            logging.info('Starting service %s' % self.__serviceName)
            scmr.hRStartServiceW(self.__scmr, self.__serviceHandle)
            time.sleep(1)

    def enableRegistry(self):
        self.__connectSvcCtl()
        self.__checkServiceStatus()
        self.connectWinReg()

    def __restore(self):
        # First of all stop the service if it was originally stopped
        if self.__shouldStop is True:
            logging.info('Stopping service %s' % self.__serviceName)
            scmr.hRControlService(self.__scmr, self.__serviceHandle, scmr.SERVICE_CONTROL_STOP)
        if self.__disabled is True:
            logging.info('Restoring the disabled state for service %s' % self.__serviceName)
            scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType=0x4)

    def finish(self):
        self.__restore()
        if self.__rrp is not None:
            self.__rrp.disconnect()
        if self.__scmr is not None:
            self.__scmr.disconnect()
