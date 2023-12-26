import logging
import os
from gevent import sleep
from impacket.dcerpc.v5 import transport, scmr
from impacket.smbconnection import *

from utils.utils import gen_random_string

class SMBEXEC:

    def __init__(self, host, username = '', password = '', domain = '', hashes = None, share = None, port=445, doKerberos=False, kdcHost=None):
        self.__host = host
        #self.__share_name = share_name
        self.__port = port
        self.__username = username
        self.__password = password
        self.__serviceName = gen_random_string()
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__share = share
        self.__output = None
        self.__batchFile = None
        self.__outputBuffer = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__retOutput = False
        self.__rpctransport = None
        self.__scmr = None
        self.__conn = None
        #self.__mode  = mode
        #self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost

        if hashes is not None:
        #This checks to see if we didn't provide the LM Hash
            if hashes.find(':') != -1:
                self.__lmhash, self.__nthash = hashes.split(':')
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ''

        stringbinding = 'ncacn_np:%s[\\pipe\\svcctl]' % self.__host
        logging.debug('StringBinding %s'%stringbinding)
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.__rpctransport.set_dport(self.__port)

        if hasattr(self.__rpctransport, 'setRemoteHost'):
            self.__rpctransport.setRemoteHost(self.__host)
        if hasattr(self.__rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            self.__rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        self.__rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        self.__scmr = self.__rpctransport.get_dce_rpc()
        self.__scmr.connect()
        s = self.__rpctransport.get_smb_connection()
        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp['lpScHandle']

        self.transferClient = self.__rpctransport.get_smb_connection()

    def execute(self, command, output=False, code_page='cp850'):
            self.__retOutput = output
            try:
                if self.__retOutput:
                    self.cd(code_page)

                self.execute_remote(command, code_page)
                self.finish()
                return self.__outputBuffer
            except Exception as e:
                traceback.print_exc()

    def cd(self, code_page):
        self.execute_remote('cd ', code_page)

    def execute_remote(self, data, code_page):
        self.__output = '\\Windows\\Temp\\' + gen_random_string()
        self.__batchFile = gen_random_string(6) + '.bat'

        if self.__retOutput:
            command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile
        else:
            command = self.__shell + 'echo ' + data + ' 2^>^&1 > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile

        command += ' & ' + 'del ' + self.__batchFile

        """
        if self.__retOutput:
            # TODO
            command = self.__shell + data + ' ^> \\\\{}\\{}\\{}'.format(local_ip, self.__share_name, self.__output)
        else:
            command = self.__shell + data
        """

        #logging.debug('Hosting batch file with command: ' + command)

        # TODO
        #command = self.__shell + '\\\\{}\\{}\\{}'.format(local_ip,self.__share_name, self.__batchFile)
        #logging.debug('Command to execute: ' + command)

        #logging.debug('Remote service {} created.'.format(self.__serviceName))
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName, lpBinaryPathName=command, dwStartType=scmr.SERVICE_DEMAND_START)
        service = resp['lpServiceHandle']

        try:
            #logging.debug('Remote service {} started.'.format(self.__serviceName))
            scmr.hRStartServiceW(self.__scmr, service)
        except:
           pass
        #logging.debug('Remote service {} deleted.'.format(self.__serviceName))
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output(code_page)

    def get_output(self, code_page):
        if not self.__retOutput: return

        def output_callback(data):
            self.__outputBuffer += data.decode(code_page, "backslashreplace")

        while True:
            try:
                self.transferClient.getFile(self.__share, self.__output, output_callback)
                self.transferClient.deleteFile(self.__share, self.__output)
                break
            except Exception:
                sleep(2)

    def finish(self):
        # Just in case the service is still created
        try:
           self.__scmr = self.__rpctransport.get_dce_rpc()
           self.__scmr.connect()
           self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
           resp = scmr.hROpenSCManagerW(self.__scmr)
           self.__scHandle = resp['lpScHandle']
           resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
           service = resp['lpServiceHandle']
           scmr.hRDeleteService(self.__scmr, service)
           scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
           scmr.hRCloseServiceHandle(self.__scmr, service)
        except:
            pass
