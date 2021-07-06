from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL

from utils.output import Output

class WMI:
    def __init__(self, target, username, password, domain, hashes=None):
        self.__target = target
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__doKerberos = False
        self.__retOutput = True

        if hashes is not None:
        #This checks to see if we didn't provide the LM Hash
            if hashes.find(':') != -1:
                self.__lmhash, self.__nthash = hashes.split(':')
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ''

        self.__dcom = DCOMConnection(self.__target, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, oxidResolver = True, doKerberos=self.__doKerberos)
        iInterface = self.__dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        self.iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

    def enumProcesses(self):
        #self.__win32Process,_ = iWbemServices.GetObject('Win32_Process')

        iEnumWbemClassObject = self.iWbemServices.ExecQuery('SELECT * from Win32_Process')
        while True:
            try:
                pEnum = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                record = pEnum.getProperties()

                if not "ProcessId" in record or not "Name" in record:
                    continue

                proc = {
                    'pid': record['ProcessId']['value'],
                    'name': record['Name']['value'],
                }

                user = pEnum.GetOwner().User
                if user != None:
                    proc['user'] = user
                else:
                    proc['user'] = 'Unknown'
                domain = pEnum.GetOwner().Domain
                if domain != None:
                    proc['domain'] = domain
                else:
                    proc['domain'] = 'Unknown'
                sid = pEnum.GetOwnerSid().Sid
                if sid != None:
                    proc['sid'] = sid

                yield proc
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise
                else:
                    break
        iEnumWbemClassObject.RemRelease()
