import socket
import traceback
import logging
from impacket.tds import MSSQL
from .mssqlexec import MSSQLEXEC

from utils.utils import AuthFailure

class MSSQL_with_timeout(MSSQL):

    def __init__(self, *args, timeout=30, **kwargs):
        self.timeout = timeout
        super(MSSQL_with_timeout, self).__init__(*args, **kwargs)

    def connect(self):
        af, socktype, proto, canonname, sa = socket.getaddrinfo(self.server, self.port, 0, socket.SOCK_STREAM)[0]
        sock = socket.socket(af, socktype, proto)
        sock.settimeout(self.timeout)

        try:
            sock.connect(sa)
        except Exception:
            #import traceback
            #traceback.print_exc()
            raise

        self.socket = sock
        return sock

class NoPrint:
    def logMessage(self, message):
        pass
    def getMessage(self):
        pass

class MSSQLScan:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        #self.mssql = MSSQL_with_timeout(self.hostname, port=self.port, timeout=self.timeout, rowsPrinter=NoPrint())
        self.mssql = MSSQL_with_timeout(self.hostname, port=self.port, timeout=self.timeout)

    def url(self):
        return 'mssql://%s:%d' % (self.hostname, self.port)

    def connect(self):
        return self.mssql.connect()

    def disconnect(self):
        return self.mssql.disconnect()

    def get_server_info(self):
        server_info = self.mssql.preLogin()

        version_tuple = (server_info["Version"][0], server_info["Version"][1], server_info["Version"][2]*256+server_info["Version"][3])
        version_number = "%d.%d.%d" % version_tuple

        # parse version number
        if version_tuple[0] == 7:
            version = "MSSQL Server 7.0"
        elif version_tuple[0] == 8:
            version = "MSSQL Server 2000"
        elif version_tuple[0] == 9:
            version = "MSSQL Server 2005"
        elif version_tuple[0] == 10:
            if version_tuple[1] == 0:
                version = "MSSQL Server 2008"
            if version_tuple[1] == 50:
                version = "MSSQL Server 2008 R2"
        elif version_tuple[0] == 11:
            version = "MSSQL Server 2012"
        elif version_tuple[0] == 12:
            version = "MSSQL Server 2014"
        elif version_tuple[0] == 13:
            version = "MSSQL Server 2016"
        else:
            version = "Unknown MSSQL Version"

        return {'version': version, 'version_number': version_number}

    def auth(self, domain, username, password, ntlm_hash):
        success = False
        is_admin = False

        if not username:
            raise Exception('MSSQL authentication requires a username')
        if domain:
            local_auth = False
        else:
            local_auth = True

        success = self.mssql.login(None, username, password, domain, ntlm_hash, not local_auth)

        if not success:
            raise AuthFailure('Authentication failed')

        is_admin = self.check_if_admin()

        return success, is_admin

    def check_if_admin(self):
        try:
            res = self.mssql.sql_query("SELECT IS_SRVROLEMEMBER('sysadmin')")
            query_output = res[0]['']

            if int(query_output):
                return True
            else:
                return False
        except Exception as e:
            print('Error calling check_if_admin(): {}'.format(e))
            logging.debug('Error calling check_if_admin(): {}'.format(e))
            return False

        return False

    def list_admins(self):
        try:
            query_output = self.mssql.sql_query("EXEC sp_helpsrvrolemember 'sysadmin'")
            admins = []
            for item in query_output:
                if "MemberName" in item:
                    admins.append(item["MemberName"])
            return admins
        except:
            traceback.print_exc()

    def list_databases(self):
        query = "SELECT name FROM master.dbo.sysdatabases WHERE dbid > 4"
        output = self.mssql.sql_query(query)

        databases = []

        for db in output:
            db_info = {'name': db['name']}
            tables_query = "USE %s; SELECT name FROM sys.Tables" % db["name"]
            tables_output = mssql.sql_query(tables_query)
            tables = []
            for table in tables_output:
                tables.append(table['name'])
            db_info['tables'] = tables

            databases.append(db_info)

        return databases

    def list_hashes(self):
        query = "SELECT name,password_hash FROM sys.sql_logins"
        return self.mssql.sql_query(query)

    def execute_sql(self, query):
        return self.mssql.sql_query(query)

    def execute_cmd(self, command):

        mssqlexec = MSSQLEXEC(self.mssql)
        output = mssqlexec.execute(command, output=True)
        if not output:
            output = "Executed command but received no output"

        return output
