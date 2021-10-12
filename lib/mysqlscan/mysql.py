import socket
import traceback
import logging

import mysql.connector

from utils.utils import AuthFailure

class NotMysql(Exception):
    pass

class MySQLScan:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.conn = None

    def url(self):
        return 'mysql://%s:%d' % (self.hostname, self.port)

    def disconnect(self):
        if self.conn != None:
            self.conn.close()
        self.conn = None

    def get_server_version_unauth(self):

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            sock.connect((self.hostname, self.port))

            data = sock.recv(1024)

            version = ""
            version_start = data[5:]

            if not data[4] in [10, 0xff]:
                raise NotMysql()

            if data[4] == 0xff:
                return None

            i = 0
            while i < len(version_start):
                if version_start[i] == 0:
                    break
                version += chr(version_start[i])
                i += 1

            sock.close()

            return version

        except Exception as e:
            raise e

    def auth(self, username, password):
        success = False

        try:
            self.conn = mysql.connector.connect(host=self.hostname, port=self.port, user=username, passwd=password, connect_timeout=self.timeout)

            version = self.conn.get_server_info()

            return True, version
        except mysql.connector.errors.ProgrammingError as e:
            raise AuthFailure(str(e))
        except mysql.connector.errors.DatabaseError as e:
            raise e
            """
            if not "system error: timed out" in str(e):
                pass
            return
            """
        except mysql.connector.errors.OperationalError as e:
            raise e
        except mysql.connector.errors.InterfaceError as e:
            raise e

    def list_databases(self):
        databases = []
        c = self.conn.cursor()
        c.execute("show databases")
        res = c.fetchall()

        for db in res:
            db_info = {'name': db[0]}
            c.execute("use %s" % db[0])
            c.execute("show tables")
            res_tables = c.fetchall()
            tables = []
            for table in res_tables:
                tables.append(table[0])
            db_info['tables'] = tables

            databases.append(db_info)

        return databases

    def list_hashes(self):
        c = self.conn.cursor()
        c.execute("SELECT host, user, password FROM mysql.user")
        res = c.fetchall()

        output = []
        for db in res:
            output.append({'host': db[0], 'username': db[1], 'hash': db[2]})

        return output

    def execute_sql(self, query):
        c = self.conn.cursor()
        c.execute(query)
        res = c.fetchall()

        output = []
        for db in res:
            output.append(list(db))

        return output


        return self.mssql.sql_query(query)
