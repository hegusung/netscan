import logging

class MSSQLEXEC:

    def __init__(self, connection):
        self.mssql_conn = connection
        self.outputBuffer = ''

    def execute(self, command, output=False):
        try:
            self.enable_xp_cmdshell()
            raw_output = self.mssql_conn.sql_query("exec master..xp_cmdshell '{}'".format(command))
            self.outputBuffer = ""
            if output:
                for row in raw_output:
                    if row["output"] == "NULL":
                        self.outputBuffer += "\n"
                    else:
                        self.outputBuffer += row["output"] + "\n"

            self.disable_xp_cmdshell()
            return self.outputBuffer

        except Exception as e:
            logging.debug('Error executing command via mssqlexec: {}'.format(e))

    def enable_xp_cmdshell(self):
        self.mssql_conn.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")

    def disable_xp_cmdshell(self):
        self.mssql_conn.sql_query("exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure 'show advanced options', 0 ;RECONFIGURE;")

