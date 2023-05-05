from lib.sshscan.ssh import SSH

# Requirements to print
from utils.output import Output
from utils.db import DB

class Module:
    name = 'DumpVersions'
    description = 'Get kernel and packages versions'

    def run(self, target, args, creds, timeout):
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None

        check(target['hostname'], target['port'], user, password, timeout)


def check(hostname, port, user, password, timeout):

    ssh = SSH(hostname, port, timeout)
    connected = ssh.auth(user, password)

    if connected:
        doc = {
            "hostname": hostname,
        }

        # Get hostname
        command = "hostname"

        result = ssh.execute(command)
        if result != '':
            host = result.strip()
        else:
            # Unable to retreive hostname
            Output.minor({'target': 'ssh://%s:%d' % (hostname, port), 'message': 'Unable to retreive hostname, aborting module Dumpversions'})
            return

        doc["host"] = host

        # Command to get kernel info
        command = "uname -r"

        result = ssh.execute(command)
        if result != '':
            doc["kernel"] = result.strip()

        # Command to get OS info
        command = "hostnamectl | grep 'Operating System'"

        result = ssh.execute(command)
        if result != '':
            doc["os"] = result.split(':')[-1].strip()

        Output.highlight({'target': 'ssh://%s:%d' % (hostname, port), 'message': '%s %s %s' % (doc['host'].ljust(30), doc['kernel'].ljust(30), doc['os'])})
        DB.insert_host_linux(doc)

        # Query packages
        dpkg_command = 'dpkg -l'
        rpm_command = 'rpm -qa --queryformat "%{NAME} %{VERSION}\n"'

        # Try dpkg
        dpkg_result = ssh.execute(dpkg_command)
        rpm_result = ssh.execute(rpm_command)
        results = [dpkg_result, rpm_result]
        result = max(results, key=len)

        if result == dpkg_result:
            start_parse = False
            for line in dpkg_result.split('\n'):
                try:
                    line = line.strip()

                    if "=========" in line:
                        start_parse = True
                        continue

                    if start_parse:
                        pkg_name = line.split()[1]
                        pkg_version = line.split()[2]

                        doc = {
                            "hostname": hostname,
                            "host": host,
                            "pkg_name": pkg_name,
                            "pkg_version": pkg_version,
                        }
                        DB.insert_host_linux_pkg(doc)


                except IndexError:
                    pass
        elif result == rpm_result:
            for line in rpm_result.split('\n'):
                try:
                    line = line.strip()

                    pkg_name = line.split()[0]
                    pkg_version = line.split()[1]

                    doc = {
                        "hostname": hostname,
                        "host": host,
                        "pkg_name": pkg_name,
                        "pkg_version": pkg_version,
                    }
                    DB.insert_host_linux_pkg(doc)
                except IndexError:
                    pass

