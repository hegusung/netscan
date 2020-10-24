#!/usr/bin/python
# Copyright (c) 2003-2015 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: DCE/RPC SAMR dumper.
#
# Author:
#  Javier Kohen <jkohen@coresecurity.com>
#  Alberto Solino (@agsolino)
#
# Reference for:
#  DCE/RPC for SAMR

from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.samr import DCERPCSessionError
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED

class ListUsersException(Exception):
    pass

class Enum:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\samr]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\samr]', 445),
        }

    def __init__(self, hostname, port, domain, username, password, hash, conn):

        self.__username = username
        self.__addr = hostname
        self.__password = password
        self.__domain = domain
        self.__hash = hash
        self.__port = port
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__doKerberos = False
        self.__host_domain = conn.getServerDomain()

        if self.__hash is not None:
        #This checks to see if we didn't provide the LM Hash
            if self.__hash.find(':') != -1:
                self.__lmhash, self.__nthash = self.__hash.split(':')
            else:
                self.__nthash = self.__hash

        if self.__password is None:
            self.__password = ''

    def enumUsers(self):
        """Dumps the list of users and shares registered present at
        addr. Addr is a valid host name or IP address.
        """

        protodef = Enum.KNOWN_PROTOCOLS['{}/SMB'.format(self.__port)]
        port = protodef[1]

        rpctransport = transport.SMBTransport(self.__addr, port, r'\samr', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)

        # Display results.

        for entry in self.__fetchUserList(rpctransport):
            (domain, username, uid, user) = entry
            if self.__host_domain != domain:
                domain = "WORKGROUP"

            tags = []
            #account_never_expires 
            if user["UserAccountControl"] & 0x00010000 != 0:
                tags.append("Never expires")
            #account_disabled 
            if user["UserAccountControl"] & 0x00000002 != 0:
                tags.append("Disabled")

            yield {
                'domain': domain,
                'username': username,
                'fullname': user['FullName'],
                'user_comment': user['UserComment'],
                'admin_comment': user['AdminComment'],
                'uid': uid,
                'tags': tags,
            }

            #self.__logger.highlight(u'{}/FullName: {}'.format(base, user['FullName']))
            #self.__logger.highlight(u'{}/UserComment: {}' .format(base, user['UserComment']))
            #self.__logger.highlight(u'{}/PrimaryGroupId: {}'.format(base, user['PrimaryGroupId']))
            #self.__logger.highlight(u'{}/BadPasswordCount: {}'.format(base, user['BadPasswordCount']))
            #self.__logger.highlight(u'{}/LogonCount: {}'.format(base, user['LogonCount']))

    def enumGroups(self, silent=False):
        """Dumps the list of users and shares registered present at
        addr. Addr is a valid host name or IP address.
        """

        protodef = Enum.KNOWN_PROTOCOLS['{}/SMB'.format(self.__port)]
        port = protodef[1]

        rpctransport = transport.SMBTransport(self.__addr, port, r'\samr', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)

        for entry in self.__fetchGroupList(rpctransport):
            (domain, groupname, uid, group, members) = entry
            if self.__host_domain != domain:
                domain = "WORKGROUP"

            yield {
                'domain': domain,
                'groupname': groupname,
                'admin_comment': group['AdminComment'],
                'members_rid': members['RelativeIds'],
                'uid': uid,
            }



    def enumAdmins(self, silent=False):
        """Dumps the list of admins registered present at
        addr. Addr is a valid host name or IP address.
        """

        # Try all requested protocols until one works.
        entries = []

        protodef = Enum.KNOWN_PROTOCOLS['{}/SMB'.format(self.__port)]
        port = protodef[1]

        rpctransport = transport.SMBTransport(self.__addr, port, r'\samr', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)

        # Display results.

        for entry in self.__fetchAdminList(rpctransport):
            print(entry)
            """
            (domain, groupname, uid, group, members) = entry
            if self.__host_domain != domain:
                domain = "WORKGROUP"
            if not silent:
                Logger.highlight("%s\\%s (%d) %s" % (domain, groupname.ljust(30), uid, group["AdminComment"]))
            #for member in members["RelativeIds"]:
            new_domain_group(domain, self.__addr, groupname, rid=uid, contained_rid=members["RelativeIds"], comment=group["AdminComment"])
            """

    def __fetchUserList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        domain = None
        entries = []

        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        try:
            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']

            domain = domains[0]['Name']

            resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle,domains[0]['Name'] )

            resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
            domainHandle = resp['DomainHandle']

            status = STATUS_MORE_ENTRIES
            enumerationContext = 0
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext = enumerationContext)
                except DCERPCException as e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise
                    resp = e.get_packet()

                for user in resp['Buffer']['Buffer']:
                    try:
                        r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                        info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],samr.USER_INFORMATION_CLASS.UserAllInformation)
                        entry = (domain, user['Name'], user['RelativeId'], info['Buffer']['All'])
                        yield entry
                        samr.hSamrCloseHandle(dce, r['UserHandle'])
                    except DCERPCSessionError:
                        pass

                enumerationContext = resp['EnumerationContext']
                status = resp['ErrorCode']

        except ListUsersException as e:
            print("Error listing users: %s" % e)

        dce.disconnect()

        #return domain, entries

    def __fetchGroupList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        domain = None
        entries = []

        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        try:
            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']

            domain = domains[0]['Name']

            resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle,domains[0]['Name'] )

            resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
            domainHandle = resp['DomainHandle']

            status = STATUS_MORE_ENTRIES
            enumerationContext = 0
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle, enumerationContext = enumerationContext)
                except DCERPCException as e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise
                    resp = e.get_packet()

                for group in resp['Buffer']['Buffer']:
                    r = samr.hSamrOpenGroup(dce, domainHandle, samr.MAXIMUM_ALLOWED, group['RelativeId'])
                    info = samr.hSamrQueryInformationGroup(dce, r['GroupHandle'],samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)

                    # Query members in group
                    try:
                        members_info = samr.hSamrGetMembersInGroup(dce, r['GroupHandle'])
                        members = {
                            "Count": members_info["Members"]["MemberCount"],
                            "RelativeIds": [],
                        }
                        for member in members_info["Members"]["Members"]:
                            members["RelativeIds"].append(int(vars(member)["fields"]["Data"]))

                        entry = (domain, group['Name'], group['RelativeId'], info['Buffer']['General'], members)
                        yield entry
                        samr.hSamrCloseHandle(dce, r['GroupHandle'])
                    except DCERPCSessionError:
                        pass

                enumerationContext = resp['EnumerationContext']
                status = resp['ErrorCode']

        except ListUsersException as e:
            print("Error listing group: %s" % e)

        dce.disconnect()

        #return domain, entries

    def __fetchAdminList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        domain = None
        entries = []

        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        try:
            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']

            domainNames = []
            for domain in domains:
                domainNames.append(domain['Name'])

            domain = "Builtin"

            resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle,domain)

            resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
            domainHandle = resp['DomainHandle']

            resp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)

            for alias in resp['Buffer']['Buffer']:
                if alias['RelativeId'] == 544:
                    # Admin group
                    resp = samr.hSamrOpenAlias(dce, domainHandle, desiredAccess=MAXIMUM_ALLOWED, aliasId=alias['RelativeId'])

                    resp = samr.hSamrGetMembersInAlias(dce, resp["AliasHandle"])
                    for member in resp["Members"]["Sids"]:
                        yield member["SidPointer"].formatCanonical()

        except ListUsersException as e:
            print("Error listing group: %s" % e)

        dce.disconnect()

        #return domain, entries
