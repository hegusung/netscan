import traceback
from time import strftime, gmtime
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5 import transport, samr, wkst, srvs, lsat, lsad
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.samr import DCERPCSessionError
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.ndr import NULL

# https://github.com/SecureAuthCorp/impacket/blob/master/examples/netview.py

class ListUsersException(Exception):
    pass

class Enum:
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

        rpctransport = transport.SMBTransport(self.__addr, self.__port, r'\samr', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)

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

        rpctransport = transport.SMBTransport(self.__addr, self.__port, r'\samr', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)

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

        rpctransport = transport.SMBTransport(self.__addr, self.__port, r'\samr', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)

        # Display results.

        admin_sids = self.__fetchAdminSidList(rpctransport)
        for entry in self.__lookupSidUidGen((n for n in admin_sids)):
            yield entry

    def enumPasswordPolicy(self):
        rpctransport = transport.SMBTransport(self.__addr, self.__port, r'\samr', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)

        dce = rpctransport.get_dce_rpc()
        dce.connect()

        dce.bind(samr.MSRPC_UUID_SAMR)

        resp = samr.hSamrConnect(dce)
        serverHandle = resp['ServerHandle']

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
        domains = resp['Buffer']['Buffer']

        domain = domains[0]["Name"]
        resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])

        resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
        domainHandle = resp['DomainHandle']

        if self.__host_domain == "":
            domain = "WORKGROUP"
        else:
            domain = self.__host_domain

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)

        pass_complexity = resp['Buffer']['Password']['PasswordProperties']
        min_pass_len = resp['Buffer']['Password']['MinPasswordLength']
        pass_hst_len = resp['Buffer']['Password']['PasswordHistoryLength']

        max_pass_age = self.__convert(resp['Buffer']['Password']['MaxPasswordAge']['LowPart'],
                                    resp['Buffer']['Password']['MaxPasswordAge']['HighPart'],
                                    1)

        min_pass_age = self.__convert(resp['Buffer']['Password']['MinPasswordAge']['LowPart'],
                                    resp['Buffer']['Password']['MinPasswordAge']['HighPart'],
                                    1)

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)

        lock_threshold = int(resp['Buffer']['Lockout']['LockoutThreshold'])

        lock_duration = None
        if lock_threshold != 0: lock_duration = int(resp['Buffer']['Lockout']['LockoutDuration']) / -600000000

        dce.disconnect()

        return {
            'complexity': pass_complexity,
            'minimum_length': min_pass_len,
            'history_length': pass_hst_len,
            'maximum_age': max_pass_age,
            'minimum_age': min_pass_age,
            'lock_threshold': lock_threshold,
            'lock_duration': lock_duration,
        }

    def enumLoggedIn(self):
        rpctransport = transport.SMBTransport(self.__addr, self.__port, r'\wkssvc', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)

        dce = rpctransport.get_dce_rpc()

        dce.connect()
        dce.bind(wkst.MSRPC_UUID_WKST)

        try:
            resp = wkst.hNetrWkstaUserEnum(dce,1)
        except Exception as e:
            raise e

        for session in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
            username = session['wkui1_username'][:-1]
            logonDomain = session['wkui1_logon_domain'][:-1]

            yield {
                'username': username,
                'domain': logonDomain,
            }

        dce.disconnect()


    def enumSessions(self):
        rpctransport = transport.SMBTransport(self.__addr, self.__port, r'\srvsvc', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)

        dce = rpctransport.get_dce_rpc()

        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)

        try:
            resp = srvs.hNetrSessionEnum(dce, '\x00', NULL, 10)
        except Exception as e:
            print("%s: %s\n%s" % (type(e), e, traceback.format_exc()))

        for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
            username = session['sesi10_username'][:-1]
            sourceIP = session['sesi10_cname'][:-1][2:]
            active_time = session['sesi10_time']
            idle_time = session['sesi10_idle_time']

            yield {
                'username': username,
                'source_ip': sourceIP,
                'active_time': active_time,
                'idle_time': idle_time,
            }

        dce.disconnect()

    def RIDBruteforce(self, start, end):
        for entry in self.__lookupSidUidGen((n for n in range(start, end+1))):
            yield entry

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

    def __fetchAdminSidList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        domain = None
        entries = []

        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        admin_sids = []

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
                        admin_sids.append(member["SidPointer"].formatCanonical())

        except ListUsersException as e:
            print("Error listing group: %s" % e)

        dce.disconnect()

        return admin_sids

    def __lookupSidUidGen(self, sid_uid_gen):

        rpctransport = transport.SMBTransport(self.__addr, self.__port, r'\lsarpc', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)
        dce = rpctransport.get_dce_rpc()

        domain = None
        entries = []

        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)

        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
        domainSid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()

        SIMULTANEOUS = 1000

        while True:
            empty = True
            sids = []
            for i in sid_uid_gen:
                empty = False
                if type(i) == int:
                    i = domainSid + '-%d' % i
                sids.append(i)

                if len(sids) >= SIMULTANEOUS:
                    break

            if empty:
                break


            try:
                resp = lsat.hLsarLookupSids(dce, policyHandle, sids,lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException as e:
                if str(e).find('STATUS_NONE_MAPPED') >= 0:
                    continue
                elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else:
                    raise

            for n, item in enumerate(resp['TranslatedNames']['Names']):
                if item['Use'] != SID_NAME_USE.SidTypeUnknown:
                    yield {
                        'domain': resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'],
                        'name': item['Name'],
                        'type': SID_NAME_USE.enumItems(item['Use']).name
                    }

        dce.disconnect()


    def __convert(self, low, high, no_zero):

        if low == 0 and hex(high) == "-0x80000000":
            return "Not Set"
        if low == 0 and high == 0:
            return "None"
        if no_zero: # make sure we have a +ve vale for the unsined int
            if (low != 0):
                high = 0 - (high+1)
            else:
                high = 0 - (high)
            low = 0 - low
        tmp = low + (high)*16**8 # convert to 64bit int
        tmp *= (1e-7) #  convert to seconds
        try:
            minutes = int(strftime("%M", gmtime(tmp)))  # do the conversion to human readable format
        except ValueError as e:
            return "BAD TIME:"
        hours = int(strftime("%H", gmtime(tmp)))
        days = int(strftime("%j", gmtime(tmp)))-1
        time = ""
        if days > 1:
         time = str(days) + " days "
        elif days == 1:
            time = str(days) + " day "
        if hours > 1:
            time += str(hours) + " hours "
        elif hours == 1:
            time = str(days) + " hour "
        if minutes > 1:
            time += str(minutes) + " minutes"
        elif minutes == 1:
            time = str(days) + " minute "
        return time

