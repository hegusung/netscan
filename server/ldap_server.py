#!/usr/bin/env python3

import tempfile, sys

from twisted.application import service
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.python.components import registerAdapter
from twisted.python import log
from ldaptor.interfaces import IConnectedLDAPEntry
from ldaptor.protocols.ldap.ldapserver import LDAPServer
from ldaptor.ldiftree import LDIFTreeEntry

from utils.output import Output
from server.vulnerability_callback import VulnCallback

class DetectVulnLDAPServer(LDAPServer):

    def handle_LDAPSearchRequest(self, request, controls, reply):
        query = request.baseObject.decode()

        Output.highlight("LDAP> Requested ressource: %s" % (query,))

        if query.startswith("vuln/"):
            vuln_id = query[5:]

            VulnCallback.check(vuln_id)

        return

        LDAPServer.handle_LDAPSearchRequest(self, request, controls, reply)

class Tree:
    def __init__(self):
        dirname = tempfile.mkdtemp(".ldap", "test-server", "/tmp")
        self.db = LDIFTreeEntry(dirname)

class LDAPServerFactory(ServerFactory):
    """
    Our Factory is meant to persistently store the ldap tree
    """

    protocol = DetectVulnLDAPServer

    def __init__(self, root):
        self.root = root

    def buildProtocol(self, addr):
        proto = self.protocol()
        #proto.debug = self.debug
        proto.factory = self
        return proto

def run_ldap_server(bind_ip, bind_port):

    # First of all, to show logging info in stdout :

    #log.startLogging(sys.stderr)

    # We initialize our tree
    tree = Tree()
    # When the ldap protocol handle the ldap tree,
    # it retrieves it from the factory adapting
    # the factory to the IConnectedLDAPEntry interface
    # So we need to register an adapter for our factory
    # to match the IConnectedLDAPEntry
    registerAdapter(lambda x: x.root, LDAPServerFactory, IConnectedLDAPEntry)

    # Run it !!
    factory = LDAPServerFactory(tree.db)
    factory.debug = True
    application = service.Application("ldaptor-server")
    myService = service.IServiceCollection(application)
    reactor.listenTCP(bind_port, factory, interface=bind_ip)
    reactor.run(installSignalHandlers=False)

