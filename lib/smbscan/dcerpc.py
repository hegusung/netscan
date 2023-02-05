

class DCERPC:

    def __init__(self, hostname, port, timeout, use_smbv1=True):

        self.rpc = None

    def connect(binding):
        self.rpc = transport.DCERPCTransportFactory(binding)
        self.rpc.set_connect_timeout(1.0)

