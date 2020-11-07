import traceback
import socket
import os.path
from operator import itemgetter

from .portmap import Portmap
from .mount import Mount, MountAccessError
from .nfs import NFS, NFSAccessError
from .utils import parse_rpc_names

from utils.output import Output
from utils.dispatch import dispatch
from utils.utils import gen_random_string, sizeof_fmt
from utils.db import DB

def rpcscan_worker(target, actions, timeout):
    portmap = None
    mount = None
    nfs = None
    try:
        portmap = Portmap(target['hostname'], 111, timeout)
        portmap.connect()
        res = portmap.null()

        if res:
            Output.write({'target': 'rpc://%s:%d' % (target['hostname'], 111) , 'message': 'Portmapper'})
            DB.insert_port({
                'hostname': target['hostname'],
                'port': 111,
                'protocol': 'tcp',
                'service': 'portmapper',
            })

            if 'rpc' in actions:
                rpc_names = parse_rpc_names(os.path.join('lib', 'rpcscan', 'rpc_names.csv'))
                output = 'RPC services:\n'
                for entry in sorted(portmap.dump(),key=itemgetter('program')):
                    name = int(entry["program"])
                    for rpc_service in rpc_names:
                        if entry["program"] in rpc_service["range"]:
                            name = rpc_service["name"]
                            entry['name'] = name
                            break
                    if 'name' in entry:
                        program = '%s [%d] version %d' % (entry['name'], entry['program'], entry['version'])
                    else:
                        program = 'Unknown [%d] version %d' % (entry['program'], entry['version'])
                    port = '%s/%d' % (entry['protocol'], entry['port'])
                    output += ' '*60+'- %s  %s\n' % (program.ljust(40), port)
                Output.write({'target': 'rpc://%s:%d' % (target['hostname'], 111) , 'message': output})

            mount_port = portmap.getport(Mount.program, Mount.program_version)

            mount = Mount(target['hostname'], mount_port, timeout)
            mount.connect()
            DB.insert_port({
                'hostname': target['hostname'],
                'port': mount_port,
                'protocol': 'tcp',
                'service': 'mount',
            })

            mounts = mount.export()

            if 'mounts' in actions:
                output = 'Mountpoints:\n'
                for mountpoint in mounts:
                    output += ' '*60+'- %s  [%s]' % (mountpoint['path'], mountpoint['authorized'])
                    Output.write({'target': 'rpc://%s:%d' % (target['hostname'], mount_port) , 'message': output})

            nfs_port = portmap.getport(NFS.program, NFS.program_version)

            for mountpoint in mounts:
                if '*' in mountpoint['authorized']:
                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': nfs_port,
                        'service': 'nfs',
                        'url': 'nfs://%s:%d' % (target['hostname'], nfs_port),
                        'name': 'NFS share accessible to everyone',
                        'description': 'NFS share is accessible from any IP address: nfs://%s:%d%s' % (target['hostname'], nfs_port, mountpoint['path']),
                    }
                    DB.insert_vulnerability(vuln_info)

            nfs = NFS(target['hostname'], nfs_port, timeout)
            nfs.connect()

            Output.write({'target': 'nfs://%s:%d' % (target['hostname'], nfs_port) , 'message': 'NFS'})
            DB.insert_port({
                'hostname': target['hostname'],
                'port': nfs_port,
                'protocol': 'tcp',
                'service': 'nfs',
            })

            if 'list' in actions:
                uid = actions['list']['uid']
                gid = actions['list']['gid']
                recurse = actions['list']['recurse']

                auth = {
                    "flavor": 1, #AUTH_UNIX
                    "machine_name": gen_random_string(),
                    "uid": uid,
                    "gid": gid,
                    "aux_gid": [gid],
                }

                # iterate through nfs content
                for mountpoint in mounts:
                    try:
                        file_handle = mount.mnt(mountpoint["path"], auth=auth)["file_handle"]
                        contents = "%s contents:\n" % mountpoint["path"]
                        for content in get_content(nfs, auth, file_handle, mountpoint['path'], recurse):
                            if content['type'] == 'file':
                                contents += " "*60+"- %s %s\n" % (content['file'].ljust(30), sizeof_fmt(content['size']))
                            else:
                                contents += " "*60+"- %s/\n" % (content['file'],)

                            db_info = {
                                'hostname': target['hostname'],
                                'port': nfs_port,
                                'url': 'nfs://%s:%d' % (target['hostname'], nfs_port),
                                'service': 'nfs',
                                'share': mountpoint['path'],
                                'path': content['file'],
                            }
                            if 'size' in content:
                                db_info['size'] = content['size']
                            DB.insert_content(db_info)
                        Output.write({'target': 'nfs://%s:%d' % (target['hostname'], nfs_port) , 'message': contents})
                    except MountAccessError as e:
                        print("%s: %s" % (type(e), e))
                        continue
    except OSError:
        pass
    except ConnectionRefusedError:
        pass
    except Exception as e:
        Output.write({'target': 'rpc://%s:%d' % (target['hostname'], 111), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        if portmap != None:
            portmap.disconnect()
        if mount != None:
            mount.disconnect()
        if nfs != None:
            nfs.disconnect()

def get_content(nfs, auth, file_handle, file_path, recurse):
    if recurse <= 0:
        return

    empty = True

    try:
        items = nfs.readdirplus(file_handle, auth=auth)
    except NFSAccessError as e:
        print("%s: %s" % (type(e), e))
        return

    for item in items:
        file_name = item["name"]
        file_type = item["file_type"]
        file_size = item["file_size"]
        file_type_str = "directory" if file_type == 2 else "file"

        if file_name in [".", ".."]:
            continue

        entry = {'file': os.path.join(file_path, file_name), 'type': file_type_str, 'size': file_size}
        yield entry

        if file_type_str == "directory" and recurse > 0:
            for content in get_content(nfs, auth, item["file_handle"], os.path.join(file_path, file_name), recurse-1):
                yield content
