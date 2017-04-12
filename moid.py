#!/usr/bin/env python3
import base64
import getopt
import getpass
import json
import os
import shutil
import ssl
import subprocess
import sys
import threading

import OpenSSL

try:
    from pyVim import connect
    from pyVmomi import vmodl
    from pyVmomi import vim
except ImportError:
    print("Couldn't import pyvmomi. Please install pyvmomi using your favorite Packagemanager", file=sys.stderr)
    print("  e.g. pip3 install pyvmomi", file=sys.stderr)
    exit(255)

KEYRING_DISABLED = False
try:
    import keyring
    import secretstorage
    import dbus
except ImportError:
    print("Couldn't import keyring, secretstorage or dbus. "
          "Please install keyring, secretstorage and dbus using your favorite Packagemanager", file=sys.stderr)
    print("  e.g. pip3 install keyring secretstorage dbus-python", file=sys.stderr)
    print("       you may also need to install libdbus-glib-1-dev using apt", file=sys.stderr)
    KEYRING_DISABLED = True

PURPLE = '\033[95m'
CYAN = '\033[96m'
DARKCYAN = '\033[36m'
BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
END = '\033[0m'


def get_vm_info(virtual_machine):
    """
    Print information for a particular virtual machine or recurse into a
    folder with depth protection
    """
    # pp = pprint.PrettyPrinter(width=41, compact=True)
    name = virtual_machine.name
    guest = virtual_machine.guest.guestFullName
    moid = virtual_machine._moId
    pstate = virtual_machine.runtime.powerState
    version = virtual_machine.config.version

    if virtual_machine.summary.guest is not None:
        ip_address = virtual_machine.guest.ipAddress
        tools_version_status = virtual_machine.guest.toolsVersionStatus
        tools_version = virtual_machine.guest.toolsVersion
        # print(dir(virtual_machine.guest))
    else:
        ip_address = "-none-"
        tools_version_status = "-none-"
    path = []
    parent = virtual_machine.parent
    while parent.name != "vm":
        path.insert(0, parent.name)
        parent = parent.parent
    strpath = '/' + '/'.join(path)

    return name, pstate, moid, strpath, ip_address, version, tools_version, tools_version_status, guest


def make_host_summary(config, vms):
    host_dict = {}
    for vm in vms:
        if vm.runtime.host not in host_dict.keys():
            host_dict[vm.runtime.host] = {"poweredOn": 0, "suspended": 0, "poweredOff": 0}
        host_dict[vm.runtime.host][vm.runtime.powerState] += 1
    # print(host_dict)
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_NONE
    service_instance = connect.SmartConnect(host=config["host"],
                                            user=config["user"],
                                            pwd=config["pass"],
                                            port=config["port"],
                                            sslContext=context)

    content = service_instance.RetrieveContent()
    container = content.rootFolder  # starting point to look into
    view_type = [vim.HostSystem]  # object types to look for
    recursive = True  # whether we should look into it recursively
    container_view = content.viewManager.CreateContainerView(
        container, view_type, recursive)

    children = container_view.view

    table_head = ('Host', 'PoweredOn', 'Suspended', 'PoweredOff', 'Sum')
    table = [table_head]
    for hostid, stats in host_dict.items():
        try:
            hostname = [host.name for host in children if host == hostid][0]
        except IndexError:
            hostname = hostid._moId

        table.append((hostname, stats["poweredOn"], stats["suspended"], stats["poweredOff"],
                      sum([stats["poweredOn"], stats["suspended"], stats["poweredOff"]])))

    print_table(table)


def print_table(table):
    lentable = []
    # print(len(tablehead))
    for i in range(0, len(table[0]), 1):
        # print(i)
        clens = [len(str(x[i])) for x in table]
        clens.sort(reverse=True)
        lentable.append(clens[0])

    # print(lentable)
    counter = 0
    for row in table:
        for field in range(len(row)):
            if counter == 0:
                print(BOLD, end='', flush=True)

            if field == len(row) - 1:
                print(str(row[field]).ljust(lentable[field]))
            else:
                print(str(row[field]).ljust(lentable[field]) + END + ' | ', end='', flush=True)

        if counter == 0:
            print(END, end='', flush=True)
            for field in range(len(row)):
                if field == len(row) - 1:
                    print('-' * lentable[field])
                else:
                    print('-' * lentable[field] + "-+-", end='', flush=True)
        counter += 1


def make_vm_overview(children):

    table_head = ('Name', 'PowerState', 'MoID', 'Path', 'IP', 'Version', 'ToolsVersion',
                  'ToolsVersionStatus', 'Guest OS')
    table = [table_head]
    for child in children:
        # print(dir(child.summary))
        # pprint.pprint(child.summary)
        table.append(get_vm_info(child))

    print_table(table)


def make_cfg():

    home = os.environ["HOME"]
    print("No config found. Creating new...\n")
    if not os.path.exists("{}/.pymoid".format(home)):
        os.mkdir("{}/.pymoid".format(home), mode=0o700)
    config = {}
    user = getpass.getuser()
    config["host"] = input("vCenter Hostname [vcenter]: ")
    if config["host"] == "":
        config["host"] = "vcenter"
    config["port"] = input("vCenter Port [443]: ")
    config["user"] = input("vCenter Username [{}]: ".format(user))
    if config["user"] == "":
        config["user"] = user
    inp = input("Do you want to the password to be stored in {u}C{r}onfig, "
                "stored in the systems {u}K{r}eyring or {u}D{r}on't stored at all? [c/k/D] ".format(u=UNDERLINE, r=END))
    if inp.lower() == "c":
        pwd = getpass.getpass("vCenter Password for {}: ".format(config["user"]))
        config["pass"] = (base64.b64encode(''.join(chr(ord(a) ^ 142) for a in pwd).encode())).decode()
    elif inp.lower() == "k":
        if not KEYRING_DISABLED:
            pwd = getpass.getpass("vCenter Password for {}: ".format(config["user"]))
            keyring.set_password("pymoid@{}".format(config["host"]), config["user"], pwd)
            config["pass"] = "KEYRING"
        else:
            print("keyring not supported! falling back to ASK")
            config["pass"] = "ASK"
    else:
        config["pass"] = "ASK"

    if config["port"] == "":
        config["port"] = 443
    else:
        config["port"] = int(config["port"])

    print("writing config...")
    open("{}/.pymoid/config".format(home), 'w+').writelines(
        [json.dumps(config, sort_keys=True, indent=4, separators=(',', ': ')), '\n'])

    os.chmod("{}/.pymoid/config".format(home), mode=0o600)
    print("downloading server certificate...")
    cert = ssl.get_server_certificate((config["host"], config["port"]), ssl.PROTOCOL_TLSv1_2)

    open("{}/.pymoid/cert.pem".format(home), 'w+').writelines(cert)
    os.chmod("{}/.pymoid/cert.pem".format(home), mode=0o600)

    print("you can reset the configuration by deleting '~/.pymoid'")


def load_cfg(no_promt=False):
    home = os.environ["HOME"]
    if not os.path.exists("{}/.pymoid/config".format(home)):
        make_cfg()

    config = json.loads(''.join(open("{}/.pymoid/config".format(home), 'r').readlines()))
    if config["pass"] == "KEYRING" and not KEYRING_DISABLED:
        config["pass"] = keyring.get_password("pymoid@{}".format(config["host"]), config["user"])
        if (config["pass"] == "" or config["pass"] is None) and not no_promt:
            print("Password not found in keyring")
            config["pass"] = getpass.getpass("vCenter Password for {}: ".format(config["user"]))
            keyring.set_password("pymoid", config["user"], config["pass"])
    elif (config["pass"] == "ASK" or (config["pass"] == "KEYRING" and KEYRING_DISABLED)) and not no_promt:
        config["pass"] = getpass.getpass("vCenter Password for {}: ".format(config["user"]))
    else:
        config["pass"] = (''.join(chr(ord(a) ^ 142) for a in (base64.b64decode(config["pass"].encode())).decode()))

    config["port"] = int(config["port"])

    return config


def make_help(msg=""):
    print(msg)
    print("""
VMware MoID Python Script
{progname} [-c vm-moid] [-r] [-v] [-l] [-h]

    Called with out an argument will generate an overview table.
    
    Options:
    --connect=vm-moid, -c vm-moid    Connect to VMRC console by VM MoId
    
    --reset, -r                      Reset the current configuration
    
    --version, -v                    Print version and exit
    
    --licence, -l                    Print Licence and exit
    
    --help, -h                       Print this help and exit
    
    Configuration:
    the config is under {home}/.pymoid/config. 
    The configuration is in JSON with the options:
        - "host" which is the hostname of the vCenter
        - "port" which is the port
        - "user" which is your username to login
        - and "pass" which is your hashed password
    
    """.format(progname=sys.argv[0], home=os.environ["HOME"]))
    exit(1)


class PrintTo(threading.Thread):
    def __init__(self, stream, file):
        threading.Thread.__init__(self)
        self._stream = stream
        self._file = file
        pass

    def run(self):
        import re
        pattern = re.compile("^$")
        for line in self._stream:
            if "Gtk-WARNING" not in str(line) and "Gtk-Message" not in str(line) and not pattern.match(line):
                print(line, file=self._file)


def connect_moid(moid, config):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_NONE
    service_instance = connect.SmartConnect(host=config["host"],
                                            user=config["user"],
                                            pwd=config["pass"],
                                            port=config["port"],
                                            sslContext=context)

    content = service_instance.RetrieveContent()
    session_manager = content.sessionManager
    session = session_manager.AcquireCloneTicket()

    link = "vmrc://clone:{ticket}@{host}:{port}/?moid={moId}".format(ticket=session, host=config["host"],
                                                                     port=config["port"], moId=moid)

    if shutil.which("vmplayer") is not None:
        print("calling {}".format(' '.join(["vmplayer", link])))
        app = subprocess.Popen(["vmplayer", link], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True)
        tstdout = PrintTo(app.stdout, sys.stdout)
        tstderr = PrintTo(app.stderr, sys.stderr)
        tstdout.start()
        tstderr.start()
    elif shutil.which("vmrc") is not None:
        print("calling {}".format(' '.join(["vmrc", link])))
        app = subprocess.Popen(["vmrc", link], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True)
        tstdout = PrintTo(app.stdout, sys.stdout)
        tstderr = PrintTo(app.stderr, sys.stderr)
        tstdout.start()
        tstderr.start()
    else:
        vcenter_data = content.setting
        vcenter_settings = vcenter_data.setting
        for item in vcenter_settings:
            key = getattr(item, 'key')
            if key == 'VirtualCenter.FQDN':
                vcenter_fqdn = getattr(item, 'value')

        vc_cert = ssl.get_server_certificate((config["host"], config["port"]))
        vc_pem = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, vc_cert)
        vc_fingerprint = vc_pem.digest('sha1').decode()

        vmname = [vm.name for vm in get_vms(config) if vm._moId == moid][0]
        httplink = "https://{host}:9443/vsphere-client/webconsole.html?vmId={moid}&vmName={name}" \
                   "&host={fqdn}:{port}&sessionTicket={ticket}&thumbprint={fp}".format(
            ticket=session, host=config["host"], port=config["port"], moid=moid, fqdn=vcenter_fqdn,
            fp=vc_fingerprint, name=vmname)

        print("calling {}".format(' '.join(["xdg-open", httplink])))
        subprocess.call(["xdg-open", httplink], universal_newlines=True)


def get_vms(config):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_NONE
    service_instance = connect.SmartConnect(host=config["host"],
                                            user=config["user"],
                                            pwd=config["pass"],
                                            port=config["port"],
                                            sslContext=context)

    content = service_instance.RetrieveContent()
    container = content.rootFolder  # starting point to look into
    view_type = [vim.VirtualMachine]  # object types to look for
    recursive = True  # whether we should look into it recursively
    container_view = content.viewManager.CreateContainerView(
        container, view_type, recursive)

    return container_view.view


def main():
    try:
        options, remain = getopt.getopt(sys.argv[1:], 'rc:hvl', ['reset', 'connect=', 'help', 'version', 'licence'])
    except getopt.GetoptError as err:
        make_help(err.msg)

    home = os.environ["HOME"]

    if "--help" in [opt[0] for opt in options] or "-h" in [opt[0] for opt in options]:
        make_help()

    if "--version" in [opt[0] for opt in options] or "-v" in [opt[0] for opt in options]:
        print("VMware MoID Python Script 0.4   [powered by pyVmomi (vmware)]\n"
              "(c) Bennet Becker, 2017\n\n\n")
        exit(0)

    if "--licence" in [opt[0] for opt in options] or "-l" in [opt[0] for opt in options]:
        print("This Script is Licenced under: \n")
        print("""{}MIT License{}

Copyright (c) 2017 Bennet Becker <bbecker@pks.mpg.de>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.""".format(BOLD, END))

    if "--reset" in [opt[0] for opt in options] or "-r" in [opt[0] for opt in options]:
        print("Resetting Config...")
        try:
            keyring.delete_password("pymoid@{}".format(load_cfg(True)["host"]), load_cfg(True)["user"])
        except:
            pass
        try:
            os.remove("{}/.pymoid/config".format(home))
            os.remove("{}/.pymoid/cert.pem".format(home))
            os.removedirs("{}/.pymoid".format(home))
        except:
            pass

        exit(0)

    config = load_cfg()

    if "--connect" in [opt[0] for opt in options] or "-c" in [opt[0] for opt in options]:
        val = [opt[1] for opt in options if opt[0] == "--connect" or opt[0] == "-c"][0]
        connect_moid(val, config)

    if len(options) == 0:
        vms = get_vms(config)

        print(CYAN + BOLD + "Hostsystems" + END)
        make_host_summary(config, vms)
        print()
        print(CYAN + BOLD + "Virtual Machines" + END)
        make_vm_overview(vms)


if __name__ == '__main__':
    main()
