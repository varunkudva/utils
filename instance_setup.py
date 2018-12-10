#!/usr/bin/python
# vim:set ts=4 sw=4 expandtab:
import os
import re
import sys
sys.path.insert(
    0,
    '/usr/lib64/python2.6/site-packages/pycrypto-2.6.1-py2.6-linux-x86_64.egg')
import json
import fcntl
import shutil
import socket
import struct
import logging
import base64
import os.path
import urllib
import urllib2
import massedit
import argparse
import boto.ec2
import subprocess
import dns.resolver
import iptools
from time import sleep
from threading import Thread
from os.path import expanduser
from Crypto.PublicKey import RSA

CDH_PREFIX = 'cdh'
AN_NODE_PREFIX = 'an-node'
#CUSTOM_DATA_DIR = '/var/lib/waagent/CustomData'
CUSTOM_DATA_DIR = '/tmp/customBlob'
MDATA_URL = "http://169.254.169.254/metadata/instance{0}?api-version=2017-08-01&format=text"
PROVISIONED_FILE = '/var/lib/waagent/provisioned'


def generate_key_pair():
    """  Generate public & private RSA key pair """
    key = RSA.generate(2048, os.urandom)

    private_key = key.exportKey("PEM")
    ssh_rsa = '00000007' + base64.b16encode('ssh-rsa')

    exponent = '%x' % (key.e, )
    if len(exponent) % 2:
        exponent = '0' + exponent

    ssh_rsa += '%08x' % (len(exponent) / 2, )
    ssh_rsa += exponent

    modulus = '%x' % (key.n, )
    if len(modulus) % 2:
        modulus = '0' + modulus

    if modulus[0] in '89abcdef':
        modulus = '00' + modulus

    ssh_rsa += '%08x' % (len(modulus) / 2, )
    ssh_rsa += modulus

    public_key = ("ssh-rsa %s niara"
                  % (base64.b64encode(base64.b16decode(ssh_rsa.upper()))))

    return private_key, public_key


def get_external_ip(self):
    ''' Get the IP address using a external DNS server '''
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ['8.8.8.8']
    for i in my_resolver.query(self).response.answer:
        for j in i.items:
            return j.to_text()


def fix_ansible():
    ''' fix the ansible file '''
    massedit.edit_files(
        ['/etc/ansible/ansible.cfg'],
        ["re.sub(r'#host_key_checking = False', 'host_key_checking = False', line)"],
        dry_run=False)


def get_metadata_item(self):
    ''' Get a Metadata item '''
    return urllib2.urlopen(
        'http://169.254.169.254/2014-02-25/meta-data/' + self).read()


def fix_epel_repo():
    ''' Fix the EPEL repo '''
    filenames = ['/etc/yum.repos.d/epel.repo']
    massedit.edit_files(filenames,
                        ["re.sub(r'https', 'http', line)"],
                        dry_run=False)


def write_file(local_file, content, state):
    ''' Generic write file '''
    LOGGER.info("Attempting to write %s to %s", content, local_file)
    with open(local_file, state) as myfile:
        myfile.write(content)


def get_ip_address(ifname):
    ''' Get the IP address assigned '''
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(
        fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s',
                                                       ifname[:15]))[20:24]
    )


def setup_networking(hostname, options):
    ''' Configure networking to make CDH Happy '''
    ip_address = get_ip_address('eth0')

    # Set Localhostname
    LOGGER.info("Set sysconfig Hostname")
    write_file('/etc/sysconfig/hostname', 'HOSTNAME={0}'.format(hostname), 'w')
    os.system("hostname {0}".format(hostname))
    LOGGER.info("Updating /etc/sysconfig/network")
    files = ['/etc/sysconfig/network']
    edit = '^HOSTNAME=localhost.localdomain'
    edit1 = "HOSTNAME={0}.{1}".format(hostname, options.domain)
    massedit.edit_files(files,
                        ["re.sub(r'{0}', '{1}', line)".format(edit, edit1)],
                        dry_run=False)
    with open("/etc/hosts", "r") as sources:
        lines = sources.readlines()
    sources.close()
    if options.hosts is None:
        LOGGER.info("Updating /etc/hosts")
        with open("/etc/hosts", "w") as sources:
            for line in lines:
                if hostname in line:
                    continue
                sources.write(line)
            sources.write("{0}     {1}.{2} {1}".format(ip_address,
                                                       hostname,
                                                       options.domain))
        sources.close()

    LOGGER.info("Restarting Network Services")
    os.system("service network restart")


def get_instance_metadata(api):
    """ Get instance data using metadata service """
    api_url = MDATA_URL.format(api)
    header = {'Metadata': 'True'}
    req = urllib2.Request(url=api_url, headers=header)

    try:
        resp = urllib2.urlopen(req)
        data = resp.read()
        item = data.decode("utf-8")
        return item
    except urllib2.HTTPError as e:
        LOGGER.exception("HTTPError = {} {}".format(e.code, e.reason))
        raise Exception("Invalid API call")
    except urllib2.URLError as e:
        LOGGER.exception("URLError = {}".format(e.reason))
        raise Exception("Invalid API call")


class AutoVivification(dict):
    """Implementation of perl's autovivification feature."""

    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = type(self)()
            return value


def generate_hosts(options):
    """ Generate Hosts File and ansible stuff to distribute"""

    hosts = AutoVivification()
    try:
        LOGGER.info("Generating Master Files for %s nodes ", options.node_count)
    except AttributeError:
        LOGGER.info("Generating Master Files for the  nodes")

    ansible = ['[nodes]']
    yml = ['---',
           '- name: Setup hosts',
           '  hosts: nodes',
           '  remote_user: root',
           '  sudo: False',
           '  tasks:',
           '  - name: Upload Common Hosts',
           '    copy: src=/etc/hosts.new dest=/etc/hosts mode=644 force=yes']

    LOGGER.info("Creating new hosts file")
    filename = open("/etc/hosts.new", 'w')

    LOGGER.info("Opening the existing host file")

    with open("/etc/hosts", "r") as oldfilename:
        sources = oldfilename.readlines()

    LOGGER.info(
        "Closing the existing host file.. we've read the file into memory")
    oldfilename.close()

    LOGGER.info("Creating/Updating new hosts")

    for source in sources:
        alias = re.split('\s+', source)
        if alias[1] not in hosts and 'localhost' in alias[1]:
            filename.write(source)

    start_addr = options.custom_data['subnet_cdh_ip_start']
    subnet_addr = options.custom_data['subnet_cdh_prefix']
    end_addr = iptools.ipv4.cidr2block(subnet_addr)[1]
    ip = iter(iptools.IpRange(start_addr, end_addr))

    node_count = int(options.custom_data['node_count'])
    for nodeid in xrange(node_count+1):
        node_ip, hostname = None, None
        if nodeid == 0:
            # an-node
            node_ip = get_ip_address('eth0')
            hostname = AN_NODE_PREFIX
        else:
            node_ip = next(ip)
            hostname = '-'.join([CDH_PREFIX, str(nodeid)])

        print hostname, node_ip
        filename.write("{0} {1}.{2} {1}\n".format(
            node_ip, hostname, options.domain))

        hosts['ipmap'][node_ip] = hostname

        LOGGER.info("Creating the ansible playbook.. Keeping it in memory")

        ansible.append(hostname)
        yml.append('- hosts: {0}'.format(hostname))
        yml.append('  remote_user: root')
        yml.append('  sudo: False')
        yml.append('  tasks:')
        yml.append('    - name: Set Name {0}'.format(hostname))
        yml.append(
            "      copy: content='{0}' dest=/tmp/node mode=644 force=yes".format(hostname[-1]))
        yml.append('    - name: Disable epel repo')
        yml.append('      command: /usr/bin/yum-config-manager --disable epel')

    if options.domain == 'niarasystems.com':
        # This is only needed if the domain name is niarasystems.com.
        LOGGER.info("Getting the External IP address for bits")
        ext_ip = get_external_ip('bits.niarasystems.com')
        filename.write("{0}  {1} {2}\n".format(ext_ip,
                                               'bits.niarasystems.com',
                                               'bits'))
    filename.close()

    LOGGER.info("Replacing the original hosts file with the newly created one")
    shutil.copy('/etc/hosts.new', '/etc/hosts')

    LOGGER.info("Opening the ansible inventory file for writing")

    filename = open("/tmp/ansible_hosts", 'w')

    for item in ansible:
        filename.write("%s\n" % item)

    LOGGER.info("Closing the ansible_hosts file.. Done writing")

    filename.close()

    LOGGER.info("Writing the playbook from memory to /tmp/ansible_deploy")
    filename = open("/tmp/ansible_deploy", 'w')
    for item in yml:
        filename.write("%s\n" % item)
    LOGGER.info("Closing the ansible playbook.. We're done here!")
    filename.close()

    return hosts


def get_next_id(directory):
    ''' Get the next logical id in a directory '''
    try:
        self = str(len(os.listdir(directory)))
    except OSError:
        self = '0'
    makedirs("{0}/{1}".format(directory, self))
    return self


def lsblk():
    ''' Get all the physical volumes avail '''
    vols = subprocess.Popen(
        ['lsblk'],
        stdout=subprocess.PIPE,
     stderr=subprocess.STDOUT)
    blockdevs = [line.strip() for line in vols.stdout if 'disk' in line]
    returncode = vols.wait()
    if returncode:
        LOGGER.exception("Error with obtaining vol info with lslbl")
    return blockdevs


def check_mount(self):
    ''' Check if volume is mounted somewhere '''
    listdrives = subprocess.Popen('mount', shell=True, stdout=subprocess.PIPE)
    listdrivesout, err = listdrives.communicate()
    if err is not None:
        print err
        LOGGER.exception(err)
    for drives in listdrivesout.split('\n'):
        drive = drives.split(" ")
        if self in drive[0]:
            LOGGER.info("%s is mounted", drive[0])
            return True

    return False


def set_status_tag(instance_id, status, conn):
    ''' Set the status tag'''
    incr = 1
    while conn.create_tags(instance_id, {"Status": status}) is not True:
        sleep(incr * 2)
        incr += 1
    LOGGER.info("Updated Status to %s", status)


def get_drive_prefix():
    ''' Get the prefix of a drive '''
    blocks = lsblk()
    return blocks[0].split(" ")[0][0:-1]


def makedirs(path):
    ''' Generic recursive directory creation '''
    if not os.path.isdir(path):
        LOGGER.info("Creating dir at %s", path)
        try:
            os.makedirs(path)
        except OSError as exc:
            LOGGER.exception("Error: %s", exc)
            sys.exit(0)


def get_ephemeral_drives(deployment, hostname, es_drive):
    ''' Get the ephemeral/instance store drives '''
    drive_prefix = get_drive_prefix()
    self = {}
    vols_to_stripe = ''

    try:
        drives = get_metadata_item('block-device-mapping/')
        for vol in drives.split("\n"):
            if 'ephemeral' in vol:
                drive = get_metadata_item(
                    'block-device-mapping/{0}/'.format(vol))[-1]
                self[drive] = "{0}{1}".format(drive_prefix, drive)
                vols_to_stripe += " /dev/{0}{1}".format(drive_prefix,
                                                        drive)

        if deployment == 'prod' and hostname != 'an-node' and hostname != 'cdh-1' and es_drive is not None:
            drive_letter = es_drive[-1]
            self[drive_letter] = "{0}{1}".format(drive_prefix, drive_letter)
    except urllib2.HTTPError:
        pass

    vols_to_stripe = re.sub(r'^ ', '', vols_to_stripe)
    return vols_to_stripe, self


def update_fstab(path, vol):
    ''' Update the fstab entry so it will survive a reboot '''
    LOGGER.info("Setting up fstab for %s", vol)
    with open("/etc/fstab", "r") as sources:
        lines = sources.readlines()
    sources.close()
    with open("/etc/fstab1", "w") as sources:
        for line in lines:
            if vol in line:
                continue
            sources.write(line)
        sources.write("{0} ext4 defaults,noatime,nofail 0 0\n".format(path))
    sources.close()
    LOGGER.info("Copying working copy to /etc/fstab")
    shutil.copy2('/etc/fstab1', '/etc/fstab')


def setup_filesystem(self):
    ''' Setup Filessystem using mkfs '''
    LOGGER.info("Setting up Filesystem %s", self)
    try:
        os.system(
            'echo y | mkfs -q -t ext4 -T largefiles -m 0 {0}'.format(self))
    except OSError:
        print "Unable to run mkfs on {0}".format(self)
        LOGGER.exception("Unable to run mkfs on %s", self)


def make_filesystem(vol, path):
    ''' Setup the filesystem and then mount it '''
    LOGGER.info("Setting up Filesystem %s", vol)
    try:
        # thread.start_new_thread(setup_filesystem, (vol, ) ))
        Thread(target=setup_filesystem, args=(vol, )).start()
    except:
        print "Error: unable to start thread"
    update_fstab("{0} {1}".format(vol, path), vol)
    LOGGER.info("Updating /etc/fstab with %s", vol)


def check_mkfs():
    ''' Checking to see if mkfs is still running '''
    LOGGER.info("/sbin/mkfs is active and building a filesystem(s).."
                "  Check /var/log/messages for errors")
    exist = True
    sleep(2)
    while exist is True:
        exist = False
        proc = subprocess.Popen("ps -U 0", shell=True, stdout=subprocess.PIPE)
        if 'mkfs' in proc.stdout.read():
            sleep(5)
            exist = True
    LOGGER.info("/sbin/mkfs is finished.")


def setup_ebs_volumes(es_drives, security_group, deployment, tags):
    ''' Setup the EBS volumes '''
    for volume in sorted(lsblk()):
        vol = volume.split(' ')[0]
        if vol == 'xvda' or vol == 'sda':
            continue
        try:
            if (check_mount(vol) is False and
                    'sgHadoopClustermembers' in security_group and
                    deployment == 'prod' and
                    "xvd{0}".format(tags['es_drives'][-1]) == vol):
                LOGGER.info("Creating Volume on %s for es", vol)
                make_filesystem(
                    "/dev/{0}".format(vol),
                    '/es/{0}'.format(get_next_id('/es')))
                es_drives.pop(vol[-1], None)
                continue
        except (KeyError, TypeError):
            pass

        if check_mount(vol) is False and vol not in es_drives.itervalues():
            LOGGER.info("Creating Volume on %s for grid", vol)
            make_filesystem("/dev/{0}".format(vol),
                            "/grid/{0}".format(get_next_id('/grid')))

    return es_drives


def setup_ephemeral_drives(es_drives, hostname, vols_to_stripe):
    ''' Setup the Ephemeral Drives '''
    if 'ephemeral' not in get_metadata_item('block-device-mapping/'):
        makedirs('/data')
        return
    if len(es_drives) > 1:
        eph_count = str(len(vols_to_stripe.split(' ')))
        mount_point = "{0}:0".format(hostname)
        try:
            os.system("echo 'yes' | mdadm --create --verbose "
                      "/dev/md/{0} --level=stripe --raid-devices={1} {2}"
                      .format(mount_point, eph_count, vols_to_stripe))
            vols_to_stripe = "/dev/md/{0}".format(mount_point)
        except OSError as err:
            LOGGER.exception(err)
            vols_to_stripe = "/dev/md/{0}".format(mount_point)
    makedirs('/data')
    make_filesystem(vols_to_stripe, '/data')


def error_message(error, sleep_time):
    ''' Caputuring error messages '''
    if 'Rate exceeded' in error.message:
        LOGGER.exception(error)
        sleep(sleep_time)
        sleep_time += 1
    return sleep_time


def setup_ssh(hosts):
    ''' Setup SSH so we can talk to each node '''
    LOGGER.info("Setting up SSH")

    # Update authorized keys
    for directory in ['/home/ec2-user', '/root', '/niaraadmin']:
        if os.path.isdir(directory) is False:
            continue
        if os.path.isdir(directory + '/.ssh') is False:
            os.system('service iptables stop')
            os.system('echo 0 > /selinux/enforce')
            os.system(
                'ssh-keygen -t rsa  -f {0}/.ssh/id_rsa -q -N ""'.format(directory))
            os.chmod(directory + "/.ssh", 0o755)
            if os.path.isfile(directory + "/.ssh/authorized_keys") is False:
                os.mknod(directory + "/.ssh/authorized_keys")

            os.chmod(directory + "/.ssh/authorized_keys", 0o644)

        try:
            with open(directory + "/.ssh/authorized_keys", "r") as sources:
                lines = sources.readlines()
        except IOError:
            lines = []

        with open(directory + "/.ssh/authorized_keys", "w") as sources:
            for line in lines:
                if 'niara' in line or line.startswith('\n'):
                    continue
                if 'no-port-forwarding' in line:
                    line = "ssh-rsa {0}".format(line.split('ssh-rsa')[1])
                sources.write(line)
            sources.write(hosts['public_key'] + '\n')

        try:
            with open(directory + "/.ssh/id_rsa", "w") as sources:
                sources.write(hosts['private_key'])
            sources.close()
            os.chmod(directory + "/.ssh/id_rsa", 0o400)
        except KeyError:
            continue

        with open(directory + "/.ssh/id_rsa.pub", "w") as sources:
            sources.write(hosts['public_key'] + '\n')

        sources.close()

        if directory == '/home/ec2-user':
            os.system('chown ec2-user:ec2-user /home/ec2-user/.ssh/*')
        elif directory == '/home/niaraadmin':
            os.system('chown niaraadmin:niaraadmin /home/niaraadmin/.ssh/*')

        sources.close()

        os.chmod(directory + "/.ssh/authorized_keys", 0o600)
        os.chmod(directory + "/.ssh/id_rsa.pub", 0o644)


def generate_my_hostname(options):
    """ This generates non an-node hostnames """
    while options.node is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the port
        server_address = (get_ip_address('eth0'), 10000)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(server_address)
        sock.listen(1)
        LOGGER.info("Waiting for a connection")
        connection, client_address = sock.accept()
        LOGGER.info("Connection Made at %s", str(client_address))
        while True:
            try:
                options.node = connection.recv(4096)
                data = json.loads(options.node)
                connection.sendall("OK")
                connection.close()
                sock.close()
                break
            except (EOFError, ValueError, socket.error):
                connection.sendall("Error")
                sleep(1)
                continue
            break

    options.node = data
    sock.close()

    LOGGER.info("Node name assigned: %s", options.node['id'])
    LOGGER.info("Data Bits %s", options.node)
    setup_ssh(options.node)
    return options.node['id']


def release_nodes(hosts):
    """ Releases the non an-nodes to finish """
    for node in hosts['ipmap']:
        if 'an-node' in hosts['ipmap'][node] or str(
                get_ip_address('eth0')) == node:
            continue

        # Create the data blob
        data = json.dumps(
            {'id': hosts['ipmap'][node],
             'public_key': hosts['public_key']})
        LOGGER.info("Data Blob %s", data)

        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect the socket to the port where the server is listening
        server_address = (node, 10000)
        LOGGER.info("Connecting to %s on port 10000", node)
        sock.connect(server_address)
        attempt = 1
        while True:
            try:
                # Set the whole string
                sock.sendall(data)
                recv = sock.recv(4096)
                if recv == 'Error':
                    attempt += 1
                    continue
                else:
                    break
            except:
                # Send failed
                LOGGER.info("Warning: Resending data blob to %s", node)
                attempt += 1
                continue
        sock.close()

        LOGGER.info("Attempts %s", str(attempt))
        LOGGER.info("Transmitted data blob to %s", node)


def configure_instance(options):
    """ Configure instance for analyzer """

    #fix_epel_repo()
    fix_ansible()

    try:
        # Get stackname and instance_name using metadata service
        options.instance_name = get_instance_metadata('/compute/name')
        options.stackname = get_instance_metadata('/compute/resourceGroupName')
    except Exception as e:
        LOGGER.exception("Cant identify instance {0}".format(e))
        sys.exit(3)

    while not os.path.isfile(PROVISIONED_FILE):
        LOGGER.info("Waiting for provisioning to finish")
        sleep(10)

    if 'an-node' in options.instance_name:
        # an-node
        options.hostname = AN_NODE_PREFIX

        while not os.path.isfile(CUSTOM_DATA_DIR):
            LOGGER.info("Waiting for {0} file".format(CUSTOM_DATA_DIR))
            sleep(10)

        with open(CUSTOM_DATA_DIR) as fd:
            options.custom_data = json.loads(fd.read())

        hosts = generate_hosts(options)

        hosts['private_key'], hosts['public_key'] = generate_key_pair()
        setup_ssh(hosts)
        os.system(
            'cat /home/niaraadmin/.ssh/authorized_keys >> /root/.ssh/authorized_keys')
        sleep(60)

        release_nodes(hosts)
        LOGGER.info("Waiting 60 secs until the SSH has been deployed")
        sleep(60)
        options.ansible_fail = False

        try:
            os.system(
                "/usr/bin/ansible-playbook -i /tmp/ansible_hosts /tmp/ansible_deploy >> /var/log/niara_analyzer.log")
        except OSError:
            LOGGER.info("Ansible Didn't deploy correctly..  Trying again later")
            options.ansible_fail = True
            pass

        with open('/etc/stackname', "w") as fd:
            fd.write(options.stackname)

        # Tells installer that the analyzer is using a ext VPC
        with open('/etc/private-vpc', "w") as privatevpc:
            privatevpc.write('1')
    else:
        # cdh-nodes
        options.hostname = generate_my_hostname(options)

    LOGGER.info("This instance will be configured as %s", options.hostname)
    setup_networking(options.hostname, options)


    vols_to_stripe, es_drives = get_ephemeral_drives(options.deployment,
                                                     options.hostname,
                                                     None)
    if len(es_drives) == 0:
        makedirs('/data')
    else:
        setup_ephemeral_drives(es_drives, options.hostname, vols_to_stripe)

    es_drives = setup_ebs_volumes(es_drives,
                                  None,
                                  options.deployment,
                                  None)
    check_mkfs()

    LOGGER.info("Mounting newly created filesystems")
    os.system('mount -a')

    if 'an-node' in options.hostname and options.ansible_fail is True:
        try:
            LOGGER.info("Ansible Retry")
            os.system(
                "/usr/bin/ansible all -m copy -a 'src=/etc/hosts dest=/etc/hosts' >> /var/log/niara_analyzer.log")
        except OSError:
            LOGGER.info("Ansible is Unable to connect to all nodes")
            sys.exit(1)

    os.mknod("/tmp/done")

    if os.path.isfile('/boot/initramfs-2.6.32-504.el6.x86_64.img-old') is True:
        try:
            os.system('package-cleanup -y --oldkernels --count=2')
            os.remove('/boot/initramfs-2.6.32-504.el6.x86_64.img-old')
            os.system('tune2fs -m 1 /dev/sda1')
        except OSError:
            pass

    LOGGER.info("Instance setup finished")
    subprocess.call('/root/setup/fix-conf', shell=True)


def parse_args():
    """Main arguement parser """

    parser = argparse.ArgumentParser(
        description="Setup a node to be ready for ansible")
    parser.add_argument("-n",
                        "--node",
                        type=str,
                        help="Manually run as a specific",
                        required=False)
    parser.add_argument("--domain",
                        type=str,
                        help="DNS Domain",
                        required=False,
                        default="niarasystems.com")
    parser.add_argument("--hosts",
                        help="Generate a hosts file",
                        action='store_true',
                        default=False)
    parser.add_argument("--proxy",
                        help="Proxy Host",
                        type=str,
                        required=False)
    parser.add_argument("--proxy_http_port",
                        help="Proxy HTTP Port",
                        type=str,
                        required=False)
    parser.add_argument("--proxy_https_port",
                        help="Proxy HTTPS Port",
                        type=str,
                        required=False)
    parser.add_argument("--proxy_pass",
                        help="Proxy Pass",
                        type=str,
                        required=False)
    parser.add_argument("--proxy_user",
                        help="Proxy Username",
                        type=str,
                        required=False)
    parser.add_argument("--hostname",
                        type=str,
                        help="Set Hostname",
                        required=False)
    parser.add_argument("--enableproxy",
                        help="Enables the Proxy",
                        action='store_true',
                        default=False)
    parser.add_argument("--nowait",
                        help="For external dependencies, this can be enabled",
                        action='store_true',
                        default=False)
    parser.add_argument("--novpc",
                        help="Launched Without a VPC",
                        action='store_true',
                        default=False)
    parser.add_argument("--stackname",
                        type=str,
                        help="Set Stackname",
                        required=False)
    parser.add_argument("--cloud_type",
                        type=str,
                        help="Cloud Type aws or azure (default: %(default)s)",
                        required=False,
                        default='azure')
    parser.add_argument("--deployment",
                        type=str,
                        help="Prod, Sandbox, etc",
                        required=False)

    args = parser.parse_args()

    # XXX
    for k in args.__dict__:
        if args.__dict__[k] == 'None':
            args.__dict__[k] = None

    return args

if __name__ == "__main__":

    LOGGER = logging.getLogger('an-startup')
    LOGGER.setLevel(logging.DEBUG)
    # add a file handler
    if not os.path.isfile:
        write_file('/var/log/niara_analyzer.log', '', 'w')
        os.chmod("/var/log/niara_analyzer.log", 0o600)

    FILEHANDLE = logging.FileHandler('/var/log/niara_analyzer.log')
    FILEHANDLE.setLevel(logging.INFO)
    # create a formatter and set the formatter for the handler.
    FRMT = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    FILEHANDLE.setFormatter(FRMT)

    # add the Handler to the logger
    LOGGER.addHandler(FILEHANDLE)

    options = parse_args()
    configure_instance(options)
