#!/usr/bin/python
# vim:set ts=4 sw=4 expandtab:
'''
Copyright (C) 2013-2015 by Niara, Inc.
All Rights Reserved.
This software is an unpublished work and is protected by copyright and
trade secret law.  Unauthorized copying, redistribution or other use of
this work is prohibited.
The above notice of copyright on this source code product does not indicate
any actual or intended publication of such source code.
'''
import os
import re
import sys
sys.path.insert(0, '/usr/lib64/python2.6/site-packages/pycrypto-2.6.1-py2.6-linux-x86_64.egg')
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
from time import sleep
from threading import Thread
from os.path import expanduser
from Crypto.PublicKey import RSA


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


def hostname_resolves(hostname):
    ''' Resolve hostname '''
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        LOGGER.exception("Hostname Error")
        return False


def fix_ansible():
    ''' fix the ansible file '''
    massedit.edit_files(['/etc/ansible/ansible.cfg'],
                        ["re.sub(r'#host_key_checking = False', 'host_key_checking = False', line)"],
                        dry_run=False)


def get_metadata_item(self):
    ''' Get a Metadata item '''
    return urllib2.urlopen('http://169.254.169.254/2014-02-25/meta-data/' + self).read()


def fix_epel_repo():
    ''' Fix the EPEL repo '''
    filenames = ['/etc/yum.repos.d/epel.repo']
    massedit.edit_files(filenames,
                        ["re.sub(r'https', 'http', line)"],
                        dry_run=False)


def fix_cloudinit():
    ''' Fix the cloudinit so that the name stays consistant '''
    filenames = ['/etc/cloud/cloud.cfg']
    massedit.edit_files(filenames,
                        ["re.sub(r'preserve_hostname: false', 'preserve_hostname: true', line)"],
                        dry_run=False)


def write_file(local_file, content, state):
    ''' Generic write file '''
    LOGGER.info("Attempting to write %s to %s", content, local_file)
    with open(local_file, state) as myfile:
        myfile.write(content)
    myfile.close()


def get_ip_address(ifname):
    ''' Get the IP address assigned '''
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(sock.fileno(),
                                        0x8915,
                                        struct.pack('256s',
                                                    ifname[:15]))
                            [20:24])


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

    LOGGER.info("Fixing CloudInit")
    if options.cloud_type == 'aws':
        fix_cloudinit()
    LOGGER.info("Restarting Network Services")
    os.system("service network restart")


class AutoVivification(dict):
    """Implementation of perl's autovivification feature."""
    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = type(self)()
            return value


def generate_hosts(stackname, conn, options):
    """ Generate Hosts File and ansible stuff to distribute"""
    hosts = AutoVivification()
    try:
        LOGGER.info("Generating Master Files for %s nodes ", options.node_count)
    except AttributeError:
        LOGGER.info("Generating Master Files for the  nodes")
        hosts['instances'] = options.hosts['instances']
        hosts['types'] = options.hosts['types']
    ansible = ['[nodes]']
    # List of ASGs
    roles = {'ESNODEASG1': 'es',
             'ANNODEASG1': 'an-node',
             'CDHNODEASG1': 'cdh',
             'CDHNODEASG11': 'cdh'}

    yml = ['---',
           '- name: Setup hosts',
           '  hosts: nodes',
           '  remote_user: root',
           '  sudo: False',
           '  tasks:',
           '  - name: Upload Common Hosts',
           '    copy: src=/etc/hosts.new dest=/etc/hosts mode=644 force=yes']

    LOGGER.info("Creating Instance Hash")

    if options.cloud_type == 'aws':
        for instance in get_instances(stackname, conn):
            if instance.tags['Name'].endswith('-nat-instance'):
                continue
            # Testing to see if this is a ASG if not makinga psuedo assignment.
            if instance.tags['aws:cloudformation:logical-id'] not in roles:
                if '-cdh-1' in instance.tags['Name']:
                    instance.tags['aws:cloudformation:logical-id'] = 'CDHNODEASG11'
                elif '-cdh-' in instance.tags['Name']:
                    instance.tags['aws:cloudformation:logical-id'] = 'CDHNODEASG1'
                elif instance.tags['aws:cloudformation:logical-id'].endswith('annode'):
                    instance.tags['aws:cloudformation:logical-id'] = 'ANNODEASG1'
                else:
                    instance.tags['aws:cloudformation:logical-id'] = 'ESNODEASG1'

            try:
                hosts['types'][instance.tags['aws:cloudformation:logical-id']]['count'] += 1
            except TypeError:
                hosts['types'][instance.tags['aws:cloudformation:logical-id']]['count'] = 1
                hosts['types'][instance.tags['aws:cloudformation:logical-id']]['current'] = 1

            hosts['instances'][instance.id]['id'] = instance.id
            hosts['instances'][instance.id]['ip'] = instance.private_ip_address
            hosts['instances'][instance.id]['type'] = instance.tags['aws:cloudformation:logical-id']

    LOGGER.info("Creating new hosts file")
    filename = open("/etc/hosts.new", 'w')

    LOGGER.info("Opening the existing host file")

    with open("/etc/hosts", "r") as oldfilename:
        sources = oldfilename.readlines()

    LOGGER.info("Closing the existing host file.. we've read the file into memory")
    oldfilename.close()

    LOGGER.info("Creating/Updating the host file")

    for source in sources:
        alias = re.split('\s+', source)
        if alias[1] not in hosts and 'localhost' in alias[1]:
            filename.write(source)

    for instance in hosts['instances']:
        if hosts['instances'][instance]['type'] == 'NATinstance':
            continue
        if hosts['instances'][instance]['type'] == 'ANNODEASG1':
            hostname = 'an-node'
        if hosts['instances'][instance]['type'] == 'CDHNODEASG11':
            hostname = 'cdh-1'
        if hosts['instances'][instance]['type'] == 'CDHNODEASG1' and hosts['types'][hosts['instances'][instance]['type']]['current'] == 1:
            hosts['types'][hosts['instances'][instance]['type']]['current'] += 1

        try:
            filename.write("{0}  {1}.{2} {1}\n".format(hosts['instances']
                                                       [instance]
                                                       ['ip'],
                                                       hostname,
                                                       options.domain))
            hosts['ipmap'][hosts['instances'][instance]['ip']] = hostname
        except UnboundLocalError:
            hostname = "{0}-{1}".format(roles[hosts['instances'][instance]['type']],
                                        hosts['types'][hosts['instances'][instance]['type']]['current'])

            filename.write("{0}  {1}.{2} {1}\n".format(hosts['instances'][instance]['ip'],
                                                       hostname,
                                                       options.domain))
            hosts['types'][hosts['instances'][instance]['type']]['current'] += 1
            hosts['ipmap'][hosts['instances'][instance]['ip']] = hostname

        LOGGER.info("Creating the ansible playbook.. Keeping it in memory")

        ansible.append(hostname)
        yml.append('- hosts: {0}'.format(hostname))
        yml.append('  remote_user: root')
        yml.append('  sudo: False')
        yml.append('  tasks:')
        yml.append('    - name: Set Name {0}'.format(hostname))
        yml.append("      copy: content='{0}' dest=/tmp/node mode=644 force=yes".format(hostname[-1]))
        yml.append('    - name: Disable epel repo')
        yml.append('      command: /usr/bin/yum-config-manager --disable epel')

        del hostname

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


def verify_nodes(options):
    ''' Verify that the appropriate nodes are online '''

    LOGGER.info("Attempting to locate %s nodes", options.node_count)
    node_count = []
    LOGGER.info("1st Node Count mismatch %s/%s", str(len(node_count)), options.node_count)

    while len(node_count) != int(options.node_count):
        filters = {"tag:aws:cloudformation:stack-name": options.stackname,
                   "instance-state-name": 'running',
                   "tag:Status": "listening"}

        LOGGER.info("Filters -> %s", str(filters))
        sleep_time = 1
        try:
            reservations = options.conn.get_all_instances(filters=filters)
            node_count = [i for r in reservations for i in r.instances]
        except boto.exception.BotoServerError, error:
            if 'Rate exceeded' in error.message:
                LOGGER.exception(error)
                sleep(sleep_time)
                sleep_time += 1
                node_count = []
        if len(node_count) != int(options.node_count):
            LOGGER.info("Node Count mismatch %s/%s",
                        str(len(node_count)),
                        options.node_count)
            sleep(30)
        else:
            LOGGER.info("%s/%s Nodes Found.  Moving forward",
                        str(len(node_count)),
                        options.node_count)
    return


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
    vols = subprocess.Popen(['lsblk'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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
                drive = get_metadata_item('block-device-mapping/{0}/'.format(vol))[-1]
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
        os.system('echo y | mkfs -q -t ext4 -T largefiles -m 0 {0}'.format(self))
    except OSError:
        print "Unable to run mkfs on {0}".format(self)
        LOGGER.exception("Unable to run mkfs on %s", self)


def make_filesystem(vol, path):
    ''' Setup the filesystem and then mount it '''
    LOGGER.info("Setting up Filesystem %s", vol)
    try:
        #thread.start_new_thread(setup_filesystem, (vol, ) ))
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
                make_filesystem("/dev/{0}".format(vol), '/es/{0}'.format(get_next_id('/es')))
                es_drives.pop(vol[-1], None)
                continue
        except (KeyError, TypeError):
            pass

        if check_mount(vol) is False and vol not in es_drives.itervalues():
            LOGGER.info("Creating Volume on %s for grid", vol)
            make_filesystem("/dev/{0}".format(vol),
                            "/grid/{0}".format(get_next_id('/grid')))

    return es_drives


def set_aws_hostname(hostname, conn, instance_id):
    ''' Set the AWS Hostname '''
    incr = 1
    while conn.create_tags(instance_id, {"Name": hostname}) is not True:
        sleep(incr * 2)
    incr += 1


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


def get_instances(stackname, conn):
    """ Get instances for a specific stack """
    filters = {"tag:Name": "{0}-*".format(stackname), "instance-state-name": 'running'}
    LOGGER.info("Filters -> %s", str(filters))

    reservations = []
    sleep_time = 1

    while len(reservations) < 1:
        try:
            reservations = conn.get_all_instances(filters=filters)
            instances = [i for r in reservations for i in r.instances]
            return instances
        except boto.exception.BotoServerError, error:
            if 'Rate exceeded' in error.message:
                LOGGER.exception(error)
                sleep(sleep_time)
                sleep_time += 1
                reservations = []


def error_message(error, sleep_time):
    ''' Caputuring error messages '''
    if 'Rate exceeded' in error.message:
        LOGGER.exception(error)
        sleep(sleep_time)
        sleep_time += 1
    return sleep_time


def setup_ssh(self):
    ''' Setup SSH so we can talk to each node '''
    LOGGER.info("Setting up SSH")

    ##  Update authorized keys

    for directory in ['/home/ec2-user', '/root', '/niaraadmin']:
        if os.path.isdir(directory) is False:
            continue
        if os.path.isdir(directory + '/.ssh') is False:
            os.system('service iptables stop')
            os.system('echo 0 > /selinux/enforce')
            os.system('ssh-keygen -t rsa  -f {0}/.ssh/id_rsa -q -N ""'.format(directory))
            os.chmod(directory + "/.ssh", 0755)
            if os.path.isfile(directory + "/.ssh/authorized_keys") is False:
                os.mknod(directory + "/.ssh/authorized_keys")

            os.chmod(directory + "/.ssh/authorized_keys", 0644)

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
            sources.write(self['public_key'] + '\n')

        try:
            with open(directory + "/.ssh/id_rsa", "w") as sources:
                sources.write(self['private_key'])
            sources.close()
            os.chmod(directory + "/.ssh/id_rsa", 0400)
        except KeyError:
            continue

        with open(directory + "/.ssh/id_rsa.pub", "w") as sources:
            sources.write(self['public_key'] + '\n')

        sources.close()

        if directory == '/home/ec2-user':
            os.system('chown ec2-user:ec2-user /home/ec2-user/.ssh/*')
        elif directory == '/home/niaraadmin':
            os.system('chown niaraadmin:niaraadmin /home/niaraadmin/.ssh/*')

        sources.close()

        os.chmod(directory + "/.ssh/authorized_keys", 0600)
        os.chmod(directory + "/.ssh/id_rsa.pub", 0644)


def generate_my_hostname(options):
    """ This generates non an-node hostnames """
    if options.cloud_type == 'aws':
        set_status_tag(options.instance_id, 'listening', options.conn)
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


def release_nodes(self):
    """ Releases the non an-nodes to finish """
    for node in self['ipmap']:
        if 'an-node' in self['ipmap'][node] or str(get_ip_address('eth0')) == node:
            continue

        # Create the data blob
        data = json.dumps({'id': self['ipmap'][node], 'public_key': self['public_key']})
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
                #Set the whole string
                sock.sendall(data)
                recv = sock.recv(4096)
                if recv == 'Error':
                    attempt += 1
                    continue
                else:
                    break
            except:
                #Send failed
                LOGGER.info("Warning: Resending data blob to %s", node)
                attempt += 1
                continue
        sock.close()

        LOGGER.info("Attempts %s", str(attempt))
        LOGGER.info("Transmitted data blob to %s", node)


def configure_instance(options):
    ''' Start of it all '''
    if options.cloud_type == 'aws':
        region = get_metadata_item('placement/availability-zone/')[:-1]
        options.instance_id = get_metadata_item('instance-id/')
        reload(boto.ec2)
        options.conn = boto.ec2.connect_to_region(region)

        reservations = []
        sleep_time = 1

        while len(reservations) < 1:
            try:
                reservations = options.conn.get_all_instances(options.instance_id)
                instances = [i for r in reservations for i in r.instances]
                LOGGER.info("Successfully connected to AWS %s", vars(instances[0]))
                options.deployment = instances[0].tags['Deployment']
                LOGGER.info("This is a %s deployement", options.deployment)
                options.stackname = instances[0].tags['aws:cloudformation:stack-name']
                LOGGER.info("This is part of the %s stack", options.stackname)
                options.hostname = instances[0].tags['Name']
                LOGGER.info("The preliminary name of this node is %s", options.hostname)
            except (boto.exception.BotoServerError, KeyError), error:
                sleep_time = error_message(error, sleep_time)
                LOGGER.info("Sleeping..  Unable to access AWS info... sleeping %s", sleep_time)
                reservations = []
                sleep(30)

    if options.enableproxy is True:
        setup_proxy(options)

    # fix_epel_repo()

    fix_ansible()

    if 'an-node' in options.hostname:
        if options.nowait is False:
            while not os.path.isfile('/tmp/analyzer-go'):
                LOGGER.info("Waiting for the /tmp/analyzer-go file")
                sleep(15)

        if options.cloud_type == 'aws':
            options.node_count = instances[0].tags['nodes']
            LOGGER.info("Verifying Nodes %s", options.node_count)
            verify_nodes(options)

        if options.nowait is False:
            while not os.path.isfile('/tmp/analyzer-go'):
                LOGGER.info("Waiting for the /tmp/analyzer-go file")
                sleep(15)

        if options.cloud_type != 'aws':
            # extract pre-processd hosts analyzer-go file
            with open('/tmp/analyzer-go', 'r') as hostblob:
                options.hosts = json.loads(hostblob.read())
            options.conn = None

        hosts = generate_hosts(options.stackname, options.conn, options)

        hosts['private_key'], hosts['public_key'] = generate_key_pair()
        setup_ssh(hosts)

        if options.cloud_type != 'aws':
            os.system('cat /home/niaraadmin/.ssh/authorized_keys >> /root/.ssh/authorized_keys')
            sleep(60)

        release_nodes(hosts)
        LOGGER.info("Waiting 60 secs until the SSH has been deployed")
        sleep(60)
        options.ansible_fail = False

        try:
            os.system("/usr/bin/ansible-playbook -i /tmp/ansible_hosts /tmp/ansible_deploy >> /var/log/niara_analyzer.log")
        except OSError:
            LOGGER.info("Ansible Didn't deploy correctly..  Trying again later")
            options.ansible_fail = True
            pass

        if os.path.isfile('/root/.boto') is True or options.cloud_type == 'azure':
            with open('/etc/stackname', "w") as stackname:
                stackname.write(options.stackname)
            stackname.close()

        # Tells installer that the analyzer is using a ext VPC
        if options.novpc is True or options.cloud_type == 'azure':
            with open('/etc/private-vpc', "w") as privatevpc:
                privatevpc.write('1')
    else:
        options.hostname = generate_my_hostname(options)

    LOGGER.info("This instance will be configured as %s", options.hostname)
    setup_networking(options.hostname, options)

    try:
        vols_to_stripe, es_drives = get_ephemeral_drives(options.deployment,
                                                         options.hostname,
                                                         instances[0].tags['es_drives'])
    except (AttributeError, UnboundLocalError, KeyError):
        vols_to_stripe, es_drives = get_ephemeral_drives(options.deployment,
                                                         options.hostname,
                                                         None)

    if len(es_drives) == 0:
        makedirs('/data')
    else:
        setup_ephemeral_drives(es_drives, options.hostname, vols_to_stripe)

    try:
        es_drives = setup_ebs_volumes(es_drives,
                                      get_metadata_item('security-groups/'),
                                      options.deployment,
                                      instances[0].tags)
        if options.hostname is not None:
            set_aws_hostname("{0}-{1}".format(options.stackname,
                                              options.hostname),
                             options.conn,
                             options.instance_id)
    except urllib2.HTTPError:
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
            os.system("/usr/bin/ansible all -m copy -a 'src=/etc/hosts dest=/etc/hosts' >> /var/log/niara_analyzer.log")
        except OSError:
            LOGGER.info("Ansible is Unable to connect to all nodes")
            sys.exit(1)

    if options.cloud_type == 'aws':
        set_status_tag(options.instance_id, 'completed', options.conn)
    else:
        os.mknod("/tmp/done")

    if os.path.isfile('/boot/initramfs-2.6.32-504.el6.x86_64.img-old') is True:
        try:
            os.system('package-cleanup -y --oldkernels --count=2')
            os.remove('/boot/initramfs-2.6.32-504.el6.x86_64.img-old')
            os.system('tune2fs -m 1 /dev/sda1')
        except OSError:
            pass


def setup_proxy(options):
    """ Configure Proxy Setting for Boto and install script"""
    home = expanduser("~")
    LOGGER.info("Setting up proxy")

    try:
        with open(home + "/.boto", "r") as sources:
            lines = sources.readlines()
        sources.close()
    except:
        lines = []

    with open(home + "/boto.cfg1", "w") as sources:
        if len(lines) == 0:
            sources.write('[Boto]\n')
            sources.write('Debug = 0\n')
            sources.write('num_retries = 10\n')

        for line in lines:
            if 'proxy' in line:
                continue
            sources.write(line)

        if options.proxy is not None:
            sources.write("proxy = {}\n".format(options.proxy))
        if options.proxy_http_port is not None:
            sources.write("proxy_port = {}\n".format(options.proxy_http_port))
        if options.proxy_user is not None:
            sources.write("proxy_user = {}\n".format(options.proxy_user))
        if options.proxy_pass is not None:
            sources.write("proxy_pass = {}\n".format(options.proxy_pass))

    sources.close()

    no_proxy = ['an-node', 'localhost']

    for num in range(1, 26, 1):
        no_proxy.append("cdh-{0},es-{0}".format(num))

    with open(home + "/.bashrc", "a") as bashrc:
        bashrc.write('export no_proxy=' +",".join(no_proxy) + '\n')

        if options.proxy_user is not None and options.proxy_pass is not None:
            options.proxy_pass = urllib.quote_plus(options.proxy_pass)
            bashrc.write('export http_proxy=http://{0}:{1}@{2}:{3}'.format(options.proxy_user,
                                                                           options.proxy_pass,
                                                                           options.proxy,
                                                                           options.proxy_http_port))

            bashrc.write('export HTTPS_PROXY=https://{0}:{1}@{2}:{3}'.format(options.proxy_user,
                                                                             options.proxy_pass,
                                                                             options.proxy,
                                                                             options.proxy_https_port))
        else:
            bashrc.write('export http_proxy=http://{0}:{1}'.format(options.proxy,
                                                                   options.proxy_http_port))

            bashrc.write('export HTTPS_PROXY=https://{0}:{1}'.format(options.proxy,
                                                                     options.proxy_https_port))

    LOGGER.info("Updating Copy to %s/.boto", home)
    shutil.copy2(home + '/boto.cfg1', home + '/.boto')


def main():
    """Main arguement parser """
    parser = argparse.ArgumentParser(description="Setup a node to be ready for ansible")
    parser.add_argument("-n",
                        "--node",
                        type=str,
                        help="Manually run as a specific",
                        required=False)
    parser.add_argument("--domain",
                        type=str,
                        help="DNS Domain",
                        required=False)
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
                        default='aws')
    parser.add_argument("--deployment",
                        type=str,
                        help="Prod, Sandbox, etc",
                        required=False)

    options = parser.parse_args()

    for k in options.__dict__:
        if options.__dict__[k] == 'None':
            options.__dict__[k] = None

    if options.enableproxy is True:
        setup_proxy(options)
        sys.exit(0)

    # ext deployments generally are in a diff domain.
    if options.domain is None:
        options.domain = 'niarasystems.com'

    configure_instance(options)


if __name__ == "__main__":
    LOGGER = logging.getLogger('an-startup')
    LOGGER.setLevel(logging.DEBUG)
    # add a file handler
    if not os.path.isfile:
        write_file('/var/log/niara_analyzer.log', '', 'w')
        os.chmod("/var/log/niara_analyzer.log", 0600)

    FILEHANDLE = logging.FileHandler('/var/log/niara_analyzer.log')
    FILEHANDLE.setLevel(logging.INFO)
    # create a formatter and set the formatter for the handler.
    FRMT = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    FILEHANDLE.setFormatter(FRMT)
    # add the Handler to the logger
    LOGGER.addHandler(FILEHANDLE)
    main()
