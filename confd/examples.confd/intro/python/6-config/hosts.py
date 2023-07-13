"""
*********************************************************************
* ConfD Stats intro example                                         *
* Implements data provider and transactional callbacks              *
*                                                                   *
* (C) 2015 Tail-f Systems                                           *
* Permission to use this code as a starting point hereby granted    *
*                                                                   *
* See the README file for more information                          *
*********************************************************************
"""
from __future__ import print_function
import argparse
import os
import select
import socket
import sys
import textwrap

import copy

import _confd
import _confd.dp as dp
import _confd.maapi as maapi

from hst_ns import ns as model_ns

V = _confd.Value

# call statistics for each fo the registered data callbacks to keep tabs on
# how many times we access the different cb functions to show in the CLI
K_GET_ELEM = 0
K_GET_NEXT = 1
K_NUM_INSTANCES = 2
K_SET_ELEM = 3
K_CREATE = 4
K_REMOVE = 5
calls_keys = [K_GET_ELEM, K_GET_NEXT, K_NUM_INSTANCES,
              K_SET_ELEM, K_CREATE, K_REMOVE]
hcp_calls = {k: 0 for k in calls_keys}
icp_calls = {k: 0 for k in calls_keys}

# database file used to keep checkpoint/running database backups
DBFILE_CHECKPOINT = 'RUNNING.ckp'
DBFILE_RUNNING = 'RUNNING.db'

# token separator used in saved DB file
DB_SEP = ' '
# host record is saved as: "HOST name domain defgw"
DB_HOST = 'HOST'
# interface record is saved as: "IFACE hostname ifname ip mask enabled"
DB_IFACE = 'IFACE'


class Iface(object):
    """ External database representation of interface. """
    def __init__(self, name, ip, mask, enabled):
        self.name = name
        self.ip = ip
        self.mask = mask
        self.enabled = enabled

    # mimics output of original example written in C
    def __str__(self):
        return '   iface: {0:>7} {1:>10} {2:>10} {3:>4}\n'.format(
            self.name, self.ip, self.mask, self.enabled)

    # mimics output of original example written in C
    def __repr__(self):
        return '{0} {1} {2} {3}'.format(
            self.name, self.ip, self.mask, self.enabled)


class Host(object):
    """ External database representation of host. """
    def __init__(self, name, domain, defgw, ifaces=None):
        self.name = name
        self.domain = domain
        self.defgw = defgw
        self.ifaces = ifaces if ifaces is not None else {}

    def update_iface(self, iface):
        self.ifaces[iface.name] = copy.deepcopy(iface)

    def remove_iface(self, if_name):
        try:
            del(self.ifaces[if_name])
        except KeyError:
            print("No such interface <{0}>".format(if_name))

    def iface_count(self):
        return len(self.ifaces)

    def show(self):
        print(str(self))

    # mimics output of original example written in C
    def __str__(self):
        basestr = 'Host {0:>10} {1:>10} {2:>10}\n'.format(
            self.name, self.domain, self.defgw)
        for k in sorted(self.ifaces.keys()):
            basestr += str(self.ifaces[k])
        return basestr

    # mimics output of original example written in C
    def __repr__(self):
        basestr = "{0} {1} {2} {{".format(
            self.name, self.domain, self.defgw)
        for k in sorted(self.ifaces.keys()):
            basestr += "  {0}".format(repr(self.ifaces[k]))
        basestr += "  }\n"
        return basestr


class CustomDatabase(object):
    """ In-memory database for our data provider needs. """

    def __init__(self):
        self.data = {}
        self.locked = False

    def add_host(self, host):
        """ Common function for adding a new / updating existing host.
            Uses host's name as a key identifier of host. """
        host_name = host.name
        self.data[host_name] = copy.deepcopy(host)

    def remove_host(self, hostname):
        """ Remove specific host from the database. """
        if hostname in self.data:
            del(self.data[hostname])

    def host_count(self):
        """ Return number of hosts stored in database. """
        return len(self.data.keys())

    def reset_to_default_db(self):
        """ Reinitialize built-in database contents to a specific values. """
        self.data = {}
        # data mimics contents used in original example written in C
        buzz = Host('buzz', 'tail-f.com', '192.168.1.1',
                    {'eth0': Iface('eth0', '192.168.1.61', '255.255.255.0',
                                   True),
                     'eth1': Iface('eth1', '10.77.1.44', '255.255.0.0', False),
                     'lo': Iface('lo', '127.0.0.1', '255.0.0.0', True)})
        earth = Host('earth', 'tailf-com', '192.168.1.1',
                     {'bge0': Iface('bge0', '192.168.1.61', '255.255.255.0',
                                    True),
                      'lo0': Iface('lo0', '127.0.0.1', '255.0.0.0', True)})
        self.add_host(buzz)
        self.add_host(earth)

    def get_host(self, hostname):
        """ Return host of specified name if present in DB, else None. """
        try:
            return self.data[hostname]
        except KeyError:
            return None

    def get_host_iface(self, hostname, if_name):
        """ Return interface data from DB if present, else None. """
        host = self.get_host(hostname)
        if host is not None:
            try:
                return host.ifaces[if_name]
            except KeyError:
                return None

    def dump_db_ok(self, filename):
        """ Dump running database to file.
            Return True on success, False otherwise. """
        try:
            with open(filename, 'w') as f:
                for h in self.data.values():
                    dump_line = DB_SEP.join([DB_HOST, h.name, h.domain,
                                             h.defgw])
                    f.write(dump_line + '\n')
                    for i in h.ifaces.values():
                        if_line = DB_SEP.join([DB_IFACE, h.name, i.name, i.ip,
                                               i.mask, i.enabled])
                        f.write(if_line + '\n')
        except IOError:
            print("Error writing file {0}\n".format(filename))
            return False
        return True

    def restore_db(self, filename):
        """ Read database contents from file.
            Return True on success, False otherwise. """
        new_data = {}
        try:
            num_entries = 0
            with open(filename, 'r') as f:
                while True:
                    line = f.readline().rstrip()
                    if line.startswith(DB_HOST):
                        _, hostname, domain, defgw = line.split(DB_SEP)
                        new_data[hostname] = Host(hostname, domain, defgw)
                        num_entries += 1
                    elif line.startswith(DB_IFACE):
                        _, hostname, ifname, ip, mask, enabled = line.split(
                                                                        DB_SEP)
                        new_data[hostname].ifaces[ifname] = Iface(ifname, ip,
                                                                  mask,
                                                                  enabled)
                    else:
                        break
            print("Restoring {0} entries".format(num_entries))
        except IOError:
            print("Could not read entries from {0} \n".format(filename))
            return False
        self.data = new_data
        return True

    def show(self):
        """ Print running DB contents. """
        sorted_host_names = sorted(self.data.keys())
        for i in sorted_host_names:
            print(self.data[i])


class TransCbs(object):
    # transaction callbacks
    #
    # The installed init() function gets called every time ConfD
    # wants to establish a new transaction, Each NETCONF
    # command will be a transaction
    #
    # We can choose to create threads here or whatever, we
    # can choose to allocate this transaction to an already existing
    # thread. We must tell ConfD which file descriptor should be
    # Used for all future communication in this transaction
    # this has to be done through the call confd_trans_set_fd();

    def __init__(self, workersocket, db):
        self._workersocket = workersocket
        self.db = db

    def cb_init(self, tctx):
        dp.trans_set_fd(tctx, self._workersocket)
        return _confd.CONFD_OK

    # This callback gets invoked at the end of the transaction
    # when ConfD has accumulated all write operations
    # we're guaranteed that
    # a) no more read ops will occur
    # b) no other transactions will run between here and tr_finish()
    #    for this transaction, i.e ConfD will serialize all transactions
    #  since we need to be prepared for abort(), we may not write
    # our data to the actual database, we can choose to either
    # copy the entire database here and write to the copy in the
    # following write operations _or_ let the write operations
    # accumulate operations create(), set(), delete() instead of actually
    # writing

    # If our db supports transactions (which it doesn't in this
    # silly example, this is the place to do START TRANSACTION

    def cb_write_start(self, tctx):
        return _confd.CONFD_OK

    def cb_prepare(self, tctx):
        return _confd.CONFD_OK

    def cb_commit(self, tctx):
        print("commit called with {0}".format(tctx))

        change = tctx.accumulated
        # TrItemRef is implemented as linked list in C-binding
        while change is not None:

            if change.callpoint == model_ns.callpoint_icp:
                hostname = str(change.hkp[-3][0])
                host = self.db.get_host(hostname)

                if change.op == dp.C_CREATE:
                    # creating a brand new new interface; keypath example:
                    # /hosts/host{hname}/interfaces/interface{eth0}
                    if host is not None:
                        ifname = str(change.hkp[0][0])
                        iface = Iface(ifname, None, None, None)
                        host.update_iface(iface)

                elif change.op == dp.C_REMOVE:
                    # deleting an interface; keypath example:
                    # /hosts/host{hname}/interfaces/interface{eth0}
                    if host is not None:
                        ifname = str(change.hkp[0][0])
                        host.remove_iface(ifname)

                elif change.op == dp.C_SET_ELEM:
                    # setting an item in an already existing interface;
                    # keypath ex:
                    # /hosts/host{hname}/interfaces/interface{eth0}/ip
                    ifname = str(change.hkp[1][0])
                    iface = self.db.get_host_iface(hostname, ifname)
                    if iface is not None:
                        leaf_tag = str(change.hkp[0])
                        if leaf_tag == 'ip':
                            iface.ip = str(change.val)
                        elif leaf_tag == 'mask':
                            iface.mask = str(change.val)
                        elif leaf_tag == 'enabled':
                            iface.enabled = bool(str(change.val))
                        else:
                            raise NotImplementedError

            elif change.callpoint == model_ns.callpoint_hcp:

                if change.op == dp.C_CREATE:
                    # brand new host entry, will soon be populated with values;
                    # keypath example: /hosts/host{hname}
                    hostname = str(change.hkp[0][0])
                    host = Host(hostname, None, None)
                    self.db.add_host(host)

                elif change.op == dp.C_REMOVE:
                    hostname = str(change.hkp[0][0])
                    self.db.remove_host(hostname)

                elif change.op == dp.C_SET_ELEM:
                    # setting the elem of an already existing host entry;
                    # keypath example: /hosts/host{hname}/defgw
                    hostname = str(change.hkp[1][0])
                    host = self.db.get_host(hostname)
                    if host is not None:
                        leaf_tag = str(change.hkp[0])
                        if leaf_tag == 'domain':
                            host.domain = str(change.val)
                        elif leaf_tag == 'defgw':
                            host.defgw = str(change.val)
                        else:
                            raise NotImplementedError
                    else:
                        raise KeyError('host not found!')
            change = change.next

        return _confd.CONFD_OK

    def cb_abort(self, tctx):
        return _confd.CONFD_OK

    def cb_finish(self, tctx):
        return _confd.CONFD_OK


class DatabaseCbs(object):
    """ Database callbacks implementation. """

    def __init__(self, datasocket, db):
        self.datasocket = datasocket
        self.db = db

    def cb_lock(self, dbx, dbname):
        self.db.locked = True
        return _confd.CONFD_OK

    def cb_unlock(self, dbx, dbname):
        self.db.locked = False
        return _confd.CONFD_OK

    def cb_delete_config(self, dbx, dbname):
        dp.db_seterr(dbx, "error from Python")
        return _confd.CONFD_ERR

    def cb_add_checkpoint_running(self, dbx):
        db_saved = self.db.dump_db_ok(DBFILE_CHECKPOINT)
        return _confd.CONFD_OK if db_saved else _confd.CONFD_ERR

    def cb_del_checkpoint_running(self, dbx):
        os.unlink(DBFILE_CHECKPOINT)
        return _confd.CONFD_OK

    def cb_activate_checkpoint_running(self, dbx):
        db_restored = self.db.restore_db(DBFILE_CHECKPOINT)
        return _confd.CONFD_OK if db_restored else _confd.CONFD_ERR


class HostDataCbs(object):
    """ Data provider callbacks for the 'host' list of YANG model. """

    def __init__(self, db):
        self.db = db

    def cb_get_elem(self, tctx, kp):
        hcp_calls[K_GET_ELEM] += 1

        v_result = None
        host_key = str(kp[-3][0])  # /hosts/host{name}/...
        host = self.db.get_host(host_key)
        if host is not None:
            tag = str(kp[0])
            if tag == 'name':
                v_result = V(host.name, _confd.C_BUF)
            elif tag == 'domain':
                v_result = V(host.domain, _confd.C_BUF)
            elif tag == 'defgw':
                v_result = V(host.defgw, _confd.C_IPV4)
            else:
                raise NotImplementedError

        if v_result is not None:
            dp.data_reply_value(tctx, v_result)
        else:
            dp.data_reply_not_found(tctx)
        return _confd.CONFD_OK

    def cb_get_next(self, tctx, kp, next):
        hcp_calls[K_GET_NEXT] += 1

        if next == -1:
            next = 0  # first call - start indexing from 0

        sorted_host_names = sorted(self.db.data.keys())

        if next < len(sorted_host_names):
            curr = sorted_host_names[next]
            key_list = [V(curr, _confd.C_BUF)]  # key of the host is its name
            dp.data_reply_next_key(tctx, key_list, next+1)
        else:
            dp.data_reply_next_key(tctx, None, 0)
        return _confd.CONFD_OK

    def cb_num_instances(self, tctx, kp):
        hcp_calls[K_NUM_INSTANCES] += 1
        print("host_num_instances\n")
        v_count = V(self.db.host_count(), _confd.C_INT32)
        dp.data_reply_value(tctx, v_count)
        return _confd.CONFD_OK

    def cb_set_elem(self, tctx, kp, newval):
        hcp_calls[K_SET_ELEM] += 1
        print("host_set_elem\n")
        return _confd.ACCUMULATE

    def cb_create(self, tctx, kp):
        hcp_calls[K_CREATE] += 1
        print("host_create\n")
        return _confd.ACCUMULATE

    def cb_remove(self, tctx, kp):
        hcp_calls[K_REMOVE] += 1
        print("host_remove\n")
        return _confd.ACCUMULATE


class IfaceDataCbs(object):
    """ Data provider callbacks for the '/host{name}/interfaces/interface{}'
        list of YANG model. """

    def __init__(self, db):
        self.db = db

    def cb_get_elem(self, tctx, kp):
        icp_calls[K_GET_ELEM] += 1

        hostkey = str(kp[-3][0])
        ifacekey = str(kp[-6][0])

        iface = self.db.get_host_iface(hostkey, ifacekey)
        if iface is None:
            dp.data_reply_not_found(tctx)
            return _confd.CONFD_OK

        tag = str(kp[0])
        if tag == 'name':
            val = V(iface.name)
        elif tag == 'ip':
            val = V(iface.ip, _confd.C_IPV4)
        elif tag == 'mask':
            val = V(iface.mask, _confd.C_IPV4)
        elif tag == 'enabled':
            val = V(iface.enabled, _confd.C_BOOL)
        else:
            return _confd.CONFD_ERR

        dp.data_reply_value(tctx, val)
        return _confd.CONFD_OK

    def cb_get_next(self, tctx, kp, next):
        icp_calls[K_GET_NEXT] += 1

        if next == -1:  # First call, index from 0...
            next = 0

        hostname = str(kp[-3][0])
        host = self.db.get_host(hostname)

        key_list = None
        next_next = -1
        if host is not None and next < host.iface_count():
            sorted_iface_names = sorted(host.ifaces.keys())
            key_list = [V(sorted_iface_names[next], _confd.C_BUF)]
            next_next = next+1

        dp.data_reply_next_key(tctx, key_list, next_next)
        return _confd.CONFD_OK

    def cb_num_instances(self, tctx, kp):
        icp_calls[K_NUM_INSTANCES] += 1
        hostname = str(kp[-3])
        host = self.db.get_host(hostname)
        v_count = V(host.iface_count(), _confd.C_INT32)
        dp.data_reply_value(tctx, v_count)
        return _confd.CONFD_OK

    def cb_set_elem(self, tctx, kp, newval):
        icp_calls[K_SET_ELEM] += 1
        return _confd.ACCUMULATE

    def cb_create(self, tctx, kp):
        icp_calls[K_CREATE] += 1
        return _confd.ACCUMULATE

    def cb_remove(self, tctx, kp):
        icp_calls[K_REMOVE] += 1
        return _confd.ACCUMULATE


class Prompt(object):
    def __init__(self, db):
        self.db = db
        self.curr_hostname = None
        print('>', end=' ')
        sys.stdout.flush()

    def handle_stdin(self, line):
        if len(line) != 0:
            tokens = line.split()
            token_count = len(tokens)
            first_word = tokens[0]
            if first_word == 'show':
                if self.curr_hostname is None:
                    self.db.show()
                else:
                    host = self.db.get_host(self.curr_hostname)
                    if host is not None:
                        host.show()
            elif line == 'host':
                print('usage: host <hname> | host <hname domain defgw>\n')
                self.curr_hostname = None
            elif line == 'default':
                self.db.reset_to_default_db()
            elif first_word == 'host' and token_count > 1:
                hostname = tokens[1].strip()
                host = self.db.get_host(hostname)
                if host is not None:
                    self.curr_hostname = hostname
                else:  # Create a new host
                    try:
                        self.curr_hostname = hostname
                        domain, defgw = tokens[2], tokens[3]
                        self.db.add_host(Host(hostname, domain, defgw))
                    except IndexError:
                        print('usage: host <newhost> <domain> <defgw>\n')
                        self.curr_hostname = None
            elif first_word == 'iface':
                if self.curr_hostname is None:
                    print('Need to pick a host before we can create iface\n')
                else:
                    hostname = self.curr_hostname
                    host = self.db.get_host(hostname)
                    try:
                        name, ip, mask, enabled = tokens[1], tokens[2],\
                                                  tokens[3], \
                                                  bool(tokens[4] == '1')
                        iface = Iface(name, ip, mask, enabled)
                        host.update_iface(iface)
                    except IndexError:
                        print('usage: iface <name> <ip> <mask> <ena>\n')
                        self.curr_hostname = None
            elif first_word == 'del':
                if token_count == 1:
                    print("usage: del <hname | ifname>\n")
                elif self.curr_hostname is None:
                    # We are in the root-node, we should remove a host
                    self.db.remove_host(tokens[1])
                else:
                    # We are in a 'host'-node, we should remove an iface
                    db_host = self.db.get_host(self.curr_hostname)
                    db_host.remove_iface(tokens[1])
            elif first_word == 'up':
                self.curr_hostname = None
            elif first_word == 'quit':
                exit(0)
            elif first_word == 'load':
                if token_count != 2:
                    print("usage: load <file>\n")
                elif not self.db.restore_db(tokens[1]):
                    print("failed to open {0} for reading \n".format(
                        tokens[1]))
            elif first_word == 'dump':
                if token_count < 2:
                    fname = DBFILE_RUNNING
                else:
                    fname = tokens[1]
                if self.db.dump_db_ok(fname):
                    print("dumped to {0}".format(fname))
                else:
                    print("failed to dump to {0}\n".format(fname))
            else:
                print(
                    "show\n"
                    "host [hostname]\n"
                    "host <name> <domain> <defgw>    - to create new host\n"
                    "iface <name> <ip> <mask> <ena>  - to create new iface\n"
                    "del <hostname | ifacename>\n"
                    "up\n"
                    "quit\n"
                    "default      -  to load default db values\n"
                    "load <file>  -  to load db from <file>\n"
                    "dump <file>  -  to dump db to <file>\n"
                )

        if self.curr_hostname is None:
            print('>', end=' ')
        else:
            print('[' + self.curr_hostname + ']>', end=' ')
        sys.stdout.flush()


def run(debuglevel):

    # In C we use confd_init() which sets the debug-level, but for Python the
    # call to confd_init() is done when we do 'import confd'.
    # Therefore we need to set the debug level here:
    _confd.set_debug(debuglevel, sys.stderr)

    # init library
    daemon_ctx = dp.init_daemon('hosts_daemon')

    # initialize our simple database
    custom_db = CustomDatabase()
    if custom_db.restore_db(DBFILE_CHECKPOINT):
        print('Restored from checkpoint\n')
    elif custom_db.restore_db(DBFILE_RUNNING):
        print('Restored from RUNNING.db\n')
    else:
        print('Starting with empty DB\n')

    custom_db.show()

    confd_addr = '127.0.0.1'
    confd_port = _confd.PORT
    managed_path = '/'

    maapisock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    ctlsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    wrksock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    try:
        dp.connect(daemon_ctx, ctlsock, dp.CONTROL_SOCKET, confd_addr,
                   confd_port, managed_path)
        dp.connect(daemon_ctx, wrksock, dp.WORKER_SOCKET, confd_addr,
                   confd_port, managed_path)

        maapi.connect(maapisock, confd_addr, confd_port, managed_path)
        maapi.load_schemas(maapisock)

        transaction_cb = TransCbs(wrksock, custom_db)
        dp.register_trans_cb(daemon_ctx, transaction_cb)

        database_cb = DatabaseCbs(wrksock, custom_db)
        dp.register_db_cb(daemon_ctx, database_cb)

        host_data_cb = HostDataCbs(custom_db)
        dp.register_data_cb(daemon_ctx, model_ns.callpoint_hcp, host_data_cb)

        iface_data_cb = IfaceDataCbs(custom_db)
        dp.register_data_cb(daemon_ctx, model_ns.callpoint_icp, iface_data_cb)

        dp.register_done(daemon_ctx)

        p = Prompt(custom_db)
        try:
            _r = [sys.stdin, ctlsock, wrksock]
            _w = []
            _e = []

            while True:
                (r, w, e) = select.select(_r, _w, _e, 1)

                for rs in r:

                    if rs.fileno() == ctlsock.fileno():
                        try:
                            dp.fd_ready(daemon_ctx, ctlsock)
                        except _confd.error.Error as e:
                            if e.confd_errno is not _confd.ERR_EXTERNAL:
                                raise e
                    elif rs.fileno() == wrksock.fileno():
                        try:
                            dp.fd_ready(daemon_ctx, wrksock)
                        except _confd.error.Error as e:
                            if e.confd_errno is not _confd.ERR_EXTERNAL:
                                raise e
                    elif rs == sys.stdin:
                        p.handle_stdin(sys.stdin.readline().rstrip())

        except KeyboardInterrupt:
            print('\nCtrl-C pressed\n')

    finally:
        ctlsock.close()
        wrksock.close()
        dp.release_daemon(daemon_ctx)


if __name__ == '__main__':

    debug_levels = {
        'q': _confd.SILENT,
        'd': _confd.DEBUG,
        't': _confd.TRACE,
        'p': _confd.PROTO_TRACE,
    }

    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-dl', '--debuglevel', choices=debug_levels.keys(),
                        help=textwrap.dedent(
                            '''\
                            set the debug level:
                                q = quiet (i.e. no) debug
                                d = debug level debug
                                t = trace level debug
                                p = proto level debug
                            '''))
    args = parser.parse_args()
    print('Args = {0}'.format(args))

    confd_debug_level = debug_levels.get(args.debuglevel, _confd.TRACE)

    run(confd_debug_level)
