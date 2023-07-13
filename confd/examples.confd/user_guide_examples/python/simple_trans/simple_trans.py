""" ConfD example -  user_guide_examples / python / simple_trans

    (C) 2018 Tail-f Systems
    Permission to use this code as a starting point hereby granted.
    This is ConfD Sample Code.

    See the ../README file for more information. """
from __future__ import print_function

import os
import select
import socket
import sys
import threading
import traceback

import _confd
import confd
import _confd.dp as dp
import _confd.maapi as maapi

from smp_ns import ns

# dummy lock for our "external DB that's not really used in this example
db_lock = threading.Lock()

# our "external" DB structure - map of two items:
# { name: [ ip_value, port_value ],
#   ...
# }
running_db = {}

# two files used - for saved/running DB,
# and one for the new contents we try to commit
DBFILE_SAVED = 'running.DB'
DBFILE_PREP = 'running.prep'

# PyAPI does not have confd_load_schemas() equivalent,
# we have to use MAAPI for schema info load...
maapi_socket = None


def save_db_to_file(filename):
    """ Write our running DB to a file. """
    print('Trying to save DB data to file: ' + filename)
    try:
        with open(filename, 'w') as fp:
            for k, v in running_db.items():
                fp.write('%s %s %s\n' % (k, v[0], v[1]))
    except IOError as ex:
        print(ex)
    else:
        print("Saving OK.")


def restore_db_from_file(filename):
    """ Read running DB contents from a file.
        Database is cleared in any case.
        Return CONFD_OK on success, CONFD_ERR otherwise. """
    global running_db
    running_db = {}
    print('Trying to read DB data from file: ' + filename)
    try:
        with open(filename, 'r') as fp:
            for line in fp:
                name, ip, port = line.split(' ')
                running_db[name] = [ip, port]
    except IOError as ex:
        print(ex)
        return confd.CONFD_ERR
    else:
        print('Read from file OK.')
        return confd.CONFD_OK


def init_db():
    """ Initialize DB from input file.
        If reading from file fails, use some dummy values instead. """
    global running_db
    if restore_db_from_file(DBFILE_SAVED) != confd.CONFD_OK:
        print('Setting running DB to default values.\n')
        running_db = {
            'ssh': ['192.168.128.1', '22'],
            'www': ['192.168.128.11', '80'],
            'smtp': ['192.168.128.1', '25'],
        }


class TransactionCallbackImpl(object):
    """ Callback for handling the ConfD transactions. """
    def __init__(self, worker_socket):
        self._worker_socket = worker_socket

    def cb_init(self, tctx):
        maapi.attach(maapi_socket, ns.hash, tctx)
        dp.trans_set_fd(tctx, self._worker_socket)
        return confd.CONFD_OK

    def cb_write_lock(self, tctx):
        """ No real locking needed with our simplistic in-memory DB,
            threading lock here just as an example... """
        db_lock.lock()
        return confd.CONFD_OK

    def cb_write_unlock(self, tctx):
        db_lock.unlock()
        return confd.CONFD_OK

    def cb_abort(self, tctx):
        """ On aborted commit, reload DB contents from a saved file. """
        restore_db_from_file(DBFILE_SAVED)
        try:
            # remove the file we have prepared to be new DB contents
            os.unlink(DBFILE_PREP)
        except IOError as ex:
            print(ex)
        return confd.CONFD_OK

    def cb_prepare(self, tctx):
        """ Iterate all the accumulated changes and update DB contents. """
        change = tctx.accumulated
        # TrItemRef is implemented as linked list in C-binding
        while change is not None:
            if change.callpoint != ns.callpoint_simplecp:
                change = change.next
                continue
            kp_index = 1 if isinstance(change.hkp[0], confd.XmlTag) else 0
            server_name = str(change.hkp[kp_index][0])
            if change.op == dp.C_CREATE:
                running_db[server_name] = [None, None]
            elif change.op == dp.C_REMOVE:
                del(running_db[server_name])
            elif change.op == dp.C_SET_ELEM:
                leaf_tag = change.hkp[0].tag
                if ns.smp_ip == leaf_tag:
                    running_db[server_name][0] = str(change.val)
                elif ns.smp_port == leaf_tag:
                    running_db[server_name][1] = str(change.val)
                else:
                    raise NotImplementedError
            else:
                raise NotImplementedError
            change = change.next

        return save_db_to_file(DBFILE_PREP)

    def cb_commit(self, tctx):
        """ Commit successful, "push" DB contents to a major DB file. """
        try:
            os.rename(DBFILE_PREP, DBFILE_SAVED)
        except Exception as ex:
            print(ex)
            return confd.CONFD_ERR
        return confd.CONFD_OK

    def cb_finish(self, tctx):
        maapi.detach(maapi_socket, tctx)
        return confd.CONFD_OK


class DataCallbackImpl(object):
    """ Implementation of the read/write callbacks of our database. """

    def cb_get_elem(self, tctx, kp):
        v_result = None
        server_name = str(kp[1][0])

        if server_name in running_db:
            leaf_tag = kp[0].tag
            if ns.smp_name == leaf_tag:
                v_result = confd.Value(server_name, confd.C_BUF)
            elif ns.smp_ip == leaf_tag:
                ip = running_db[server_name][0]
                v_result = confd.Value(ip, confd.C_IPV4)
            elif ns.smp_port == leaf_tag:
                port = int(running_db[server_name][1])
                v_result = confd.Value(port, confd.C_UINT16)
            else:
                raise NotImplementedError

        (dp.data_reply_value(tctx, v_result) if v_result is not None
         else dp.data_reply_not_found(tctx))
        return confd.CONFD_OK

    def cb_get_next(self, tctx, kp, next):
        list_tag = kp[0].tag
        next_key = None

        if ns.smp_server == list_tag:
            sorted_server_names = sorted(running_db.keys())
            num_servers = len(sorted_server_names)
            index = next - (-1)
            if index < num_servers:
                next_key = confd.Value(sorted_server_names[index], confd.C_BUF)
        else:
            raise NotImplementedError

        if next_key is None:
            dp.data_reply_next_key(tctx, keys=None, next=-1)
        else:
            dp.data_reply_next_key(tctx, keys=[next_key], next=next + 1)
        return confd.CONFD_OK

    # accumulate all the writes to apply together in prepare phase
    def cb_set_elem(self, tctx, kp, newval):
        return confd.ACCUMULATE

    def cb_create(self, tctx, kp):
        return confd.ACCUMULATE

    def cb_remove(self, tctx, kp):
        return confd.ACCUMULATE


def main():
    """ Main execution of the transformer daemon. """
    global maapi_socket

    init_db()

    _confd.set_debug(confd.TRACE, sys.stderr)

    dest_ip = '127.0.0.1'
    dest_port = confd.CONFD_PORT
    managed_path = '/servers'

    daemon_ctx = dp.init_daemon('simple_trans')

    maapi_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    worker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

    try:
        maapi.connect(maapi_socket, dest_ip, dest_port, managed_path)
        maapi.load_schemas(maapi_socket)

        dp.connect(daemon_ctx, control_sock, dp.CONTROL_SOCKET,
                   dest_ip, dest_port, managed_path)

        dp.connect(daemon_ctx, worker_sock, dp.WORKER_SOCKET,
                   dest_ip, dest_port, managed_path)

        transaction_cb = TransactionCallbackImpl(worker_sock)
        dp.register_trans_cb(daemon_ctx, transaction_cb)

        data_cb = DataCallbackImpl()
        dp.register_data_cb(daemon_ctx, ns.callpoint_simplecp, data_cb)

        dp.register_done(daemon_ctx)

        try:
            read_list = [control_sock, worker_sock]
            write_list = []
            error_list = []

            fd_map = {
                control_sock.fileno(): control_sock,
                worker_sock.fileno(): worker_sock
            }

            print('entering poll loop')
            while True:
                read_socks = select.select(read_list, write_list,
                                           error_list, 1)[0]
                for rs in read_socks:
                    sock = fd_map[rs.fileno()]
                    try:
                        dp.fd_ready(daemon_ctx, sock)
                    except _confd.error.Error as ex:
                        traceback.print_exc()
                        if ex.confd_errno is not confd.ERR_EXTERNAL:
                            raise ex

        except KeyboardInterrupt:
            print("Ctrl-C pressed\n")
    finally:
        control_sock.close()
        worker_sock.close()
        dp.release_daemon(daemon_ctx)


if __name__ == '__main__':
    main()
