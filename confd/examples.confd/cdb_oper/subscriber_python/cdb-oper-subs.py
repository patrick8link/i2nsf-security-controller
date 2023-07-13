###############################################################################
# ConfD CDB operational data subscriber example
#
# (C) 2018 Tail-f Systems
# Permission to use this code as a starting point hereby granted
#
# See the README file for more information
###############################################################################
from __future__ import print_function
import socket

import sys
import select

import _confd
import _confd.cdb as cdb
import _confd.maapi as maapi

import routes_ns


def iterate_changes(kp, op, oldv, newv, state):
    """ Iteration procedure invoked by ConfD lib for each atomic change
        being done on registered subscription.
    """
    # operation type to string helper
    cdb_op_str = {
        _confd.MOP_CREATED: "CREATED",
        _confd.MOP_DELETED: "DELETED",
        _confd.MOP_MODIFIED: "MODIFIED",
        _confd.MOP_VALUE_SET: "SET",
    }

    # here, we'd normally do whatever is necessary on change happening
    # in subscribed operational data, depending on op. type, new value, etc.
    print(cdb_op_str[op] + ": " + str(kp))

    if op == _confd.MOP_CREATED:
        pass
    elif op == _confd.MOP_DELETED:
        pass
    elif op == _confd.MOP_MODIFIED:
        pass
    elif op == _confd.MOP_VALUE_SET:
        print("\toldv == " + str(oldv) + "; newv == " + str(newv))
    else:
        raise Exception(("Unexpected op %d for %s" % (op, kp)))

    return _confd.ITER_RECURSE


def run():
    """ Main subscriber thread execution. """
    confd_addr = '127.0.0.1'
    confd_port = _confd.PORT

    _confd.set_debug(_confd.SILENT, sys.stderr)

    sub_path = "/system/ip/route"

    # MAAPI socket to load schemas for a nicer print() calls
    maapi_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    maapi.connect(maapi_sock, confd_addr, confd_port, sub_path)
    maapi.load_schemas(maapi_sock)

    # socket for subscription data iteration
    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    cdb.connect(data_sock, cdb.DATA_SOCKET, confd_addr, confd_port, sub_path)

    # tailf:cdb-oper subscription socket
    oper_sub_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    cdb.connect(oper_sub_sock, cdb.SUBSCRIPTION_SOCKET,
                confd_addr, confd_port, sub_path)

    oper_sub_point = cdb.oper_subscribe(oper_sub_sock, routes_ns.ns.hash,
                                        sub_path)
    cdb.subscribe_done(oper_sub_sock)

    try:
        read_list = [oper_sub_sock]
        write_list = []
        error_list = []

        print('entering poll loop')
        while True:
            read_socks = select.select(read_list, write_list,
                                       error_list, 1)[0]
            for rs in read_socks:
                # process only our cdb-oper subscription socket here...
                if rs.fileno() is not oper_sub_sock.fileno():
                    continue
                try:
                    sub_points = cdb.read_subscription_socket(oper_sub_sock)
                    for s in sub_points:
                        if s != oper_sub_point:
                            continue
                        print("CDB operational subscription point triggered")
                        cdb.start_session(data_sock, cdb.OPERATIONAL)
                        cdb.set_namespace(data_sock, routes_ns.ns.hash)
                        cdb.diff_iterate(oper_sub_sock, oper_sub_point,
                                         iterate_changes, 0, None)
                        cdb.end_session(data_sock)

                    cdb.sync_subscription_socket(oper_sub_sock,
                                                 cdb.DONE_OPERATIONAL)
                except _confd.error.Error as e:
                    if e.confd_errno is not _confd.ERR_EXTERNAL:
                        raise e

    except KeyboardInterrupt:
        print("\nCtrl-C pressed\n")
    finally:
        data_sock.close()
        oper_sub_sock.close()


if __name__ == "__main__":
    run()
