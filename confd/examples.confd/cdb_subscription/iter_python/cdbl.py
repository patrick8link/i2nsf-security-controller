# *********************************************************************
# ConfD CDB iteration example - python version
#
# (C) 2007-2017 Tail-f Systems
# Permission to use this code as a starting point hereby granted
# This is ConfD Sample Code.
#
# See the README file for more information
# ********************************************************************

import logging
import select
import socket
import sys

import _confd
import _confd.cdb as cdb
import _confd.maapi as maapi

import root_ns

confd_debug_level = _confd.TRACE
log_level = logging.INFO
CONFD_ADDR = '127.0.0.1'

logging.basicConfig(
    format="%(asctime)s:%(relativeCreated)s"
           "%(levelname)s:%(filename)s:%(lineno)s:%(funcName)s  %(message)s",
    level=log_level)
log = logging.getLogger("cdbl")


class Rfhead:
    sector_id = ''
    children = {}  # key is cdn, value is childattr


rfheads = {}  # key is dn, value is Rfhead


# helper function for logging (alternative to dump_db in C example)
def _str_rfh(rfheads):
    s = "{"
    for k1, v1 in rfheads.items():
        s += "%d:sector_id=%s," % (k1, v1.sector_id)
        s += " children: {"
        for k2, v2 in v1.children.items():
            s += " %d:childattr=%s, " % (k2, v2)
        s += "}, "
    s += "}"
    return s


def read_head(cdbsock, headkey):
    log.debug(
        "==> cdbsock.fileno()=%d headkey=%d" % (cdbsock.fileno(), headkey))
    hp = rfheads.get(headkey)

    if hp is None:
        hp = Rfhead()
        rfheads[headkey] = hp
        log.debug("Created new hp=%s" % hp)

    cdb.cd(cdbsock, "/root/node-b/rf-head{%d}" % headkey)
    hp.sector_id = str(cdb.get(cdbsock, "sector-id"))
    hp.children.clear()
    log.debug("hp=%s", hp)
    n = cdb.num_instances(cdbsock, "child")
    log.debug("number of child instances n=%d" % n)
    for i in range(n):
        dn = int(cdb.get(cdbsock, "child[%d]/cdn" % i))
        childattr = str(cdb.get(cdbsock, "child[%d]/child-attr" % i))
        hp.children[dn] = childattr

    log.debug("<== processed hp=%s" % hp)


def read_db(cdbsock):
    log.debug("==> cdbsock.fileno()=%d" % cdbsock.fileno())
    cdb.start_session(cdbsock, cdb.RUNNING)
    cdb.set_namespace(cdbsock, root_ns.ns.hash)
    n = cdb.num_instances(cdbsock, "/root/node-b/rf-head")
    for k, v in rfheads.items():
        v.children.clear()
    rfheads.clear()
    for i in range(n):
        key = int(cdb.get(cdbsock, "/root/node-b/rf-head[%d]/dn" % i))
        read_head(cdbsock, key)

    cdb.end_session(cdbsock)
    log.debug("<== rfheads=%s" % _str_rfh(rfheads))


def iter(kp, op, oldv, newv, cdbsock):
    log.info("=> kp=%s op=%i oldv=%s newv=%s cdbsock.fileno()=%d"
             % (kp, op, newv, oldv, cdbsock.fileno()))
    log.debug("rfheads=%s" % _str_rfh(rfheads))
    rv = _confd.ITER_CONTINUE
    if op == _confd.MOP_CREATED:
        log.debug("MOP_CREATED")
        log.info("Create: %s" % kp)
        ctag = kp[1]
        if ctag.tag == root_ns.ns.root_rf_head:
            log.debug("rf-head")
            # an rfhead was created
            # keypath is /root/node-b/rf-head{$key}
            #              3     2      1    0
            read_head(cdbsock, int(kp[0][0]))  # kp[0] is a tuple of keys
        elif ctag.tag == root_ns.ns.root_child:
            log.debug("child")
            # a child to en existing rfhead was created.
            # keypath is /root/node-b/rf-head{$key}/child{$key2}
            #              5      4      3    2      1    0
            # we can here choose to read the  new child or reread
            # the entire head structure
            read_head(cdbsock, int(kp[2][0]))  # kp[2] is a tuple of keys

    elif op == _confd.MOP_DELETED:
        log.debug("MOP_DELETED")
        log.info("Delete: %s" % kp)
        dtag = kp[1]
        if dtag.tag == root_ns.ns.root_rf_head:
            log.debug("rf-head")
            # an rfhead was created
            # keypath is /root/node-b/rf-head{$key}
            #              3     2      1    0
            headkey = int(kp[0][0])  # kp[0] is a tuple of keys
            log.debug("headkey=%d" % headkey)
            if headkey in rfheads:
                del rfheads[headkey]
            else:
                log.warn(
                    "Cannot find %d in rfheads map %s" % (
                        headkey, _str_rfh(rfheads)))
                rv = _confd.ITER_RECURSE
        elif dtag.tag == root_ns.ns.root_child:
            log.debug("child")
            # a child of an existing head was removed
            # keypath is /root/node-b/rf-head{$key}/child{$key2}
            #               5      4      3    2      1    0
            # we can here choose to read the  new child or reread
            # the entire head structure
            headkey = int(kp[2][0])
            childkey = int(kp[0][0])
            log.debug("headkey=%d childkey=%d" % (headkey, childkey))
            if headkey in rfheads:
                rh = rfheads[headkey]
                if childkey in rh.children:
                    del rfheads[headkey].children[childkey]
                else:
                    log.warn("Cannot find %d in children" % childkey)
            else:
                log.warn(
                    "Cannot find %d in rfheads map %s" % (headkey,
                                                          _str_rfh(rfheads)))
                rv = _confd.ITER_RECURSE

    elif op == _confd.MOP_MODIFIED:
        log.debug("MOP_MODIFIED")
        log.info("Modified %s" % kp)
        rv = _confd.ITER_RECURSE

    elif op == _confd.MOP_VALUE_SET:
        log.debug("MOP_VALUE_SET")
        log.info("Value Set: %s --> (%s)" % (kp, newv))
        leaf = kp[0]
        if leaf.tag == root_ns.ns.root_sector_id:
            log.debug("sector-id")
            # keypath is /root/node-b/rf-head{$key}/sector-id
            #              4     3      2     1       0
            headkey = int(kp[1][0])  # kp[0] is a tuple of keys
            log.debug("headkey=%d" % headkey)
            if headkey in rfheads:
                rfheads[headkey].sector_id = str(newv)
                rv = _confd.ITER_RECURSE
            else:
                log.warn(
                    "Cannot find %d in rfheads map %s" % (
                        headkey, _str_rfh(rfheads)))
        elif leaf.tag == root_ns.ns.root_child_attr:
            log.debug("child-attr")
            # keypath is /root/node-b/rf-head{$key}/child{$key2}/child-attr
            #             6      5      4    3      2     1       0
            headkey = int(kp[3][0])
            childkey = int(kp[1][0])
            log.debug("headkey=%d childkey=%d" % (headkey, childkey))
            if headkey in rfheads:
                rh = rfheads[headkey]
                if childkey in rh.children:
                    rfheads[headkey].children[childkey] = str(newv)
                else:
                    log.warn("Cannot find %d in children rfheads map %s"
                             % (childkey, _str_rfh(rfheads)))
            else:
                log.warn("Cannot find %d in rfheads map %s"
                         % (headkey, _str_rfh(rfheads)))
    else:
        log.warn("Unexpected op %d for %s" % (op, kp))
        rv = _confd.ITER_RECURSE

    log.info("<== rv=%i rfheads=%s", rv, _str_rfh(rfheads))
    return rv


def run():
    log.info("==>")
    # In C we use confd_init() which sets the debug-level, but for Python the
    # call to confd_init() is done when we do 'import confd'.
    # Therefore we need to set the ConfD debug level here (if we want it to be
    # different from the default debug level - CONFD_SILENT):
    _confd.set_debug(confd_debug_level, sys.stderr)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    subsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    # maapi socket for load schemas
    maapisock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    maapi.connect(maapisock, CONFD_ADDR, _confd.CONFD_PORT)
    maapi.load_schemas(maapisock)

    cdb.connect(sock, cdb.DATA_SOCKET, CONFD_ADDR, _confd.CONFD_PORT)
    sub_path = "/root/node-b/rf-head"
    cdb.connect(subsock, cdb.SUBSCRIPTION_SOCKET, CONFD_ADDR, _confd.CONFD_PORT)
    spoint = cdb.subscribe(subsock, 3, root_ns.ns.hash, sub_path)
    cdb.subscribe_done(subsock)
    log.debug("Subscribed to path %s spoint=%i" % (sub_path, spoint))
    read_db(sock);

    try:
        _r = [subsock]
        _w = []
        _e = []
        log.debug("subscok connected, starting ConfD loop")
        while (True):
            (r, w, e) = select.select(_r, _w, _e, 1)
            # log.debug("select triggered r=%r" % r)
            for rs in r:
                log.debug("rs.fileno=%i subscok.fileno=%i" % (
                    rs.fileno(), subsock.fileno()))
                if rs.fileno() == subsock.fileno():
                    log.debug("subsock triggered")
                    try:
                        sub_points = cdb.read_subscription_socket(subsock)
                        for s in sub_points:
                            if s == spoint:
                                log.debug("our spoint=%i triggered" % spoint)
                                cdb.start_session(sock, cdb.RUNNING)
                                cdb.set_namespace(sock, root_ns.ns.hash)
                                cdb.diff_iterate(subsock, spoint, iter,
                                                 _confd.ITER_WANT_PREV, sock)
                                cdb.end_session(sock)

                                # variant with diff_match not yet available
                                # in python

                                cdb.sync_subscription_socket(subsock,
                                                             cdb.DONE_PRIORITY)
                    except (_confd.error.Error) as e:
                        if e.confd_errno is not _confd.ERR_EXTERNAL:
                            raise e

    except KeyboardInterrupt:
        print("\nCtrl-C pressed\n")
    finally:
        sock.close()
        subsock.close()
    log.info("<==")


if __name__ == "__main__":
    log.info("==>")
    run()
    log.info("<==")
