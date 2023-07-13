"""
*********************************************************************
* Introduction example for pushing data to the CDB oper datastore.  *
* Python version.                                                   *
*                                                                   *
* (C) 2018 Tail-f Systems                                           *
* Permission to use this code as a starting point hereby granted    *
*                                                                   *
* See the README file for more information                          *
*********************************************************************
"""
from __future__ import print_function

import argparse
import logging
import re
import socket
import subprocess
import sys
import textwrap
import time

import _confd
import _confd.dp as dp
import _confd.maapi as maapi

from arpe_ns import ns

CONFD_ADDR = '127.0.0.1'
INTERVAL = 5
MAX_NOBJS = 100

log_level = logging.INFO
logging.basicConfig(
    format="%(asctime)s:%(relativeCreated)s"
           "%(levelname)s:%(filename)s:%(lineno)s:%(funcName)s  %(message)s",
    level=log_level)
log = logging.getLogger("confd_example_logger")
maapisock = None


def make_tag_value(ns_hash, tag, init, vtype):
    """
    Wrapper to create a _confd.TagValue
    """
    return _confd.TagValue(_confd.XmlTag(ns_hash, tag),
                           _confd.Value(init, vtype))


def proccess_arp_line(line):
    log.debug("==>")
    # Now lazy parse lines like
    # ? (192.168.1.1) at 00:0F:B5:EF:11:00 [ether] on eth0
    # slightly different arp output on Linux and BSD

    # Skip space and 'at'
    log.debug("processing line={}".format(line))

    arp_line = [x for x in re.split("[ ,?<>()]", line)
                if x != "" and x != "at"]
    ip = arp_line[0]
    i = 1
    perm = 0
    pub = 0
    hwaddr = ""
    if arp_line[1] == "incomplete":
        for elem in arp_line[1:]:
            i += 1
            if elem == "on":
                break
    elif arp_line[1]:
        hwaddr = arp_line[1]
        for elem in arp_line[2:]:
            i += 1
            if elem == "PERM":
                perm = 1
            elif elem == "PUB":
                pub = 1
            elif elem == "[ether]":
                continue
            elif elem == "on":
                break
    # i should now point on the index just before the interface
    iface = arp_line[i + 1].strip()
    # Some OSes have perm/pub after interface name
    for elem in arp_line[i + 1:]:
        if elem == "permanent":
            perm = 1
        elif elem == "published":
            pub = 1
    log.debug("ip={} hwaddr={} iface={} perm={} pub={}"
              .format(ip, hwaddr, iface, perm, pub))
    v = [
        make_tag_value(ns.hash, ns.arpe_arpe, (ns.arpe_arpe, ns.hash),
                       _confd.C_XMLBEGIN),
        make_tag_value(ns.hash, ns.arpe_ip, ip, _confd.C_IPV4),
        make_tag_value(ns.hash, ns.arpe_ifname, iface, _confd.C_STR),
        make_tag_value(ns.hash, ns.arpe_hwaddr, hwaddr, _confd.C_STR),
        make_tag_value(ns.hash, ns.arpe_permanent, perm, _confd.C_BOOL),
        make_tag_value(ns.hash, ns.arpe_published, pub, _confd.C_BOOL),
        make_tag_value(ns.hash, ns.arpe_arpe, (ns.arpe_arpe, ns.hash),
                       _confd.C_XMLEND),
    ]

    log.debug("<== len(v)={}".format(len(v)))
    return v


def update_arp_data_in_cdb(msock, tid, max_nobjs):
    log.debug("==>")
    v = []

    fp = subprocess.Popen(["arp", "-an"], universal_newlines=True,
                          stdout=subprocess.PIPE)
    maapi.set_namespace(maapisock, tid, ns.hash)
    maapi.delete(maapisock, tid, "/arpentries/arpe")

    for line in iter(fp.stdout.readline, ''):
        v += proccess_arp_line(line)
        if len(v) == max_nobjs + 2:
            log.debug("got {} objects, writing chunk to CDB".format(len(v)))
            maapi.set_values(msock, tid, v, "/arpentries")
            v = []

    if len(v) != 0:
        log.debug("writing objects (len={}) to CDB".format(len(v)))
        maapi.set_values(msock, tid, v, "/arpentries")

    log.debug("<==")


def run_arp(max_nobjs):
    log.debug("==>")

    dbname = _confd.OPERATIONAL
    tid = maapi.start_trans(maapisock, dbname, _confd.READ_WRITE)
    update_arp_data_in_cdb(maapisock, tid, max_nobjs)
    maapi.apply_trans(maapisock, tid, 0)
    maapi.finish_trans(maapisock, tid)

    log.debug("<==")


def init_confd_daemon(confd_debug_level):
    log.info("==>")

    user = "admin"
    groups = [user]
    context = "system"
    global maapisock

    # In C we use confd_init() which sets the debug-level, but for Python the
    # call to confd_init() is done when we do 'import confd'.
    # Therefore we need to set the ConfD debug level here (if we want it to be
    # different from the default debug level - CONFD_SILENT):
    _confd.set_debug(confd_debug_level, sys.stderr)
    dp.init_daemon("arpe_app")
    maapisock = socket.socket()
    maapi.connect(sock=maapisock, ip=CONFD_ADDR, port=_confd.CONFD_PORT)
    maapi.load_schemas(maapisock)  # in Python load schemas through maapi
    maapi.start_user_session(maapisock, user, context, groups, CONFD_ADDR,
                             _confd.PROTO_TCP)

    log.info("<== Initialization complete")


def main():
    log.info("==>")

    debug_levels = {
        's': _confd.SILENT,
        'd': _confd.DEBUG,
        't': _confd.TRACE,
        'p': _confd.PROTO_TRACE,
    }

    rv = _confd.CONFD_OK
    interval = INTERVAL
    max_nobjs = MAX_NOBJS
    try:

        parser = argparse.ArgumentParser(
            description="",
            formatter_class=argparse.RawTextHelpFormatter
        )
        parser.add_argument('-dl', '--debuglevel', choices=debug_levels.keys(),
                            help=textwrap.dedent(
                                '''\
                            set the debug level:
                                s = silent (i.e. no) debug
                                d = debug level debug
                                t = trace level debug
                                p = proto level debug
                            '''))
        parser.add_argument("-i", "--interval", dest="interval",
                            action="store", type=int,
                            help="timeout interval", default=INTERVAL)
        parser.add_argument("-m", "--max_nobj", dest="max_nobjs",
                            action="store", type=int,
                            help="max objs size", default=MAX_NOBJS)
        args = parser.parse_args()
        log.debug('Args = {0}'.format(args))
        if args.interval:
            interval = args.interval
        if args.max_nobjs:
            max_nobjs = args.max_nobjs
        confd_debug_level = debug_levels.get(args.debuglevel, _confd.TRACE)
        log.debug("interval={} max_nobjs={} confd_debug_level={}".
                  format(interval, max_nobjs, confd_debug_level))

        init_confd_daemon(confd_debug_level)
        while True:
            time.sleep(interval)
            run_arp(max_nobjs)
    except KeyboardInterrupt:
        log.info(" **** Ctrl-C pressed ***")
    except Exception:
        log.exception("Error during processing!")
        rv = _confd.CONFD_ERR
    finally:
        pass
        log.debug("Closing sockets")
        if maapisock is not None:
            maapisock.close()
    log.info("<== rv=%d" % rv)
    return rv


if __name__ == "__main__":
    main()
