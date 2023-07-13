"""
*********************************************************************
* ConfD Stats intro example                                         *
* Implements an operational data provider                           *
*                                                                   *
* (C) 2015 Tail-f Systems                                           *
* Permission to use this code as a starting point hereby granted    *
*                                                                   *
* See the README file for more information                          *
*********************************************************************
"""
from __future__ import print_function
import re
import select
import socket
import subprocess
import sys
import time
import traceback

import arpe_ns
import _confd
import _confd.dp as dp
import _confd.maapi as maapi

V = _confd.Value


class ArpRunner(object):
    def __init__(self):
        self.arpdata = None

    def collect_arp_data(self):
        self.fp = subprocess.Popen(["arp", "-an"], stdout=subprocess.PIPE,
                                   universal_newlines=True)
        arpentries = []
        for line in iter(self.fp.stdout.readline, ''):
            # Now lazy parse lines like
            # ? (192.168.1.1) at 00:0F:B5:EF:11:00 [ether] on eth0
            # slightly different arp output on Linux and BSD
            # FilterFun = lambda x: not(x == " " or x == "at" or x == "on")

            # Skip space and 'at'
            filterfun = lambda x: not(x == "" or x == "at")
            arp_line = list(filter(filterfun, re.split("[ ,?<>()]", line)))
            ip = arp_line[0]
            i = 1
            perm = None
            pub = None
            elem = None
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
            iface = arp_line[i+1].strip()
            # Some OSes have perm/pub after interface name
            for elem in arp_line[i+1:]:
                if elem == "permanent":
                    perm = 1
                elif elem == "published":
                    pub = 1
            arp_entry = dict(ip=ip, hwaddr=hwaddr, iface=iface, perm=perm,
                             pub=pub)
            arpentries.append(arp_entry)

        self.arpdata = arpentries

    def find_entry(self, keypath):
        index = self.get_index(keypath)
        entry = self.arpdata[index]
        return entry

    def get_index(self, keypath):
        keys = re.search(r'\{(.*)\}', str(keypath))
        index = keys.group(1)
        return int(index)

    def find_tag(self, keypath):
        keys = re.search(r'\}/(.*)', str(keypath))
        [tag] = keys.group(1).split()
        return tag


class TransCbs(object):

    def __init__(self, workersocket, arp):
        self._workersocket = workersocket
        self.arp = arp

    def cb_init(self, tctx):
        arp = self.arp
        try:
            arp.collect_arp_data()
            dp.trans_set_fd(tctx, self._workersocket)
            return _confd.CONFD_OK
        except:
            traceback.print_exc()

    def cb_finish(self, tctx):
        self.arp.arpdata = None
        return _confd.CONFD_OK


class DataCbs(object):

    def __init__(self, arp):
        self.arp = arp

    def cb_get_elem(self, tctx, kp):
        arp = self.arp
        if arp.arpdata is None:
            arp.collect_arp_data()

        arpentry = arp.find_entry(kp)
        if arpentry is None:
            dp.data_reply_not_found(tctx)
            return _confd.CONFD_OK

        tag = arp.find_tag(kp)
        val = None
        print("\npicking out {0} from {1}\n".format(tag, arpentry))
        if tag == 'hwaddr':
            entryelem = arpentry[tag]
            if entryelem is None:
                dp.data_reply_not_found(tctx)
                return _confd.CONFD_OK
            val = V(entryelem)
        elif tag == 'permanent':
            if arpentry['perm']:
                val = V(True, _confd.C_BOOL)
            else:
                val = V(False, _confd.C_BOOL)
        elif tag == 'published':
            if arpentry['pub']:
                val = V(True, _confd.C_BOOL)
            else:
                val = V(False, _confd.C_BOOL)
        elif tag == 'ip':
            entryelem = arpentry[tag]
            val = V(entryelem, _confd.C_IPV4)
        elif tag == 'ifname':
            entryelem = arpentry['iface']
            val = V(entryelem)
        else:
            return _confd.CONFD_ERR
        dp.data_reply_value(tctx, val)
        return _confd.CONFD_OK

    def cb_get_next(self, tctx, kp, next):
        arp = self.arp
        if next == -1:  # first call
            arp.collect_arp_data()

        if next < len(arp.arpdata)-1:
            key = [V(next+1, _confd.C_INT64)]
            dp.data_reply_next_key(tctx, key, next+1)
        else:  # last element
            dp.data_reply_next_key(tctx, None, 0)

        return _confd.CONFD_OK


def run():
    # In C we use confd_init() which sets the debug-level, but for Python the
    # call to confd_init() is done when we do 'import confd'.
    # Therefore we need to set the debug level here:
    _confd.set_debug(_confd.TRACE, sys.stderr)

    ctx = dp.init_daemon("arpe_daemon")
    maapisock = socket.socket()
    ctlsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    wrksock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    try:
        maapi.connect(maapisock, '127.0.0.1', _confd.CONFD_PORT)
        dp.connect(ctx,
                   ctlsock,
                   dp.CONTROL_SOCKET,
                   '127.0.0.1',
                   _confd.CONFD_PORT,
                   '/')
        dp.connect(ctx,
                   wrksock,
                   dp.WORKER_SOCKET,
                   '127.0.0.1',
                   _confd.CONFD_PORT,
                   '/')

        maapi.load_schemas(maapisock)

        arp = ArpRunner()

        tcb = TransCbs(wrksock, arp)
        dp.register_trans_cb(ctx, tcb)
        dcb = DataCbs(arp)
        dp.register_data_cb(ctx, arpe_ns.ns.callpoint_arpe2, dcb)

        dp.register_done(ctx)

        try:
            _r = [ctlsock, wrksock]
            _w = []
            _e = []

            while (True):
                (r, w, e) = select.select(_r, _w, _e, 1)
                for rs in r:
                    if rs.fileno() == ctlsock.fileno():
                        try:
                            dp.fd_ready(ctx, ctlsock)
                        except (_confd.error.Error) as e:
                            if e.confd_errno is not _confd.ERR_EXTERNAL:
                                raise e
                    elif rs.fileno() == wrksock.fileno():
                        try:
                            dp.fd_ready(ctx, wrksock)
                        except (_confd.error.Error) as e:
                            if e.confd_errno is not _confd.ERR_EXTERNAL:
                                raise e

        except KeyboardInterrupt:
            print("\nCtrl-C pressed\n")

    finally:
        ctlsock.close()
        wrksock.close()
        dp.release_daemon(ctx)


if __name__ == "__main__":
    run()
