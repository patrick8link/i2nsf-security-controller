"""
*********************************************************************
* ConfD Stats server side filtering example - Python API            *
* Implements an operational data provider                           *
*                                                                   *
* (C) 2019 Tail-f Systems                                           *
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
import os
import traceback

from arpe_ns import ns as arpe
import _confd
import _confd.dp as dp
import _confd.maapi as maapi

V = _confd.Value


class ArpFilter(object):
    def __init__(self):
        self.exact = True

    def command(self):
        return "arp -an"

    def entry_eligible(self, entry):
        return True


class ArpFilterNone(ArpFilter):
    def __init__(self):
        super(ArpFilterNone, self).__init__()
        self.exact = False


class ArpFilterIf(ArpFilter):
    def __init__(self, ifc):
        super(ArpFilterIf, self).__init__()
        self.ifc = ifc

    def command(self):
        return "arp -an -i {}".format(self.ifc)


class ArpFilterHostname(ArpFilter):
    def __init__(self, hostname):
        super(ArpFilterHostname, self).__init__()
        self.hostname = hostname

    def command(self):
        if os.uname()[0] == 'Linux':
            cmd = "arp -an {}"
        else:
            cmd = "arp -n {}"
        return cmd.format(self.hostname)


class ArpFilterField(ArpFilter):
    def __init__(self, field, value):
        super(ArpFilterField, self).__init__()
        self.field = field
        self.value = value

    def entry_eligible(self, entry):
        return entry[self.field] == self.value


def build_filter(list_filter):
    if list_filter is None:
        return ArpFilterNone()
    if list_filter.type == _confd.LF_AND:
        # to keep things simple, only one branch of the AND expression
        # is used; we will report incomplete filtering to ConfD
        arp_filter = build_filter(list_filter.expr1)
        if isinstance(arp_filter, ArpFilterNone):
            arp_filter = build_filter(list_filter.expr2)
        arp_filter.exact = False
        return arp_filter
    elif list_filter.type == _confd.LF_CMP and list_filter.op == _confd.CMP_EQ:
        val_str = str(list_filter.val)
        tag = list_filter.node[0].tag
        if tag == arpe.arpe_ip:
            return ArpFilterHostname(val_str)
        elif tag == arpe.arpe_ifname:
            return ArpFilterIf(val_str)
        elif tag == arpe.arpe_hwaddr:
            return ArpFilterField("hwaddr", val_str)
        elif tag == arpe.arpe_permanent:
            return ArpFilterField("perm", val_str)
    return ArpFilterNone()


filter_comp_op = {
    _confd.CMP_NOP: "_",
    _confd.CMP_EQ: "=",
    _confd.CMP_NEQ: "!=",
    _confd.CMP_GT: ">",
    _confd.CMP_GTE: ">=",
    _confd.CMP_LT: "<",
    _confd.CMP_LTE: "<=",
    _confd.EXEC_STARTS_WITH: "starts-with",
    _confd.EXEC_RE_MATCH: "re-match",
    _confd.EXEC_DERIVED_FROM: "derived-from",
    _confd.EXEC_DERIVED_FROM_OR_SELF: "derived-from-or-self"}


def format_filter_node(list_filter):
    return "[{}]".format(', '.join(map(str, list_filter.node)))


def format_filter(list_filter):
    if list_filter.type in (_confd.LF_OR, _confd.LF_AND):
        oper = "OR" if list_filter.type == _confd.LF_OR else "AND"
        return "{}({}, {})".format(oper,
                                   format_filter(list_filter.expr1),
                                   format_filter(list_filter.expr2))
    if list_filter.type == _confd.LF_NOT:
        return "NOT({}".format(format_filter(list_filter.expr1))
    if list_filter.type == _confd.LF_CMP:
        return "{}{}{}".format(format_filter_node(list_filter),
                               filter_comp_op[list_filter.op],
                               list_filter.val)
    if list_filter.type == _confd.LF_EXISTS:
        return "EXISTS({})".format(format_filter_node(list_filter))
    if list_filter.type == _confd.LF_EXEC:
        return "{}({}, {})".format(filter_comp_op[list_filter.op],
                                   format_filter_node(list_filter),
                                   list_filter.val)


class ArpRunner(object):
    def __init__(self):
        self.initialize()

    def initialize(self):
        self.entries = []
        self.traversal_id = -1
        self.th = -1
        self.curr = -1

    def collect_arp_data(self, tctx, hostname=None):
        self.traversal_id = tctx.traversal_id
        self.th = tctx.th
        if hostname is not None:
            self.arpfilter = ArpFilterHostname(hostname)
        else:
            list_filter = dp.data_get_list_filter(tctx)
            self.arpfilter = build_filter(list_filter)
            if list_filter is not None:
                print("\n{}".format(format_filter(list_filter)))
        command = self.arpfilter.command()
        print("using command", command)
        self.fp = subprocess.Popen(command.split(),
                                   stdout=subprocess.PIPE,
                                   universal_newlines=True)
        arpentries = []
        for line in self.fp.stdout:
            # Now lazy parse lines like
            # ? (192.168.1.1) at 00:0F:B5:EF:11:00 [ether] on eth0
            # slightly different arp output on Linux and BSD
            # FilterFun = lambda x: not(x == " " or x == "at" or x == "on")

            if line[0] != "?":
                # this is not a ARP line
                continue
            # Skip space and 'at'
            arp_line = iter(x for x in re.split("[ ,?<>()]", line) if x != "")
            ip = next(arp_line)
            perm = "false"
            pub = "false"
            elem = None
            assert next(arp_line) == "at"
            hwaddr = next(arp_line)
            if "incomplete" in hwaddr:
                hwaddr = None
                for elem in arp_line:
                    if elem == "on":
                        break
            else:
                for elem in arp_line:
                    if elem == "PERM":
                        perm = "true"
                    elif elem == "PUB":
                        pub = "true"
                    elif elem == "on":
                        break
            iface = next(arp_line).strip()
            # Some OSes have perm/pub after interface name
            for elem in arp_line:
                if elem == "permanent":
                    perm = "true"
                elif elem == "published":
                    pub = "true"
            arp_entry = dict(ip=ip, hwaddr=hwaddr, iface=iface, perm=perm,
                             pub=pub)
            if self.arpfilter.entry_eligible(arp_entry):
                arpentries.append(arp_entry)

        self.entries = sorted(arpentries, key=lambda e:
                              (socket.inet_aton(e['ip']), e['hwaddr']))
        self.curr = 0

    def init_arp(self, tctx, hostname=None):
        try:
            self.collect_arp_data(tctx, hostname)
        except Exception:
            traceback.print_exc()

    def find_entry(self, tctx, keypath):
        [ip, iface] = self.get_ip_iface(keypath)
        entry = None
        if self.curr >= 0 and self.curr < len(self.entries):
            entry = self.entries[self.curr]
        if entry is not None and entry['ip'] == ip and entry['iface'] == iface:
            return entry
        self.init_arp(tctx, ip)
        [(i, entry)] = [(i, entry)
                        for (i, entry) in enumerate(self.entries)
                        if entry['ip'] == ip and entry['iface'] == iface]
        self.curr = i
        return entry

    def get_ip_iface(self, keypath):
        keys = re.search(r'\{(.*)\}', str(keypath))
        [ip, iface] = keys.group(1).split()
        return [ip, iface]


class TransCbs(object):

    def __init__(self, workersocket, arp):
        self._workersocket = workersocket
        self.arp = arp

    def cb_init(self, tctx):
        self.arp.initialize()
        dp.trans_set_fd(tctx, self._workersocket)
        return _confd.CONFD_OK

    def cb_finish(self, tctx):
        return _confd.CONFD_OK


class DataCbs(object):

    def __init__(self, arp):
        self.arp = arp

    def cb_get_elem(self, tctx, kp):
        arpentry = self.arp.find_entry(tctx, kp)
        if arpentry is None:
            dp.data_reply_not_found(tctx)
            return _confd.CONFD_OK
        tag = kp[0].tag
        val = None
        if tag == arpe.arpe_hwaddr:
            entryelem = arpentry['hwaddr']
            if entryelem is None:
                dp.data_reply_not_found(tctx)
                return _confd.CONFD_OK
            val = V(entryelem)
        elif tag == arpe.arpe_permanent:
            val = V(arpentry['perm'] == 'true', _confd.C_BOOL)
        elif tag == arpe.arpe_published:
            val = V(arpentry['pub'] == 'true', _confd.C_BOOL)
        elif tag == arpe.arpe_ip:
            val = V(arpentry['ip'], _confd.C_IPV4)
        elif tag == arpe.arpe_ifname:
            val = V(arpentry['iface'], _confd.C_STR)
        else:
            return _confd.CONFD_ERR

        dp.data_reply_value(tctx, val)
        return _confd.CONFD_OK

    def cb_get_next(self, tctx, kp, next):
        arp = self.arp
        if next == -1 \
           or next != arp.curr+1 \
           or tctx.th != arp.th \
           or tctx.traversal_id != arp.traversal_id:
            arp.init_arp(tctx)
        else:
            arp.curr += 1

        arpentries = arp.entries

        if arp.curr < len(arpentries):
            entry = arpentries[arp.curr]
            key = [V(entry['ip'], _confd.C_IPV4), V(entry['iface'])]
            if arp.arpfilter.exact:
                tctx.cb_flags = _confd.TRANS_CB_FLAG_FILTERED
            dp.data_reply_next_key(tctx, key, arp.curr+1)
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
    CONFD_IP = os.environ.get('CONFD_IPC_ADDR', '127.0.0.1')
    CONFD_PORT = os.environ.get('CONFD_IPC_PORT', _confd.CONFD_PORT)
    try:
        maapi.connect(maapisock, CONFD_IP, CONFD_PORT)
        dp.connect(ctx,
                   ctlsock,
                   dp.CONTROL_SOCKET,
                   CONFD_IP,
                   CONFD_PORT,
                   '/')
        dp.connect(ctx,
                   wrksock,
                   dp.WORKER_SOCKET,
                   CONFD_IP,
                   CONFD_PORT,
                   '/')

        maapi.load_schemas(maapisock)

        arp = ArpRunner()

        tcb = TransCbs(wrksock, arp)
        dp.register_trans_cb(ctx, tcb)
        dcb = DataCbs(arp)
        dp.register_data_cb(ctx, arpe.callpoint_arpe, dcb,
                            flags=dp.DATA_WANT_FILTER)

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
