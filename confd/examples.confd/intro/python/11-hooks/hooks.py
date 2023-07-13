# *********************************************************************
# ConfD hooks example - python version
#
# (C) 2018 Tail-f Systems
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
import _confd.dp as dp
from _confd import maapi

import hooks_ns

confd_debug_level = _confd.TRACE
log_level = logging.INFO
CONFD_ADDR = '127.0.0.1'
maapisock = None
ctlsock = None
workersock = None
dctx = None

logging.basicConfig(
    format="%(asctime)s:%(relativeCreated)s"
           "%(levelname)s:%(filename)s:%(lineno)s:%(funcName)s  %(message)s",
    level=log_level)
log = logging.getLogger("hooks")


class TransCbs(object):
    def cb_init(self, tctx):
        log.debug("==>")
        rv = _confd.CONFD_OK
        dp.trans_set_fd(tctx, workersock)
        maapi.attach(maapisock, 0, tctx)
        log.debug("<== rv=%d" % rv)
        return rv

    def cb_finish(self, tctx):
        log.debug("==>")
        rv = _confd.CONFD_OK
        maapi.detach(maapisock, tctx)
        log.debug("<== rv=%d" % rv)
        return rv


class DataIpMaskCbs(object):
    def cb_create(self, tctx, kp):
        log.debug("==> kp=%s" % kp)
        rv = _confd.CONFD_ERR
        log.error("ip-mask: This 'create hook' function  should not be called"
                  " as create is invoked only on list elements!")
        log.debug("<== rv=%d" % rv)
        return rv

    def cb_remove(self, tctx, kp):
        log.debug("==> kp=%s" % kp)
        rv = _confd.CONFD_OK
        log.info("ip-mask: Remove hook detected, no change done.")
        log.debug("<== rv=%d" % rv)
        return rv

    def cb_set_elem(self, tctx, kp, newval):
        log.debug("==> kp=%s newval=%s" % (kp, newval))
        rv = _confd.CONFD_OK
        log.info("ip-mask: Set hook detected.")
        try:
            path = str(kp[1:])  # remove first kp elem
            log.info("ip-mask: Host path=%s" % path)
            ip = None
            netmask = None
            if maapi.exists(maapisock, tctx.th, path + "/ip"):
                log.debug("ip-mask: ip exits")
                ip = maapi.get_elem(maapisock, tctx.th, path + "/ip")
            if maapi.exists(maapisock, tctx.th, path + "/netmask"):
                log.debug("ip-mask: netmask exits")
                netmask = maapi.get_elem(maapisock, tctx.th, path + "/netmask")
            if ip is not None and netmask is not None:
                if not maapi.exists(maapisock, tctx.th, path + "/gw"):
                    ip_addr = [int(x) for x in str(ip).split('.')]
                    netmask_addr = [int(x) for x in str(netmask).split('.')]
                    gw_addr = ""
                    for i in range(len(ip_addr)):
                        if i is len(ip_addr) - 1:
                            gw_addr += str((ip_addr[i] & netmask_addr[i]) | 1)
                        else:
                            gw_addr += str(ip_addr[i] & netmask_addr[i])
                            gw_addr += "."
                    gw = _confd.Value(gw_addr, _confd.C_IPV4)
                    maapi.set_elem(maapisock, tctx.th, gw, path + "/gw")
                else:
                    log.info("ip-mask: gw for host %s already set." % path)
            else:
                log.info("ip or netmask not set!")

        except Exception as e:
            log.exception(e)
            rv = _confd.CONFD_ERR
        log.debug("<== rv=%d" % rv)
        return rv


class DataTransHostCbs(object):

    @staticmethod
    def convert_ip_elem(maapisock, th, key, elem):
        log.debug("==> th=%s key=%s elem=%s" % (th, key, elem))

        if maapi.exists(maapisock, th, "/hosts{%s}/%s" % (key, elem)):
            val = maapi.get_elem(maapisock, th, "/hosts{%s}/%s" % (key, elem))
            ip = [int(x) for x in str(val).split('.')]
            ip6 = "::ffff:" \
                  + "%02x:" % ((ip[1] & 0xFF) + ((ip[0] << 8) & 0xFF00)) \
                  + "%02x" % ((ip[3] & 0xFF) + ((ip[2] << 8) & 0xFF00))
            ip6_val = _confd.Value(ip6, _confd.C_IPV6)
            log.debug("ip ipv4=%s" % val)
            log.debug("ip ipv6=%s" % ip6_val)
            maapi.set_elem(maapisock, th, ip6_val,
                           "/hosts-ipv6{%s}/%s" % (key, elem))

        log.debug("<==")

    @staticmethod
    def create_ipv6_hosts(maapisock, th):
        log.debug("==> th=%s" % th)
        rv = _confd.CONFD_OK

        mc = maapi.init_cursor(maapisock, th, "/hosts")
        keys = maapi.get_next(mc)
        while keys:
            if not maapi.exists(maapisock, th, "/hosts-ipv6{%s}" % keys[0]):
                log.debug("Ipv6 host does not exists, creating...")
                maapi.create(maapisock, th, "/hosts-ipv6{%s}" % keys[0])
                DataTransHostCbs.convert_ip_elem(maapisock, th, keys[0], "ip")
                DataTransHostCbs.convert_ip_elem(maapisock, th, keys[0], "gw")
            keys = maapi.get_next(mc)
        maapi.destroy_cursor(mc)

        log.debug("<== rv=%d" % rv)
        return rv

    @staticmethod
    def delete_ipv6_hosts(maapisock, th):
        log.debug("==> th=%s" % th)
        rv = _confd.CONFD_OK

        mc = maapi.init_cursor(maapisock, th, "/hosts-ipv6")
        keys = maapi.get_next(mc)
        while keys:
            if not maapi.exists(maapisock, th, "/hosts{%s}" % keys[0]):
                log.debug("Ipv4 host does not exists, deleting ipv6 host")
                maapi.delete(maapisock, th, "/hosts-ipv6{%s}" % keys[0])
            keys = maapi.get_next(mc)
        maapi.destroy_cursor(mc)

        log.debug("<== rv=%d" % rv)
        return rv

    def cb_write_all(self, tctx, kp):
        log.debug("==> kp=%s" % kp)
        rv = _confd.CONFD_OK

        if _confd.CONFD_OK != self.create_ipv6_hosts(maapisock, tctx.th):
            log.fatal("Failed to create ipv6 hosts!")
            rv = _confd.CONFD_ERR
        else:
            if _confd.CONFD_OK != self.delete_ipv6_hosts(maapisock, tctx.th):
                log.fatal("Failed to delete ipv6 hosts!")
                rv = _confd.CONFD_ERR

        log.debug("<== rv=%d" % rv)
        return rv


def init_confd_daemon():
    log.info("==>")
    global maapisock, ctlsock, workersock, dctx
    # In C we use confd_init() which sets the debug-level, but for Python the
    # call to confd_init() is done when we do 'import confd'.
    # Therefore we need to set the ConfD debug level here (if we want it to be
    # different from the default debug level - CONFD_SILENT):
    _confd.set_debug(confd_debug_level, sys.stderr)
    ctlsock = socket.socket()
    workersock = socket.socket()
    maapisock = socket.socket()
    dctx = dp.init_daemon("hooks_daemon")
    maapi.connect(sock=maapisock, ip=CONFD_ADDR, port=_confd.CONFD_PORT)
    maapi.load_schemas(maapisock)  # in Python load schemas through maapi
    dp.connect(dx=dctx, sock=ctlsock, type=dp.CONTROL_SOCKET,
               ip=CONFD_ADDR, port=_confd.CONFD_PORT)

    dp.connect(dx=dctx, sock=workersock, type=dp.WORKER_SOCKET,
               ip=CONFD_ADDR, port=_confd.CONFD_PORT)

    dp.register_trans_cb(dctx, TransCbs())
    dp.register_data_cb(dctx, hooks_ns.ns.callpoint_ip_mask, DataIpMaskCbs())
    dp.register_data_cb(dctx, hooks_ns.ns.callpoint_trans_hosts,
                        DataTransHostCbs())

    dp.register_done(dctx)
    log.info("<== Initialization complete")


def confd_loop():
    log.info("==>")
    _r = [ctlsock, workersock]
    _w = []
    _e = []

    try:
        while True:
            r, w, e = select.select(_r, _w, _e)

            for rs in r:
                if rs == ctlsock or rs == workersock:
                    try:
                        dp.fd_ready(dctx, rs)
                    except _confd.error.Error as e:
                        # Callback error
                        if e.confd_errno is _confd.ERR_EXTERNAL:
                            log.exception(e)
                        else:
                            raise e

    except KeyboardInterrupt:
        log.info(" **** Ctrl-C pressed ***")

    log.info("<==")


def main():
    log.info("==>")
    rv = _confd.CONFD_OK
    try:
        init_confd_daemon()
        confd_loop()
    except:
        log.exception("Error during processing!")
        rv = _confd.CONFD_ERR
    finally:
        log.debug("Closing sockets")
        maapisock.close()
        workersock.close()
        ctlsock.close()
    log.info("<== rv=%d" % rv)
    return rv


if __name__ == "__main__":
    main()
