# *********************************************************************
# ConfD validate example - python version
#
# (C) 2020 Tail-f Systems
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
import _confd.maapi as maapi

import mtest_ns

confd_debug_level = _confd.TRACE
log_level = logging.DEBUG
CONFD_ADDR = '127.0.0.1'
maapisock = None
ctlsock = None
workersock = None
dctx = None

logging.basicConfig(
    format="%(asctime)s:%(relativeCreated)s"
           "%(levelname)s:%(filename)s:%(lineno)s:%(funcName)s  %(message)s",
    level=log_level)
log = logging.getLogger("vallog")

class TransCbsBase(object):
    def cb_init(self, tctx):
        log.debug("==>")
        rv = _confd.CONFD_OK
        global workersock

        try:
            dp.trans_set_fd(tctx, workersock)
        except Exception as error:
            log.error("Error during processing of cb_init, error: %r" % error)
            rv = _confd.CONFD_ERR

        log.debug("<== rv=%d" % rv)
        return rv

class TransCbs(TransCbsBase):
    def cb_finish(self, tctx):
        log.debug("==>")
        rv = _confd.CONFD_OK
        log.debug("<== rv=%d" % rv)
        return rv


class TransValCbs(TransCbsBase):
    def cb_stop(self, tctx):
        log.debug("==>")
        rv = _confd.CONFD_OK
        log.debug("<== rv=%d" % rv)
        return rv


class ValCbs(object):
    def cb_validate(self, tctx, kp, newval):
        global maapisock
        log.debug("==> kp=%s newval=%s" % (kp, newval))
        rv = _confd.CONFD_ERR
        try:
            maapi.attach(maapisock, mtest_ns.ns.hash, tctx)
            if kp[0].tag == mtest_ns.ns.mtest_a_number:
                b_val = maapi.get_elem(maapisock, tctx.th, "/mtest/b-number")
                a_val = maapi.get_elem(maapisock, tctx.th, "/mtest/a-number")
                a_val = int(a_val)
                b_val = int(b_val)
                newval_a = int(newval)
                log.debug("a_val={} b_val={}".format(a_val, b_val))
                if newval == 88:
                    text = "Dangerous value: 88"
                    dp.trans_seterr(tctx, text)
                    log.warning(text)
                    rv = _confd.VALIDATION_WARN
                elif newval_a > b_val:
                    rv = _confd.CONFD_OK
                else:
                    text = "a-number is <= b-number"
                    dp.trans_seterr(tctx, text)
                    log.warning(text)
            else:
                text = "Unknown tag {}".format(kp[0].tag)
                dp.trans_seterr(tctx, text)
                log.warning(text)

            maapi.detach(maapisock, tctx)
        except Exception as e:
            log.exception(e)
            rv = _confd.CONFD_ERR
        log.debug("<== rv=%d" % rv)
        return rv

def init_confd_daemon():
    log.info("==>")
    global maapisock, maapisock_commit, ctlsock, workersock, workersock_commit,\
        dctx
    # In C we use confd_init() which sets the debug-level, but for Python the
    # call to confd_init() is done when we do 'import confd'.
    # Therefore we need to set the ConfD debug level here (if we want it to be
    # different from the default debug level - CONFD_SILENT):
    _confd.set_debug(confd_debug_level, sys.stderr)

    maapisock = socket.socket()
    maapi.connect(sock=maapisock, ip=CONFD_ADDR, port=_confd.CONFD_PORT)
    maapi.load_schemas(maapisock)  # in Python load schemas through maapi

    ctlsock = socket.socket()
    workersock = socket.socket()
    dctx = dp.init_daemon("actions_daemon")
    dp.connect(dx=dctx, sock=ctlsock, type=dp.CONTROL_SOCKET,
               ip=CONFD_ADDR, port=_confd.CONFD_PORT)

    dp.connect(dx=dctx, sock=workersock, type=dp.WORKER_SOCKET,
               ip=CONFD_ADDR, port=_confd.CONFD_PORT)
    dp.register_trans_cb(dctx, TransCbs())

    # validation
    dp.register_trans_validate_cb(dctx, TransValCbs())
    dp.register_valpoint_cb(dctx, mtest_ns.ns.validate_vp1,
                            ValCbs())

    dp.register_done(dctx)
    log.info("<== Initialization complete")


def confd_loop():
    global ctlsock, workersock, dctx
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
