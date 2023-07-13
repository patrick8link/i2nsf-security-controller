# *********************************************************************
# ConfD maapi example - python version
#
# (C) 2007-2018 Tail-f Systems
# Permission to use this code as a starting point hereby granted
# This is ConfD Sample Code.
#
# See the README file for more information
# ********************************************************************

import logging
import select
import socket
import sys
import threading
from time import gmtime, strftime

import _confd
import _confd.dp as dp
import _confd.maapi as maapi

import maapi_example_ns

confd_debug_level = _confd.TRACE
log_level = logging.INFO
CONFD_ADDR = '127.0.0.1'
_DEFAULT_CONFIRMED_TIMEOUT = 600  # we use default NETCONF timeout of 600s
maapisock = None
ctlsock = None
workersock = None
# For commit command we need different worker socket running
# in different confd loop (another thread) not to block validation callpoints.
# We also need different maapi socket as fist one is used by validation.
workersock_commit = None
maapisock_commit = None
dctx = None

items_keypath_string = "/config/items"
start_log_keypath_string = "/config/start-log"

logging.basicConfig(
    format="%(asctime)s:%(relativeCreated)s"
           "%(levelname)s:%(filename)s:%(lineno)s:%(funcName)s  %(message)s",
    level=log_level)
log = logging.getLogger("cdbl")


# reuse for cb_init in TransTransCbsBase and ActCbsBase
def cb_init_common(init, fd_fun, workersock):
    log.debug("==>")
    rv = _confd.CONFD_OK
    try:
        fd_fun(init, workersock)
    except Exception as error:
        log.error("Error during processing of cb_init, error: %r" % error)
        rv = _confd.CONFD_ERR
    log.debug("<== rv=%d" % rv)
    return rv


class TransCbsBase(object):
    def cb_init(self, tctx):
        log.debug("==>")
        global workersock
        rv = cb_init_common(tctx, dp.trans_set_fd, workersock)
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
        rv = _confd.CONFD_OK
        threshold = 100
        try:
            maapi.attach(maapisock, maapi_example_ns.ns.hash, tctx)
            mc = maapi.init_cursor(maapisock, tctx.th, items_keypath_string)
            val_sum = 0
            keys = maapi.get_next(mc)
            while keys:
                if maapi.exists(maapisock, tctx.th, "%s{%s}/value" %
                                                    (items_keypath_string,
                                                     keys[0])):
                    log.debug("value element exists")
                    val = maapi.get_elem(maapisock, tctx.th, "%s{%s}/value" %
                                         (items_keypath_string, keys[0]))
                    log.debug("val=%d", val)
                    val_sum += int(val)
                keys = maapi.get_next(mc)
            maapi.destroy_cursor(mc)
            maapi.detach(maapisock, tctx)
            if val_sum > threshold:
                text = "Sum of value elements in %s is %u," \
                       " which is greater than %u!" % (
                           items_keypath_string, val_sum, threshold)
                dp.trans_seterr(tctx, text)
                log.warn(text)
                rv = _confd.CONFD_ERR
        except Exception as e:
            log.exception(e)
            rv = _confd.CONFD_ERR
        log.debug("<== rv=%d" % rv)
        return rv


class DataCbs(object):
    def cb_get_next(self, tctx, kp, next):
        global maapisock
        log.debug("==> kp=%s next=%d" % (kp, next))
        rv = _confd.CONFD_OK
        try:
            maapi.attach(maapisock, maapi_example_ns.ns.hash, tctx)
            if next == -1:  # first call
                next = 0
            n = 0
            mc = maapi.init_cursor(maapisock, tctx.th, items_keypath_string)
            keys = maapi.get_next(mc)
            while keys and n != next:
                log.debug("n=%d" % n)
                keys = maapi.get_next(mc)
                n += 1
            if not keys:
                log.debug("No more item entry, element not found.")
                dp.data_reply_next_key(tctx, None, -1)
            else:
                next += 1
                dp.data_reply_next_key(tctx, keys, next)
            maapi.destroy_cursor(mc)
            maapi.detach(maapisock, tctx)
        except Exception as e:
            log.exception(e)
            rv = _confd.CONFD_ERR
        log.debug("<== rv=%d" % rv)
        return rv

    def cb_get_elem(self, tctx, kp):
        global maapisock
        log.debug("==> kp=%s" % kp)
        rv = _confd.CONFD_OK
        try:
            maapi.attach(maapisock, maapi_example_ns.ns.hash, tctx)
            if isinstance(kp[0], _confd.XmlTag) and kp[
                0].tag == maapi_example_ns.ns.maapi_example_name:
                val = maapi.get_elem(maapisock, tctx.th, "%s{%s}/name" %
                                     (items_keypath_string, kp[1][0]))
                dp.data_reply_value(tctx, val)
            elif isinstance(kp[0], _confd.XmlTag) and kp[
                0].tag == maapi_example_ns.ns.maapi_example_value:
                val = maapi.get_elem(maapisock, tctx.th, "%s{%s}/value" %
                                     (items_keypath_string, kp[1][0]))
                dp.data_reply_value(tctx, val)
            else:
                dp.data_reply_not_found(tctx)
            maapi.detach(maapisock, tctx)
        except Exception as e:
            log.exception(e)
            rv = _confd.CONFD_ERR
        log.debug("<== rv=%d" % rv)
        return rv


class ActCbsBase(object):
    def cb_init(self, uinfo):
        log.debug("==>")
        global workersock
        rv = cb_init_common(uinfo, dp.action_set_fd, workersock)
        log.debug("<== rv=%d" % rv)
        return rv

    def cb_command(self, uinfo, path, argv):
        raise NotImplementedError('subclasses must override cb_command()!')


class ActStartCountCbs(ActCbsBase):
    def cb_command(self, uinfo, path, argv):
        global maapisock
        log.debug("==> path %s argv=%r" % (path, argv))
        rv = _confd.CONFD_OK
        try:
            maapi.attach2(maapisock, maapi_example_ns.ns.hash, uinfo.usid,
                          uinfo.actx_thandle)
            mc = maapi.init_cursor(maapisock, uinfo.actx_thandle,
                                   start_log_keypath_string)
            count = 0
            keys = maapi.get_next(mc)
            while keys:
                if (maapi.exists(maapisock, uinfo.actx_thandle,
                                 "%s{%s}" % (start_log_keypath_string,
                                             str(keys[0])))):
                    count += 1
                log.debug("Value element count=%d" % count)
                keys = maapi.get_next(mc)
            maapi.destroy_cursor(mc)
            maapi.detach2(maapisock, uinfo.actx_thandle)
            log.debug("count=%i" % count)
            maapi.cli_write(maapisock, uinfo.usid,
                            "\nApplication startup count %d\n" % count)
        except Exception as e:
            maapi.cli_write(maapisock, uinfo.usid,
                            "Cannot determine application startup count")
            log.exception(e)
            rv = _confd.CONFD_ERR

        log.debug("<== rv=%d" % rv)
        return rv


def xpath_eval_iter_usid(usid):
    def xpath_eval_iter(kp, val):
        log.debug("==> kp=%s val=%s" % (kp, val))
        rv = _confd.ITER_CONTINUE
        maapi.cli_write(maapisock, usid, "\nItem %s\n" % val)
        log.debug("<== rv=%d" % rv)
        return rv

    return xpath_eval_iter


class ActShowItemsCbs(ActCbsBase):
    def cb_command(self, uinfo, path, argv):
        global maapisock
        log.debug("==> path %s argv=%r" % (path, argv))
        rv = _confd.CONFD_OK
        if len(argv) != 2:
            rv = _confd.CONFD_ERR
            log.fatal("Wrong number of arguments %i, expected 2" % len(argv))
        else:
            log.debug("value to search for is argv[1]=%s" % argv[1])
            try:
                maapi.attach2(maapisock, maapi_example_ns.ns.hash, uinfo.usid,
                              uinfo.actx_thandle)
                qstr = "%s[value = %s]/name" % (items_keypath_string, argv[1])
                log.debug("qstr=%s" % qstr)
                maapi.xpath_eval(maapisock, uinfo.actx_thandle, qstr,
                                 xpath_eval_iter_usid(uinfo.usid), None, "")
                maapi.detach2(maapisock, uinfo.actx_thandle)
            except Exception as e:
                log.exception(e)
                rv = _confd.CONFD_ERR
        log.debug("<== rv=%d" % rv)
        return rv


class ActShowItemsSmallerCbs(ActCbsBase):
    def cb_command(self, uinfo, path, argv):
        global maapisock
        log.debug("==> path %s argv=%r" % (path, argv))
        rv = _confd.CONFD_OK
        if len(argv) != 2:
            rv = _confd.CONFD_ERR
            log.fatal("Wrong number of arguments %i, expected 2" % len(argv))
        else:
            log.debug("value to search for is argv[1]=%s" % argv[1])
            try:
                maapi.attach2(maapisock, maapi_example_ns.ns.hash, uinfo.usid,
                              uinfo.actx_thandle)
                qstr = "%s[value < %s]" % (items_keypath_string, argv[1])
                log.debug("qstr=%s" % qstr)
                qh = maapi.query_start(maapisock, uinfo.actx_thandle, qstr,
                                       None, 0,
                                       1, _confd.QUERY_TAG_VALUE, ["name"], [])
                log.debug("qh=%d" % qh)
                qr = maapi.query_result(maapisock, qh)
                log.debug("qr=%r" % qr)

                while qr.nresults > 0:
                    log.debug("qr.nresults=%i qr.offset=%i" %
                              (qr.nresults, qr.offset))
                    for i in range(qr.nresults):
                        for j in range(qr.nelements):
                            tag = _confd.hash2str(qr[i][j].tag)
                            val = qr[i][j].v
                            log.debug("tag=%s val=%s" % (tag, val))
                            maapi.cli_write(maapisock, uinfo.usid,
                                            "\nItem %s\n" % val)
                    maapi.query_free_result(qr)
                    qr = maapi.query_result(maapisock, qh)
                maapi.query_stop(maapisock, qh)
                maapi.detach2(maapisock, uinfo.actx_thandle)
            except Exception as e:
                log.exception(e)
                rv = _confd.CONFD_ERR
        log.debug("<== rv=%d" % rv)
        return rv


class ActConfirmedCommit(object):
    def cb_init(self, uinfo):
        log.debug("==>")
        global workersock_commit
        rv = cb_init_common(uinfo, dp.action_set_fd, workersock_commit)
        log.debug("<== rv=%d" % rv)
        return rv

    def timeout_to_int(self, timeout):
        if timeout is not None:
            tim = int(timeout)
        else:
            tim =_DEFAULT_CONFIRMED_TIMEOUT
        return tim

    def perform_maapi_candidate_confirmed_commit(self, usid, id=None,
                                                 timeout=None):
        """
        Start confirmed commit.
        :param usid: session id for maapi_cli_write
        :param id: persist id for the commit
        :param timeout: timeout for the commit (default is used when None)
        :return CONFD_OK or confd error value
        """
        global maapisock_commit
        log.debug("usid=%d, id=%r, timeout=%r" % (usid, id, timeout))
        maapi.candidate_confirmed_commit_persistent(maapisock_commit,
                                                    self.timeout_to_int(
                                                        timeout), id, None)
        maapi.cli_write(maapisock_commit, usid, "Confirmed commit started!\n")
        if id is not None:
            maapi.cli_write(maapisock_commit, usid, "Persist: %s\n" % id)
        if timeout is not None:
            maapi.cli_write(maapisock_commit, usid, "Timeout: %s\n" % timeout)

    def perform_maapi_commit_status(self, usid):
        """
        Print to CLI status info if there is ongoing confirmed commit.
        NOTE: maapi_confirmed_commit_in_progress return usid of ongoing commit
        (ConfD User Guide says 1)
        :param usid: session id for maapi_cli_write
        :return CONFD_OK or confd error value
        """
        global maapisock_commit
        log.debug("usid=%d", usid)
        stat = maapi.confirmed_commit_in_progress(maapisock_commit)
        log.debug("stat=%d", stat)
        if stat != 0:
            maapi.cli_write(maapisock_commit, usid,
                            "Ongoing commit in progress!\n")
            maapi.cli_write(maapisock_commit, usid, "Session id: %d\n" % stat)
        else:
            maapi.cli_write(maapisock_commit, usid,
                            "No ongoing commit in progress!\n")

    def perform_maapi_commit_abort(self, usid, id=None):
        """
        Abort ongoig commit operation
        :param usid: session id for maapi_cli_write
        :param id: persist id for the commit
        :return CONFD_OK or confd error value
        """
        log.debug("usid=%d, id=%r" % (usid, id))
        try:
            maapi.candidate_abort_commit_persistent(maapisock_commit, id)
            maapi.cli_write(maapisock_commit, usid,
                             "Confirmed commit aborted!\n")
            if id is not None:
                maapi.cli_write(maapisock_commit, usid, "Persist id: %s\n" % id)
        except Exception as e:
            maapi.cli_write(maapisock_commit, usid,
                             "Commit not aborted! (Is persist id correct?)\n")
            log.warn("Failed to abort commit! usid=%d, id=%r" %(usid, id))
            log.exception(e)
            raise e

    def confirm_maapi_candidate_commit(self, usid, id=None):
        """
        Copy candidate to running.
        Optionally use persist id of ongoing commit operation.
        :param usid: session id for maapi_cli_write
        :param id: persist id or None
        """
        log.debug("usid=%d, id=%r" % (usid, id))
        try:
            maapi.candidate_commit_persistent(maapisock_commit, id)
            maapi.cli_write(maapisock_commit, usid,
                            "Commit successfully confirmed!\n")
            if id is not None:
                maapi.cli_write(maapisock_commit, usid, "Persist id: %s\n" % id)
        except Exception as e:
            maapi.cli_write(maapisock_commit, usid,
                            "Commit not confirmed! (Is persist id correct?)\n")
            log.warn("Failed to confirm commit! usid=%i, id=%r" % (usid, id))
            log.exception(e)
            raise e

    def cb_command(self, uinfo, path, argv):
        global maapisock_commit
        log.debug("==> path %s argv=%r" % (path, argv))
        rv = _confd.CONFD_OK
        if len(argv) not in [1, 2, 3, 5]:
            rv = _confd.CONFD_ERR
            log.fatal(
                "Wrong number of arguments %i, expected 1,2,3,5" % len(argv))
        else:
            try:
                maapi.attach2(maapisock_commit, maapi_example_ns.ns.hash,
                              uinfo.usid,
                              uinfo.actx_thandle)
                if len(argv) == 1:
                    self.perform_maapi_candidate_confirmed_commit(uinfo.usid)
                elif len(argv) == 2:
                    if argv[1] == "status":
                        self.perform_maapi_commit_status(uinfo.usid)
                    elif argv[1] == "abort":
                        # abort ongoing confirmed commit - without ID
                        self.perform_maapi_commit_abort(uinfo.usid)
                    elif argv[1] == "confirm":
                        # confirm ongoing confirmed commit - without ID
                        self.confirm_maapi_candidate_commit(uinfo.usid)
                    else:
                        log.fatal("Unexpected parameter argv[1]=%s",
                                  argv[1])
                        rv = _confd.CONFD_ERR
                elif len(argv) == 3:
                    if argv[1] == "abort":
                        # abort ongoing confirmed commit - with ID
                        self.perform_maapi_commit_abort(uinfo.usid, argv[2])
                    elif argv[1] == "confirm":
                        # confirm ongoing confirmed commit - with ID
                        self.confirm_maapi_candidate_commit(uinfo.usid, argv[2])
                    elif argv[1] == "timeout":
                        # start new commit without id and with timeout
                        self.perform_maapi_candidate_confirmed_commit(
                            uinfo.usid,
                            timeout=argv[2])
                    elif argv[1] == "persist":
                        # start new commit with id and without timeout
                        self.perform_maapi_candidate_confirmed_commit(
                            uinfo.usid,
                            id=argv[2])
                        pass
                    else:
                        log.fatal("Unexpected parameter argv[1]=%s",
                                  argv[1])
                        rv = _confd.CONFD_ERR
                elif len(argv) == 5:
                    # start new commit with id and timeout
                    self.perform_maapi_candidate_confirmed_commit(uinfo.usid,
                                                                  id=argv[2],
                                                                  timeout=argv[
                                                                      4])
                else:
                    log.fatal("Unexpected len(argv)=%d value", len(argv))
                    rv = _confd.CONFD_ERR

                maapi.detach2(maapisock_commit, uinfo.actx_thandle)
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
    maapisock_commit = socket.socket()
    maapi.connect(sock=maapisock_commit, ip=CONFD_ADDR, port=_confd.CONFD_PORT)
    maapi.load_schemas(maapisock)  # in Python load schemas through maapi

    ctlsock = socket.socket()
    workersock = socket.socket()
    workersock_commit = socket.socket()
    dctx = dp.init_daemon("actions_daemon")
    dp.connect(dx=dctx, sock=ctlsock, type=dp.CONTROL_SOCKET,
               ip=CONFD_ADDR, port=_confd.CONFD_PORT)

    dp.connect(dx=dctx, sock=workersock, type=dp.WORKER_SOCKET,
               ip=CONFD_ADDR, port=_confd.CONFD_PORT)

    dp.connect(dx=dctx, sock=workersock_commit, type=dp.WORKER_SOCKET,
               ip=CONFD_ADDR, port=_confd.CONFD_PORT)

    dp.register_trans_cb(dctx, TransCbs())

    # validation
    dp.register_trans_validate_cb(dctx, TransValCbs())
    dp.register_valpoint_cb(dctx, maapi_example_ns.ns.validate_val_items,
                            ValCbs())

    # data provider
    dp.register_data_cb(dctx, maapi_example_ns.ns.callpoint_items, DataCbs())

    # clispec command actions
    dp.register_action_cbs(dctx, "start_count_cp", ActStartCountCbs())
    dp.register_action_cbs(dctx, "show_items_with_value_cp", ActShowItemsCbs())
    dp.register_action_cbs(dctx, "show_items_with_smaller_than_value_cp",
                           ActShowItemsSmallerCbs())
    dp.register_action_cbs(dctx, "start_confirmed_commit",
                           ActConfirmedCommit())
    dp.register_done(dctx)
    log.info("<== Initialization complete")


def update_start_log():
    log.info("==>")
    log.debug("Creating start-log record")
    user = "admin"
    groups = ["admin"]
    dbname = _confd.CANDIDATE
    context = "maapi"
    maapi.start_user_session(maapisock, user, context, groups, CONFD_ADDR,
                             _confd.PROTO_TCP)
    tid = maapi.start_trans(maapisock, dbname, _confd.READ_WRITE)
    cur_time = strftime("%Y-%m-%dT%H:%M:%S", gmtime())
    log.debug("logging timestamp %s" % cur_time)
    maapi.create(maapisock, tid, "%s{%s}" %
                 (start_log_keypath_string, cur_time))
    maapi.apply_trans(maapisock, tid, False)
    maapi.finish_trans(maapisock, tid)
    maapi.candidate_commit(maapisock)
    log.info("<==")

def commit_confd_loop():
    global workersock_commit, dctx
    log.info("==>")
    _r = [workersock_commit]
    _w = []
    _e = []

    try:
        while True:
            r, w, e = select.select(_r, _w, _e)

            for rs in r:
                if rs == workersock_commit:
                    try:
                        dp.fd_ready(dctx, rs)
                    except _confd.error.Error as e:
                        # Callback error
                        if e.confd_errno is _confd.ERR_EXTERNAL:
                            log.exception(e)
                        else:
                            raise e

    except Exception:
        log.info("Closing commit loop")

    log.info("<==")


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
    th = None
    try:
        init_confd_daemon()
        update_start_log()
        th = threading.Thread(target=commit_confd_loop)
        th.start()
        confd_loop()
    except:
        log.exception("Error during processing!")
        rv = _confd.CONFD_ERR
    finally:
        log.debug("Closing sockets")
        maapisock.close()
        workersock.close()
        ctlsock.close()
        if th is not None:
            th.join()
        maapisock_commit.close()
        workersock_commit.close()
    log.info("<== rv=%d" % rv)
    return rv


if __name__ == "__main__":
    main()
