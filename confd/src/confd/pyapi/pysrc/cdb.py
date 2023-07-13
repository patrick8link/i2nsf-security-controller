"""
CDB high level module.

This module implements a couple of classes for subscribing
to CDB events.
"""
import logging
import os
import select
import socket
import threading
import traceback

try:
    import queue
except ImportError:
    import Queue as queue

from . import tm
from . import log as _log

_tm = __import__(tm.TM)
cdb = _tm.cdb


def _have_callable(obj, name):
    return hasattr(obj, name) and callable(getattr(obj, name))


def _call_if_callable(obj, name, default):
    if _have_callable(obj, name):
        return getattr(obj, name)()
    return default


class Subscriber(threading.Thread):
    """CDB Subscriber for config data.

    Supports the pattern of collecting changes and then handle the changes in
    a separate thread. For each subscription point a handler object must be
    registered. The following methods will be called on the handler:

    * pre_iterate() (optional)

        Called just before iteration starts, may return a state object
        which will be passed on to the iterate method. If not implemented,
        the state object will be None.

    * iterate(kp, op, oldv, newv, state) (mandatory)

        Called for each change in the change set.

    * post_iterate(state) (optional)

        Runs in a separate thread once iteration has finished and the
        subscription socket has been synced. Will receive the final state
        object from iterate() as an argument.

    * should_iterate() (optional)

        Called to check if the subscriber wants to iterate. If this method
        returns False, neither pre_iterate() nor iterate() will be called.
        Can e.g. be used by HA secondary nodes to skip iteration. If not
        implemented, pre_iterate() and iterate() will always be called.

    * should_post_iterate(state) (optional)

        Called to determine whether post_iterate() should be called
        or not. It is recommended to implement this method to prevent
        the subscriber from calling post_iterate() when not needed.
        Should return True if post_iterate() should run, otherwise False.
        If not implemented, post_iterate() will always be called.

    Example iterator object:

        class MyIter(object):
            def pre_iterate(self):
                return []

            def iterate(self, kp, op, oldv, newv, state):
                if op is ncs.MOP_VALUE_SET:
                    state.append(newv)
                return ncs.ITER_RECURSE

            def post_iterate(self, state):
                for item in state:
                    print(item)

            def should_post_iterate(self, state):
                return state != []

    The same handler may be registered for multiple subscription points.
    In that case, pre_iterate() will only be called once, followed by iterate
    calls for all subscription points, and finally a single call to
    post_iterate().
    """

    _quit_indicator = '125b5f6c88acff5748f4b5201f93910f3810e3f7'

    def __init__(self, app=None, log=None, host=_tm.ADDR, port=_tm.PORT,
                 subtype=cdb.RUNNING, name=''):
        """Initialize a Subscriber."""
        super(Subscriber, self).__init__()
        self._cb_dict = {}
        if log is None and app is None:
            self.log = _log.Log(logging.getLogger(__name__))
        elif log is None:
            self.log = app.log
        elif isinstance(log, _log.Log):
            self.log = log
        else:
            self.log = _log.Log(log)
        self.app = app
        self.subtype = subtype
        self.name = name
        self.sock = socket.socket()
        self.fp = os.pipe()
        self.work_threads = {}
        cdb.connect(self.sock, cdb.SUBSCRIPTION_SOCKET, host, port)
        if self.subtype == cdb.SUB_RUNNING_TWOPHASE:
            cdb.mandatory_subscriber(self.sock, name)
        self.init()

    def init(self):
        """Custom initialization.

        Override this method to do custom initialization without needing
        to override __init__.
        """
        pass

    def register(self, path, iter_obj=None, iter_flags=_tm.ITER_WANT_PREV,
                 priority=0, flags=0, subtype=None):
        """Register an iterator object at a specific path.

        Setting 'iter_obj' to None will internally use 'self' as the iterator
        object which means that Subscriber needs to be sub-classed.

        Operational and configuration subscriptions can be done on the
        same Subscriber, but in that case the notifications may be
        arbitrarily interleaved, including operational notifications
        arriving between different configuration notifications for the
        same transaction. If this is a problem, use separate
        Subscriber instances for operational and configuration
        subscriptions.

        Arguments:

        * path -- path to node (str)
        * iter_object -- iterator object (obj, optional)
        * iter_flags -- iterator flags (int, optional)
        * priority -- priority order for subscribers (int)
        * flags -- additional subscriber flags (int)
        * subtype -- subscriber type SUB_RUNNING, SUB_RUNNING_TWOPHASE,
                    SUB_OPERATIONAL (cdb)

        Returns:

        * subscription point (int)

        Flags (cdb):

        * SUB_WANT_ABORT_ON_ABORT

        Iterator Flags (ncs):

        * ITER_WANT_PREV
        * ITER_WANT_ANCESTOR_DELETE
        * ITER_WANT_ATTR
        * ITER_WANT_CLI_STR
        * ITER_WANT_SCHEMA_ORDER
        * ITER_WANT_LEAF_FIRST_ORDER
        * ITER_WANT_LEAF_LAST_ORDER
        * ITER_WANT_REVERSE
        * ITER_WANT_P_CONTAINER
        * ITER_WANT_LEAF_LIST_AS_LEAF
        * ITER_WANT_CLI_ORDER
        """
        iter_obj = iter_obj or self
        if not _have_callable(iter_obj, 'iterate'):
            raise Exception('Iterator object must have an iterate() method')
        if subtype is None:
            subtype = self.subtype
        # not looking up the ns for the path, can match multiple
        # namespaces if under a mount-point.
        point = cdb.subscribe2(self.sock, subtype, flags, priority,
                               0, path)
        self._cb_dict[point] = (iter_obj, subtype, iter_flags)
        if _have_callable(iter_obj, 'post_iterate') and \
           iter_obj not in self.work_threads:
            q = queue.Queue()
            t = Subscriber._Workthread(iter_obj.post_iterate, q, self.log)
            t.start()
            self.work_threads[iter_obj] = (t, q)
        return point

    def run(self):
        """Main processing loop."""
        name = self.__class__.__name__ + ' (subscriber)'
        if self.app:
            self.app.add_running_thread(name)
        try:
            fds = [self.sock.fileno(), self.fp[0]]
            p = select.poll()
            for fd in fds:
                p.register(fd, select.POLLIN)
            while True:
                self.log.debug("Waiting for subscription event")
                r = [fd for fd, _mask in p.poll()]
                if self.sock.fileno() in r:
                    if not self._read_sub_socket():
                        break
                if self.fp[0] in r:
                    break
        except Exception as e:
            self.log.error(e)
            self.log.error(traceback.format_exc())
        finally:
            cdb.close(self.sock)
            os.close(self.fp[0])
            os.close(self.fp[1])
        if self.app:
            self.app.del_running_thread(name)
        self.log.debug("Subscriber finished")

    def start(self):
        """Start the subscriber."""
        self.log.debug("Starting subscriber")
        cdb.subscribe_done(self.sock)
        super(Subscriber, self).start()

    def stop(self):
        """Stop the subscriber."""
        self.log.debug("Stopping subscriber")
        for cb in self.work_threads:
            _, q = self.work_threads[cb]
            q.put(Subscriber._quit_indicator)
        for cb in self.work_threads:
            t, _ = self.work_threads[cb]
            t.join()
        try:
            # We need a silent try-except here.
            # The run method may already be finished (e.g. if NCS went down)
            # so this pipe may be closed when we try to write to it.
            os.write(self.fp[1], b'x')
        except Exception:
            pass
        self.join()

    def _read_sub_socket(self):
        states = {}
        try:
            points = cdb.read_subscription_socket(self.sock)
        except _tm.error.EOF:
            return False
        except Exception as e:
            self.log.error(e)
            self.log.error(traceback.format_exc())
            return False

        for point in points:
            (cb, subtype, flags) = self._cb_dict[point]

            # In some cases (e.g. HA secondary nodes) it's desirable
            # to be able to skip calling diff_iterate.
            if not _call_if_callable(cb, 'should_iterate', True):
                continue

            if cb not in states:
                states[cb] = _call_if_callable(cb, 'pre_iterate', None)
            cdb.diff_iterate(self.sock, point, cb.iterate, flags, states[cb])

        if subtype is cdb.OPERATIONAL:
            cdb.sync_subscription_socket(self.sock, cdb.DONE_OPERATIONAL)
        else:
            cdb.sync_subscription_socket(self.sock, cdb.DONE_PRIORITY)

        for cb in states:
            if _have_callable(cb, 'post_iterate'):
                self._maybe_run_post_iterate(cb, states[cb])
        return True

    def _maybe_run_post_iterate(self, cb, state):
        if not _have_callable(cb, 'should_post_iterate') or \
           cb.should_post_iterate(state):
            _, q = self.work_threads[cb]
            q.put(state)

    class _Workthread(threading.Thread):
        def __init__(self, post_iter, q, log):
            super(Subscriber._Workthread, self).__init__()
            self.post_iter = post_iter
            self.q = q
            self.log = log

        def run(self):
            while True:
                state = self.q.get()
                if state is Subscriber._quit_indicator:
                    break
                try:
                    self.post_iter(state)
                except Exception as e:
                    self.log.error(e)
                    self.log.error(traceback.format_exc())


class TwoPhaseSubscriber(Subscriber):
    """CDB Subscriber for config data with support for aborting transactions.

    Subscriber that is capable of aborting transactions during the
    prepare phase of a transaction.

    The following methods will be called on the handler in addition to
    the methods described in Subscriber:

    * prepare(kp, op, oldv, newv, state) (mandatory)

        Called in the transaction prepare phase. If an exception occurs
        during the invocation of prepare the transaction is aborted.

    * cleanup(state) (optional)

        Called after a prepare failure if available. Use to cleanup
        resources allocated by prepare.

    * abort(kp, op, oldv, newv, state) (mandatory)

        Called if another subscriber aborts the transaction and this
        transaction has been prepared.

    Methods are called in the following order:

    1. should_iterate -> pre_iterate ( -> cleanup, on exception)
    2. should_iterate -> iterate -> post_iterate
    3. should_iterate -> abort, if transaction is aborted by other subscriber
    """

    def __init__(self, name, app=None, log=None, host=_tm.ADDR, port=_tm.PORT):
        super(TwoPhaseSubscriber, self).__init__(
            app, log, host, port, name=name, subtype=cdb.SUB_RUNNING_TWOPHASE)

        self._states = {}

    def register(self, path, iter_obj=None, iter_flags=_tm.ITER_WANT_PREV,
                 priority=0, flags=0, subtype=None):
        """Register an iterator object at a specific path.

        Setting 'iter_obj' to None will internally use 'self' as the iterator
        object which means that TwoPhaseSubscriber needs to be sub-classed.

        Operational and configuration subscriptions can be done on the
        same TwoPhaseSubscriber, but in that case the notifications may be
        arbitrarily interleaved, including operational notifications
        arriving between different configuration notifications for the
        same transaction. If this is a problem, use separate
        TwoPhaseSubscriber instances for operational and configuration
        subscriptions.

        For arguments and flags, see Subscriber.register()
        """
        iter_obj = iter_obj or self
        if not _have_callable(iter_obj, 'prepare'):
            raise Exception('Iterator object must have a prepare() method')
        if not _have_callable(iter_obj, 'abort'):
            raise Exception('Iterator object must have an abort() method')

        super(TwoPhaseSubscriber, self).register(
            path, iter_obj, iter_flags, priority, flags, subtype)

    def _read_sub_socket(self):
        try:
            (type, flags, points) = cdb.read_subscription_socket2(self.sock)
        except _tm.error.EOF:
            return False
        except Exception as e:
            self.log.error(e)
            self.log.error(traceback.format_exc())
            return False

        if type == cdb.SUB_PREPARE:
            self._states = {}

            message = None
            for point in points:
                (cb, subtype, flags) = self._cb_dict[point]

                if not _call_if_callable(cb, 'should_iterate', True):
                    continue

                if cb not in self._states:
                    self._states[cb] = _call_if_callable(
                        cb, 'pre_iterate', None)

                try:
                    cdb.diff_iterate(
                        self.sock, point, cb.prepare, flags, self._states[cb])
                except Exception as e:
                    self.log.error(e)
                    self.log.error(traceback.format_exc())
                    message = e.message or 'aborted'

            if message is None:
                cdb.sync_subscription_socket(self.sock, cdb.DONE_PRIORITY)
            else:
                if _have_callable(cb, 'cleanup'):
                    try:
                        cb.cleanup(self._states[cb])
                    except Exception as e:
                        self.log.error(e)
                        self.log.error(traceback.format_exc())

                cdb.sub_abort_trans(self.sock, 1, 0, 0, message)

        elif type in (cdb.SUB_COMMIT, cdb.SUB_ABORT):
            for point in points:
                (cb, subtype, flags) = self._cb_dict[point]
                if not _call_if_callable(cb, 'should_iterate', True):
                    continue

                iter_cb = type == cdb.SUB_COMMIT and cb.iterate or cb.abort
                cdb.diff_iterate(
                    self.sock, point, iter_cb, flags, self._states[cb])

            cdb.sync_subscription_socket(self.sock, cdb.DONE_PRIORITY)

            for cb in self._states:
                if _have_callable(cb, 'post_iterate'):
                    self._maybe_run_post_iterate(cb, self._states[cb])

        else:
            # ignore unsupported types
            pass

        return True


class OperSubscriber(Subscriber):
    """CDB Subscriber for oper data.

    Use this class when subscribing on operational data. In all other means
    the behavior is the same as for Subscriber().
    """

    def __init__(self, app=None, log=None, host=_tm.ADDR, port=_tm.PORT):
        """Initialize an OperSubscriber."""
        super(OperSubscriber, self).__init__(app, log, host, port,
                                             subtype=cdb.OPERATIONAL)
