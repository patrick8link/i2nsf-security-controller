"""Callback module for connecting data providers to ConfD/NCS."""
import errno
import inspect
import logging
import os
import select
import socket
import threading
import traceback
import functools
import time

from . import maapi
from . import maagic
from . import log as _log
from . import pool
from . import tm
if tm.TM == '_ncs':
    from . import util

_tm = __import__(tm.TM)


def take_worker_socket(state, name, key):
    """Take worker socket associated with a worker thread from Daemon/state.

    Take worker socket from pool, must be returned with
    dp.return_worker_socket after use.
    """
    state = _daemon_as_dict(state)
    wthread = state['wthread_pool'].enqueue(_Wsock.run, name)
    with state['threads_lock']:
        state['threads'][key] = wthread
    return wthread.item.sock


def return_worker_socket(state, key):
    """Return worker socket associated with a worker thread from Daemon/state.

    Return worker socket to pool.
    """
    state = _daemon_as_dict(state)
    with state['threads_lock']:
        wthread = state['threads'][key]
        del state['threads'][key]
    wthread.item.stop()


def _select_loop(ctx, sock, finish_fds, read_finish_fds):
    fds = [sock.fileno()]
    fds.extend(finish_fds)
    fds.extend(read_finish_fds)
    p = select.poll()
    for fd in fds:
        p.register(fd, select.POLLIN)

    stop = False
    while not stop:
        r = [fd for fd, _mask in p.poll()]
        try:
            if sock.fileno() in r:
                _tm.dp.fd_ready(ctx, sock)
        except _tm.error.EOF:
            stop = True
        except Exception:
            # TOOD: sleep on N-errors in a row print(traceback.format_exc())
            pass

        if not stop:
            stop = any((finish_fd in r for finish_fd in finish_fds))

        for finish_fd in read_finish_fds:
            if finish_fd in r:
                # discard byte in pipe to avoid aborting directly in
                # next iteration
                os.read(finish_fd, 1)
                stop = True


def _daemon_as_dict(daemon):
    if isinstance(daemon, dict):
        return daemon
    return {
        'ctx': daemon._ctx,
        'csock': daemon._csock,
        'ip': daemon._ip,
        'port': daemon._port,
        'path': daemon._path,
        'log': daemon.log,
        'wthread_pool': daemon._wthread_pool,
        'threads': daemon._threads,
        'threads_lock': daemon._threads_lock
    }


def _get_num_args(fun):
    if hasattr(inspect, 'signature'):
        sig = inspect.signature(fun)
        return len(sig.parameters)
    else:
        spec = inspect.getargspec(fun)
        return len(spec.args)


class _Wsock(object):
    def __init__(self, log, ctx, sock, finish_fd=None):
        self.log = log
        self.ctx = ctx
        self.sock = sock

        if finish_fd is None:
            self._finish_fds = []
        else:
            self._finish_fds = [finish_fd]
        self._finish_pipe = os.pipe()
        self._read_finish_fds = [self._finish_pipe[0]]

    def stop(self):
        os.write(self._finish_pipe[1], b'x')

    def close(self):
        self.sock.close()
        os.close(self._finish_pipe[0])
        os.close(self._finish_pipe[1])

    @staticmethod
    def run(wsock):
        _select_loop(
            wsock.ctx, wsock.sock, wsock._finish_fds, wsock._read_finish_fds)


class _WsockCb(pool.PoolItemCb):
    def __init__(self, ctx, log, finish_fd, connect_fun):
        self.log = log

        self._ctx = ctx
        self._finish_fd = finish_fd
        self._connect_fun = connect_fun

    def create_item(self):
        sock = self._connect_fun()
        wsock = _Wsock(self.log, self._ctx, sock, self._finish_fd)
        self.log.debug('_WsockCb.create_item() = {0}'.format(wsock))
        return wsock

    def delete_item(self, wsock):
        self.log.debug('_WsockCb.delete_item({0})'.format(wsock))
        wsock.close()


class _WthreadPool(pool.ThreadPool):
    def __init__(self, ctx, log, name, finish_fd, connect_fun):
        if not isinstance(ctx, _tm.dp.DaemonCtxRef):
            raise ValueError('ctx must be an instance of {0}'.format(
                _tm.dp.DaemonCtxRef))

        self.name = '_WthreadPool({0})'.format(name)
        self.log = log

        self._cfg = pool.PoolConfig(min_size=0, max_size=0, idle_timeout_s=30)
        self._item_cb = _WsockCb(ctx, log, finish_fd, connect_fun)

        super(_WthreadPool, self).__init__(
            self.log, name, self._cfg, self._item_cb)


class TransactionCallback(object):
    """Default transaction callback implementation class.

    When connecting data providers to ConfD/NCS a transaction callback
    handler must be provided. This class is a generic implementation of
    such a handler. It implements the only required callback 'cb_init'.
    """

    def __init__(self, state):
        """Initialize a TransactionCallback object.

        The argument 'wsock' is the connected worker socket and 'log'
        is a log object.
        """
        self.log = state['log']
        self.log.debug("TransactionCallback().__init()__")

        self._state = state

    def cb_init(self, tctx):
        """The cb_init callback must always be implemented.

        It is required to prepare for future read/write operations towards
        the data source. This default implementation associates a worker
        socket with a transaction.
        """
        self.log.debug("TransactionCallback.cb_init({0})".format(tctx))

        name = 'th-{0}'.format(tctx.th)
        key = self._make_key(tctx)
        wsock = take_worker_socket(self._state, name, key)
        try:
            init_cb = getattr(self, 'init', None)
            if callable(init_cb):
                init_cb(tctx)

            # Associate the worker socket with the transaction.
            _tm.dp.trans_set_fd(tctx, wsock)
            return _tm.CONFD_OK

        except Exception as e:
            # cb_finish will not be called if cb_init did not succeed
            return_worker_socket(self._state, key)

            self.log.error(e)
            self.log.error(traceback.format_exc())
            return _tm.CONFD_ERR

    def cb_finish(self, tctx):
        """The cb_finish callback of TransactionCallback.

        This implementation returns worker socket associated with a
        worker thread from Daemon/state.
        """
        self.log.debug("TransactionCallback.cb_finish({0})".format(tctx))

        try:
            finish_cb = getattr(self, 'finish', None)
            if callable(finish_cb):
                finish_cb(tctx)
        except Exception as e:
            self.log.error(e)
            self.log.error(traceback.format_exc())
        finally:
            return_worker_socket(self._state, self._make_key(tctx))

    def _make_key(self, tctx):
        return '{0}-{1}'.format(id(self), tctx.th)


class TransValidateCallback(object):
    """Default transaction validation callback implementation class.

    When registering validation points in ConfD/NCS a transaction
    validation callback handler must be provided. This class is a
    generic implementation of such a handler. It implements the
    required callbacks 'cb_init' and 'cb_stop'.
    """

    def __init__(self, state):
        """Initialize a TransValidateCallback object.

        The argument 'state' is the dict representation of a daemon.
        """
        self._state = state

    def cb_init(self, tctx):
        """The cb_init callback must always be implemented.

        It is required to prepare for future validation
        callbacks. This default implementation allocates a worker
        thread and socket pair and associates it with the transaction.
        """
        name = 'usid-{0}-{1}'.format(tctx.uinfo.usid, 'trans_validate')
        wsock = take_worker_socket(self._state, name,
                                   self._make_key(tctx.uinfo))
        _tm.dp.trans_set_fd(tctx, wsock)

    def cb_stop(self, tctx):
        """The cb_stop callback must always be implemented.

        Clean up resources previously allocated in the cb_init
        callback. This default implementation returnes the worker
        thread and socket pair to the pool of workers.
        """
        key = self._make_key(tctx.uinfo)
        return_worker_socket(self._state, key)

    def _make_key(self, uinfo):
        return '{0}-{1}'.format(id(self), uinfo.usid)


def _state_manager_create_dp_wrapper(name):
    def wrapper(state, *args, **kwargs):
        fun = getattr(_tm.dp, name)
        return fun(state['ctx'], *args, **kwargs)
    return wrapper


class StateManager(object):
    """Base class for state managers used with Daemon"""

    def __init__(self, log):
        self.log = log

        for name in dir(_tm.dp):
            if name.startswith('register_'):
                setattr(self, name, _state_manager_create_dp_wrapper(name))

    def setup(self, state, previous_state):
        """Not Implemented."""
        raise NotImplementedError()

    def teardown(self, state, finished):
        """Not Implemented."""
        raise NotImplementedError()


class Daemon(threading.Thread):
    """Manage a data provider connection towards ConfD/NCS."""

    class State(dict):
        """State access to dp.Daemon state, primarily used in callbacks."""
        def __init__(self, daemon):
            super(Daemon.State, self).__init__(_daemon_as_dict(daemon))

        @property
        def ctx(self):
            """Get the daemon context from the Daemon"""
            return self.get('ctx', None)

        @property
        def ip(self):
            """Get the IP address used to connect, else None."""
            return self.get('ip', None)

        @property
        def port(self):
            """Get the port used to connect, else None."""
            return self.get('port', None)

        @property
        def path(self):
            """Get the path used to connect, else None."""
            return self.get('path', None)

        @property
        def log(self):
            """Get the log from the Daemon"""
            return self.get('log', None)

    # time between retries if init connection fails in
    INIT_RETRY_INTERVAL_S = 1

    def __init__(self, name, log=None, ip=_tm.ADDR, port=_tm.PORT,
                 path=None, state_mgr=None):
        """Initialize a Daemon object.

        The 'name' argument should be unique. It will show up in the
        CLI and in error messages. All other arguments are optional.
        Argument 'log' can be any log object, and if not set the standard
        logging mechanism will be used. Set 'ip' and 'port' to
        where your Confd/NCS server is. 'path' is a filename to a unix
        domain socket to be used in place of 'ip' and 'port'. If 'path'
        is provided, 'ip' and 'port' arguments are ignored.

        Daemon supports automatic restarting in case of error if a
        state manager is provided using the state_mgr parameter.
        """
        super(Daemon, self).__init__(name=name)
        self.log = log or _log.Log(logging.getLogger(__name__))
        self._ip = ip
        self._port = port
        self._path = path
        self._state = None
        self._state_mgr = state_mgr

        if path is not None:
            self._ip = None
            self._port = 0

        self._clear_connection()
        self.trans_cb_cls = None
        self.trans_validate_cb_cls = None
        self._finished = False
        self.finish_pipe = None

        # If no callbacks exist, setup the connection before entering
        # the run state to allow for registrations.
        if self._state_mgr is None:
            self._init_connection()

    def _connect_sock(self, sock_type):
        sock = socket.socket()
        _tm.dp.connect(
            self._ctx, sock, sock_type, self._ip, self._port, self._path)
        return sock

    def ctx(self):
        """Return the daemon context."""
        return self._ctx

    def ip(self):
        """Return the ip address."""
        return self._ip

    def port(self):
        """Return the port."""
        return self._port

    def path(self):
        """Return the unix domain socket path."""
        return self._path

    @property
    def wsock(self):
        raise Exception(
            'wsock no longer supported. Daemon now use multiple workers. '
            'See dp.take_worker_socket and dp.return_worker_socket.')

    def register_trans_cb(self, trans_cb_cls=TransactionCallback):
        """Register a transaction callback class.

        It's not necessary to call this method. Only do that if a custom
        transaction callback will be used.
        """
        if self.trans_cb:
            return
        self.trans_cb_cls = trans_cb_cls

        if self._ctx is not None:
            self.trans_cb = trans_cb_cls(_daemon_as_dict(self))
            _tm.dp.register_trans_cb(self._ctx, self.trans_cb)

    def register_trans_validate_cb(
            self, trans_validate_cb_cls=TransValidateCallback):
        """Register a transaction validation callback class.

        It's not necessary to call this method. Only do that if a custom
        transaction callback will be used.
        """
        if self.trans_validate_cb:
            return
        self.trans_validate_cb_cls = trans_validate_cb_cls

        if self._ctx is not None:
            self.trans_validate_cb = trans_validate_cb_cls(
                _daemon_as_dict(self))
            _tm.dp.register_trans_validate_cb(self._ctx,
                                              self.trans_validate_cb)

    def load_schemas(self):
        """Load schema information into the process memory."""
        with maapi.Maapi(self._ip, self._port, self._path):
            pass

    def start(self):
        """Start daemon work thread.

        After registering any callbacks (action, services and such), call
        this function to start processing. The low-level function
        dp.register_done() will be called before the thread is started.
        """
        if self._state_mgr is None:
            if not self.trans_cb:
                self.register_trans_cb()
            if self.trans_validate_cb_cls is not None:
                self.register_trans_validate_cb()
            _tm.dp.register_done(self._ctx)
        super(Daemon, self).start()

    def run(self):
        """Daemon thread processing loop.

        Don't call this method explicitly. It handles reading of control
        and worker sockets and notifying ConfD/NCS that it should continue
        processing by calling the low-level function dp.fd_ready().
        If the connection towards ConfD/NCS is broken or if finish() is
        explicitly called, this function (and the thread) will end.
        """
        self.log.debug('Daemon(%s).run()' % (self.name, ))

        if self._state_mgr is None:
            self._run_once_and_close()
        else:
            self._run_with_retry()

        self.log.debug('Daemon(%s).run() finished' % (self.name, ))

    def _run_with_retry(self):
        retry_count = 1
        run_count = 0
        while not self._finished:
            if run_count > 0:
                self.log.debug('Daemon(%s) (re)start %d try %d' % (
                    self.name, run_count, retry_count))

            try:
                retry_count += 1
                self._init_connection()

                try:
                    retry_count = 1
                    run_count += 1
                    self.log.debug('Daemon(%s) running' % (self.name, ))
                    self._run_once_and_close()
                except Exception as e:
                    self.log.error('Daemon(%s) run exception: %s' % (
                        self.name, str(e)))
                    self.log.error(traceback.format_exc())
            except Exception as e:
                # clear out (potentially) half-finished init, let the
                # gc take care of resource cleanup in this case.
                self._clear_connection()

                if not self._finished:
                    msg = 'Daemon(%s) failed to init due to: %s' % (
                        self.name, str(e))
                    if getattr(e, 'errno', 0) == errno.ECONNREFUSED:
                        self.log.debug('%s' % (msg, ))
                    else:
                        # socket connection succeeded but init failed,
                        # treat as error.
                        self.log.error('%s' % (msg, ))
                        self.log.error(traceback.format_exc())

                    time.sleep(Daemon.INIT_RETRY_INTERVAL_S)

    def _clear_connection(self):
        self.trans_cb = None
        self.trans_validate_cb = None
        self._csock = None
        self._ctx = None
        self._wthread_pool = None
        self._threads = None
        self._threads_lock = None

    def _init_connection(self):
        self._ctx = _tm.dp.init_daemon(self.name)
        self._csock = self._connect_sock(_tm.dp.CONTROL_SOCKET)

        self.finish_pipe = os.pipe()
        self._wthread_pool = _WthreadPool(
            self._ctx, self.log, self.name, self.finish_pipe[0],
            lambda: self._connect_sock(_tm.dp.WORKER_SOCKET))
        self._wthread_pool.start()
        self._threads = {}
        self._threads_lock = threading.Lock()

        if self._state_mgr is not None:
            previous_state = self._state
            self._state = Daemon.State(self)
            self._state_mgr.setup(self._state, previous_state)
            self.register_trans_cb(self.trans_cb_cls or TransactionCallback)
            if self.trans_validate_cb_cls is not None:
                self.register_trans_validate_cb(self.trans_validate_cb_cls)
            _tm.dp.register_done(self._ctx)

        self.log.debug('Daemon(%s) init_connection done' % (self.name,))

    def _close_connection(self, finished):
        finish_pipe = self.finish_pipe
        csock = self._csock
        ctx = self._ctx
        state = self._state
        wthread_pool = self._wthread_pool
        self._clear_connection()

        def wait_and_close():
            status = ' (in background)' if finished else ''

            os.write(finish_pipe[1], b'x')
            wthread_pool.stop()
            self.log.debug(
                'Daemon(%s) worker thread finished%s' % (self.name, status))

            try:
                if self._state_mgr is not None:
                    self.log.debug(
                        'Daemon(%s) teardown%s' % (self.name, status))
                    self._state_mgr.teardown(state, finished)
            except Exception:
                # do not log errors in deamon threads
                if not finished:
                    raise

            try:
                self._do_close_connection(finish_pipe, csock, ctx)
            except Exception:
                # do not log errors in deamon threads
                if not finished:
                    raise

            self.log.debug('Daemon(%s) finished%s' % (self.name, status))

        if finished:
            wait_and_close()
        else:
            close_thread = threading.Thread(target=wait_and_close)
            close_thread.setDaemon(True)
            close_thread.start()

    def _do_close_connection(self, finish_pipe, csock, ctx):
        if finish_pipe:
            os.close(finish_pipe[0])
            os.close(finish_pipe[1])
        if csock:
            csock.close()
        if ctx:
            _tm.dp.release_daemon(ctx)

    def _run_once_and_close(self):
        try:
            _select_loop(self._ctx, self._csock, [self.finish_pipe[0]], [])

        finally:
            # ensure worker thread completes
            self._close_connection(self._finished)

    def finish(self):
        """Stop the daemon thread."""
        self.log.debug('Daemon(%s).finish()' % (self.name, ))
        self._finished = True
        if self.finish_pipe is not None:
            os.write(self.finish_pipe[1], b'x')


class Action(object):
    """Action callback.

    This class makes it easy to create and register action callbacks by
    sub-classing it and implementing cb_action in the derived class.
    """

    def __init__(self, daemon, actionpoint, log=None, init_args=None):
        """Initialize this object.

        The 'daemon' argument should be a Daemon instance. 'actionpoint'
        is the name of the tailf:actionpoint to manage. 'log' can be any
        log object, and if not set the Daemon logger will be used.
        'init_args' may be any object that will be passed into init()
        when this object is constructed. Lastly, the low-level function
        dp.register_action_cbs() will be called.

        When using this class together with ncs.application.Application
        there is no need to manually initialize this object as it is
        done by the Application.register_action() method.

        Arguments:

        * daemon -- Daemon instance (dp.Daemon)
        * actionpoint -- actionpoint name (str)
        * log -- logging object (optional)
        * init_args -- additional arguments (optional)
        """
        self.actionpoint = actionpoint

        self._state = Daemon.State(daemon)
        ctx = self._state['ctx']
        self.log = log or self._state['log']

        if init_args:
            self.init(init_args)
        _tm.dp.register_action_cbs(ctx, actionpoint, self)

    def __setattr__(self, name, value):
        if tm.TM == '_ncs':
            fun = util.get_setattr_fun(self, Action)
            return fun(name, value)
        else:
            return super(Action, self).__setattr__(name, value)

    def init(self, init_args):
        """Custom initialization.

        When registering an action using ncs.application.Application this
        method will be called with the 'init_args' passed into the
        register_action() function.
        """
        pass

    def cb_init(self, uinfo):
        """The cb_init callback must always be implemented.

        This default implementation will associate a new worker socket
        with this callback.
        """
        name = 'usid-{0}-{1}'.format(uinfo.usid, self.actionpoint)
        wsock = take_worker_socket(self._state, name, self._make_key(uinfo))
        _tm.dp.action_set_fd(uinfo, wsock)

    @staticmethod
    def action(fn):
        """Decorator for the cb_action callback.

        Only use this decorator for actions of tailf:action type.

        Using this decorator alters the signature of the cb_action callback
        and passes in maagic.Node objects for input and output action data.

        Example of a decorated cb_action:

            @Action.action
            def cb_action(self, uinfo, name, kp, input, output, trans):
                pass

        Callback arguments:

        * uinfo -- a UserInfo object
        * name -- the tailf:action name (string)
        * kp -- the keypath of the action (HKeypathRef)
        * input -- input node (maagic.Node)
        * output -- output node (maagic.Node)
        * trans -- read only transaction, same as action transaction if
                   executed with an action context (maapi.Transaction)
        """
        if _get_num_args(fn) == 6:
            ofn = fn

            def fn2(self, uinfo, name, kp, input, output, trans):
                return ofn(self, uinfo, name, kp, input, output)
            fn = fn2

        def get_action_node(state, log, uinfo, kp):
            m = maapi.Maapi(
                ip=state['ip'], port=state['port'], path=state['path'])
            if uinfo.actx_thandle == -1:
                log.debug('starting new trans to get action {} from'.format(kp))
                act_trans = m.start_read_trans(usid=uinfo.usid)
                node = maagic.get_node(act_trans, kp)
            else:
                log.debug('attaching to transaction {} to get action {}'.format(
                    uinfo.actx_thandle, kp))
                act_trans = m.attach(uinfo.actx_thandle)
                try:
                    node = maagic.get_node(act_trans, kp)
                except Exception:
                    # when called from a notification kicker the
                    # transaction does not support reading the
                    # configuration data, fallback to new transaction.
                    log.debug(
                        'falling back to new trans to get action {}'.format(kp))
                    trans = m.start_read_trans(usid=uinfo.usid)
                    node = maagic.get_node(trans, kp)

            return m, act_trans, node

        @functools.wraps(fn)
        def wrapper(self, uinfo, name, kp, params):
            try:
                m, act_trans, node = get_action_node(
                    self._state, self.log, uinfo, kp)
                yang_name = '{0}:{1}'.format(
                    _tm.ns2prefix(name.ns), _tm.hash2str(name.tag))
                action = node._children.get_by_yang(node._backend, node,
                                                    yang_name)
                input = action.get_input()
                input._from_tagvalues(params)
                output = action.get_output()
                if tm.TM == '_ncs':
                    with util.with_setattr_check(kp):
                        ret = fn(self, uinfo, str(name), kp, input, output,
                                 act_trans)
                else:
                    ret = fn(self, uinfo, str(name), kp, input, output,
                             act_trans)

                if ret is None or ret == _tm.CONFD_OK:
                    tv = output._tagvalues()
                    if tv:
                        _tm.dp.action_reply_values(uinfo, tv)
                return ret
            except Exception as e:
                self.log.error(e)
                self.log.error(traceback.format_exc())
                raise
            finally:
                try:
                    m.close()
                except Exception:
                    pass
                return_worker_socket(self._state, self._make_key(uinfo))

        return wrapper

    @staticmethod
    def rpc(fn):
        """Decorator for the cb_action callback.

        Only use this decorator for rpc:s.

        Using this decorator alters the signature of the cb_action callback
        and passes in maagic.Node objects for input and output action data.

        Example of a decorated cb_action:

            @Action.rpc
            def cb_action(self, uinfo, name, input, output):
                pass

        Callback arguments:

        * uinfo -- a UserInfo object
        * name -- the rpc name (string)
        * input -- input node (maagic.Node)
        * output -- output node (maagic.Node)
        """
        @functools.wraps(fn)
        def wrapper(self, uinfo, name, kp, params):
            try:
                prefix = _tm.ns2prefix(name.ns)
                name = str(name)
                node = maagic.get_node(None, '/%s:%s' % (prefix, name))
                input = node.get_input()
                input._from_tagvalues(params)
                output = node.get_output()
                if tm.TM == '_ncs':
                    with util.with_setattr_check(kp):
                        ret = fn(self, uinfo, name, input, output)
                else:
                    ret = fn(self, uinfo, name, input, output)

                if ret is None or ret == _tm.CONFD_OK:
                    tv = output._tagvalues()
                    if tv:
                        _tm.dp.action_reply_values(uinfo, tv)
                return ret
            except Exception as e:
                self.log.error(e)
                self.log.error(traceback.format_exc())
                raise
            finally:
                return_worker_socket(self._state, self._make_key(uinfo))

        return wrapper

    def start(self):
        """Custom actionpoint start triggered when Python VM starts up."""
        self.log.debug('Action(', self.actionpoint, ').start()')

    def stop(self):
        """Custom actionpoint stop triggered when Python VM shuts down."""
        self.log.debug('Action(', self.actionpoint, ').finish()')

    def _make_key(self, uinfo):
        return '{0}-{1}'.format(id(self), uinfo.usid)


class ValidationError(Exception):
    """Exception raised to indicate a failed validation
    """
    def __init__(self, message):
        super(ValidationError, self).__init__(message)


class ValidationPoint(object):
    """Validation Point callback.

    This class makes it easy to create and register validation point
    callbacks by subclassing it and implementing cb_validate with the
    @validate or @validate_with_trans decorator.
    """

    def __init__(self, daemon, validationpoint, log=None, init_args=None):
        self.validationpoint = validationpoint

        daemon_d = _daemon_as_dict(daemon)
        ctx = daemon_d['ctx']
        self.log = log or daemon_d['log']
        self._maapi_pool = daemon['maapi_pool']

        if init_args:
            self.init(init_args)

        _tm.dp.register_valpoint_cb(ctx, validationpoint, self)

    def init(self, init_args):
        """Custom initialization.

        When registering a validation point using
        ncs.application.Application this method will be called with
        the 'init_args' passed into the register_validation()
        function.
        """
        pass

    @staticmethod
    def validate(fn):
        """Decorator for the cb_validate callback.

        Using this decorator alters the signature of the cb_validate
        callback and passes in the validationpoint as the last
        argument.

        In addition it logs unhandled exceptions, handles
        ValidationError exception setting the transaction error and
        returns _tm.CONFD_ERR.

        Example of a decorated cb_validate:

            @ValidationPoint.validate
            def cb_validate(self, tctx, keypath, value, validationpoint):
                pass

        Callback arguments:

        * tctx - transaction context (TransCtxRef)
        * kp -- path to the node being validated (HKeypathRef)
        * value -- new value of keypath (Value)
        * validationpoint - name of the validation point (str)
        """
        @functools.wraps(fn)
        def wrapper(self, tctx, kp, value):
            try:
                return fn(self, tctx, kp, value, self.validationpoint)
            except ValidationError as e:
                _tm.dp.trans_seterr(tctx, str(e))
                return _tm.CONFD_ERR
            except Exception as e:
                self.log.error(e)
                self.log.error(traceback.format_exc())
                raise
        return wrapper

    @staticmethod
    def validate_with_trans(fn):
        """Decorator for the cb_validate callback.

        Using this decorator alters the signature of the cb_validate
        callback and passes in root node attached to the transaction
        being validated and the validationpoint as the last argument.

        In addition it logs unhandled exceptions, handles
        ValidationError exception setting the transaction error and
        returns _tm.CONFD_ERR.

        Example of a decorated cb_validate:

            @ValidationPoint.validate_with_trans
            def cb_validate(self, tctx, root, kp, value, validationpoint):
                pass

        Callback arguments:

        * tctx - transaction context (TransCtxRef)
        * root -- root node (maagic.Root)
        * kp -- path to the node being validated (HKeypathRef)
        * value -- new value of keypath (Value)
        * validationpoint - name of the validation point (str)
        """
        @functools.wraps(fn)
        def wrapper(self, tctx, kp, value):
            m = self._maapi_pool.take_item()
            try:
                with m.attach(tctx) as trans:
                    root = maagic.get_root(trans)
                    return fn(self, tctx, root, kp, value, self.validationpoint)
            except ValidationError as e:
                _tm.dp.trans_seterr(tctx, str(e))
                return _tm.CONFD_ERR
            except Exception as e:
                self.log.error(e)
                self.log.error(traceback.format_exc())
                raise
            finally:
                self._maapi_pool.return_item(m)
        return wrapper

    def start(self):
        """Start ValidationPoint"""
        self.log.debug('ValidationPoint(', self.validationpoint, ').run()')

    def stop(self):
        """Stop ValidationPoint"""
        self.log.debug('ValidationPoint(', self.validationpoint,
                       ').run() finished')
