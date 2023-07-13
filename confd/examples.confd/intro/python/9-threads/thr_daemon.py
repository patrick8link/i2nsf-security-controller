"""
*********************************************************************
* ConfD Threads intro example                                       *
* Implements a couple of actions                                    *
*                                                                   *
* (C) 2016 Tail-f Systems                                           *
* Permission to use this code as a starting point hereby granted    *
*                                                                   *
* See the README file for more information                          *
*********************************************************************
"""
from __future__ import print_function

import re
import socket
import select
import sys
import time
from threading import Thread

import _confd
import _confd.dp as dp
import _confd.maapi as maapi
import _confd.error as confd_errors
from model_ns import ns

# Hardcoded IP address for a running ConfD instance to connect to.
CONFD_ADDR = '127.0.0.1'

# Max # of times we try to create_daemon() (i.e. connect to ConfD)
# - could be unlimited in production code, but we don't want this
# example code to keep running forever if we forget to 'make stop'
MAX_ATTEMPTS = 5

# thread keys used for the main common threads
THR_KEY_CONTROL = 'CONTROL'
THR_KEY_WORKER = 'WORKER'


# transaction callback
class TransCbs(object):
    def __init__(self, worker_socket):
        self._worker_socket = worker_socket

    def cb_init(self, tctx):
        dp.trans_set_fd(tctx, self._worker_socket)
        return _confd.OK

    def cb_finish(self, tctx):
        return _confd.OK


# Dummy data to be sent to ConfD via data provider API
class ProcInfo:
    def __init__(self, pid, cpu):
        self.pid = pid  # used as key (index) value in the model
        self.cpu = cpu


# data provider for config false data
class DataCbs(object):
    def __init__(self):
        # ordering here is enforced only via explicit ordering when initializing
        # the array values!
        self._procData = []
        for (x, y) in [(1, 37), (5, 19), (17, 42)]:
            self._procData.append(ProcInfo(x, y))

    def cb_get_elem(self, tctx, kp):
        # get the row index ~ process id
        ptr = re.search(r'\{(.*)\}', str(kp))
        [key] = ptr.group(1).split()
        index = int(key)

        # find it in our artificial cache
        entry = None
        for proc in self._procData:
            if proc.pid == index:
                entry = proc

        if entry is None:
            dp.data_reply_not_found(tctx)
            return _confd.OK

        # get the requested element tag
        # note that tag can be obtained also via numeric value from keypath,
        # not only as a string like we do here...
        ptr = re.search(r'\}/(.*)', str(kp))
        [tag] = ptr.group(1).split()

        if tag == ns.model_pid_:
            val = _confd.Value(entry.pid, _confd.C_UINT32)
        elif tag == ns.model_cpu_:
            val = _confd.Value(entry.cpu, _confd.C_UINT32)
        else:
            print("Unsupported leaf tag requested! ({0})".format(tag))
            return _confd.ERR

        dp.data_reply_value(tctx, val)
        return _confd.OK

    def cb_get_next(self, tctx, kp, next):
        if next == -1:  # first call
            ix = 0
        else:
            ix = next

        if ix < len(self._procData):
            keys = [_confd.Value(self._procData[ix].pid, _confd.C_UINT32)]
            dp.data_reply_next_key(tctx, keys, ix + 1)
        else:  # last element
            dp.data_reply_next_key(tctx, None, 0)

        return _confd.CONFD_OK


# Thread object that creates poll loop on a newly created worker socket
class PollingThread(Thread):
    def __init__(self, dctx, key, thread_map, control=False):
        super(PollingThread, self).__init__()
        self.dctx = dctx
        self.stop_flag = False
        self.daemon = True

        # create the socket
        self.sock = socket.socket(family=socket.AF_INET,
                                  type=socket.SOCK_STREAM,
                                  proto=0)

        thr_type = dp.WORKER_SOCKET
        if control:
            thr_type = dp.CONTROL_SOCKET

        dp.connect(dx=dctx,
                   sock=self.sock,
                   type=thr_type,
                   ip=CONFD_ADDR,
                   port=_confd.CONFD_PORT)

        self.key = key
        self.thread_map = thread_map
        # add thread reference to global map for potential abort etc.
        print('[thr# ' + key + '] new thread')
        if key in self.thread_map:
            print('WARN - got recycled worker')
            del self.thread_map[key]
        self.thread_map[self.key] = self

    def _read_data(self, sock):
        try:
            dp.fd_ready(self.dctx, sock)
        except confd_errors.Error as ex:
            # Callback error
            if ex.confd_errno is _confd.ERR_EXTERNAL:
                print(str(ex))
            else:
                print("raising exception")
                raise ex

    def run(self):
        # main poll loop
        _rsocks = [self.sock]

        while not self.stop_flag:
            rr = select.select(_rsocks, [], [])[0]
            for sock in rr:
                if sock == self.sock:
                    self._read_data(sock=self.sock)

        # remove self from the list of running threads
        del self.thread_map[self.key]

        print("closing the socket")
        self.sock.close()


def make_tag_value(ns_hash, tag, init, vtype):
    """
    Wrapper to create a _confd.TagValue
    """
    return _confd.TagValue(_confd.XmlTag(ns_hash, tag),
                           _confd.Value(init, vtype))


def get_thread_key(uinfo):
    """
    Return key for the "global" threads map used to identify
    the specific thread running the action.
    """
    return str(uinfo.usid)


# callback implementing the actions defined in our yang model
class ActionCallback(object):
    def __init__(self, dctx, ctrl_sock):
        self.daemon_context = dctx
        self.csock = ctrl_sock
        self.thread_map = {}

    def cb_init(self, uinfo):
        print('init called')
        # create new worker thread
        thr = PollingThread(dctx=self.daemon_context,
                            key=get_thread_key(uinfo),
                            thread_map=self.thread_map)
        # start thread and bind it as action executor
        thr.start()
        dp.action_set_fd(uinfo, thr.sock)

    def cb_action(self, uinfo, name, keypath, params):
        name_str = str(name)
        print('action called: ' + name_str)

        if name_str == 'sleep':
            rv = self.exec_sleep(uinfo, params)
        elif name_str == 'totals':
            rv = self.exec_totals(uinfo)
        else:
            print('Unimplemented action!')
            rv = _confd.ERR

        # after the execution passed - terminate the servicing thread...
        key = get_thread_key(uinfo)
        print('[thr# ' + key + '] invoke thread stop')
        self.thread_map[key].stop_flag = True

        return rv

    def cb_abort(self, uinfo):
        print('abort called')

        # find which thread to terminate...
        key = get_thread_key(uinfo)
        print('[thr# ' + key + '] abort thread')
        if key in self.thread_map:
            print('thread stop flag set')
            self.thread_map[key].stop_flag = True
        else:
            print('WARN - thread not found')

    def exec_sleep(self, uinfo, params):
        print('exec sleep')

        key = get_thread_key(uinfo)
        print('[thr# ' + key + '] watch thread for abort request')
        if key in self.thread_map:
            thr = self.thread_map[key]
        else:
            print('Didn\'t find running thread info!')
            return _confd.ERR

        # params[0] is sleep time
        sleeptime = int(params[0].v)

        start = time.time()

        # set timeout to expected sleepy time + mini backup
        dp.action_set_timeout(uinfo, sleeptime + 3)

        slept = 0
        while (not thr.stop_flag) and (slept < sleeptime):
            time.sleep(1)
            slept += 1

        if thr.stop_flag:
            print('got interrupted after ' + str(slept) + " seconds")
        else:
            print('finished whole job')
            stop = time.time()
            result = [
                make_tag_value(ns.hash, ns.model_slept,
                               stop - start, _confd.C_UINT32)
            ]
            dp.action_reply_values(uinfo, result)

        return _confd.OK

    def exec_totals(self, uinfo):
        print('exec totals')

        key = get_thread_key(uinfo)
        print('[thr# ' + key + '] watch thread for abort request')
        thr = self.thread_map[key]

        # import pdb; pdb.set_trace()

        # open own MAAPI connection for reading values
        msock = socket.socket()
        maapi.connect(msock, CONFD_ADDR, _confd.CONFD_PORT)
        th = maapi.start_trans2(msock, _confd.RUNNING, _confd.READ, uinfo.usid)

        path = "/model:dm/proc"

        mc = maapi.init_cursor(msock, th, path)

        # gather data from ConfD
        cpu_sum = 0
        cpu_cnt = 0
        keys = maapi.get_next(mc)
        while not thr.stop_flag and keys is not False:
            cpu = maapi.get_elem(msock, th, path + '{' + str(keys[0]) + '}/cpu')
            cpu_sum += int(cpu)
            cpu_cnt += 1
            keys = maapi.get_next(mc)

        # clean the used MAAPI session
        maapi.destroy_cursor(mc)
        maapi.close(msock)

        # and dispatch result to ConfD
        result = [
            make_tag_value(ns.hash, ns.model_num_procs,
                           int(cpu_cnt), _confd.C_UINT32),
            make_tag_value(ns.hash, ns.model_total_cpu,
                           int(cpu_sum), _confd.C_UINT32)
        ]

        dp.action_reply_values(uinfo, result)
        return _confd.OK


class DaemonData:
    def __init__(self):
        self.dctx = None
        self.thread_map = {}


def create_daemon(dd):
    ret_val = _confd.OK

    dd.dctx = dp.init_daemon("threads_daemon")
    dd.thread_map = {}

    try:
        # maapi socket for auxiliary tasks
        maapisock = socket.socket()
        maapi.connect(maapisock, CONFD_ADDR, _confd.CONFD_PORT)
        maapi.load_schemas(maapisock)

        # common control socket
        control_thread = PollingThread(dd.dctx, THR_KEY_CONTROL,
                                       dd.thread_map, control=True)

        # common control socket
        worker_thread = PollingThread(dd.dctx, THR_KEY_WORKER,
                                      dd.thread_map)

        # register transaction callbacks
        tcb = TransCbs(worker_thread.sock)
        dp.register_trans_cb(dd.dctx, tcb)

        # the common data provider for config false data
        dcb = DataCbs()
        dp.register_data_cb(dd.dctx, ns.callpoint_proc, dcb)

        # and the action handler callback object
        acb = ActionCallback(dd.dctx, control_thread.sock)
        dp.register_action_cbs(dd.dctx, ns.actionpoint_sleep, acb)
        dp.register_action_cbs(dd.dctx, ns.actionpoint_totals, acb)

        dp.register_done(dd.dctx)

        # don't forget to start the servicing threads
        control_thread.start()
        worker_thread.start()
    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)
    except Exception as ex:
        eprint(ex.__str__())
        ret_val = _confd.ERR
    finally:
        pass
        # ctlsock.close()
        # wrksock.close()
        # dp.release_daemon(dctx)
    return ret_val


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def destroy_daemon(demon_data):
    # terminate all the running threads
    for key in demon_data.thread_map:
        print('terminating thread #' + key)
        demon_data.thread_map[key].stop_flag = True
        demon_data.thread_map[key].join()


# main execution
if __name__ == "__main__":

    # In C we use confd_init() which sets the debug-level, but for Python the
    # call to confd_init() is done when we do 'import confd'.
    # Therefore we need to set the debug level here:
    _confd.set_debug(_confd.TRACE, sys.stderr)

    dd = DaemonData()

    while True:
        attempts = 0

        while create_daemon(dd) != _confd.OK:
            attempts += 1
            if attempts > MAX_ATTEMPTS:
                eprint('Failed to create daemon, giving up')
                exit(2)
            else:
                eprint('Failed to create daemon, will retry...')
                time.sleep(3)

        # wait for control thread to exit
        while dd.thread_map[THR_KEY_CONTROL].isAlive():
            time.sleep(1)

        eprint("Daemon terminated, restarting")
        destroy_daemon(dd)
