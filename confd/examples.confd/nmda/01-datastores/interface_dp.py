import contextlib
import psutil
import select
import socket
import sys

import _confd
import confd


class UsessCb(object):
    def __init__(self):
        pass

    def cb_start(self, dx, uinfo):
        pass

    def cb_stop(self, dx, uinfo):
        pass


class TransCb(object):
    def __init__(self, s_work):
        self.s_work = s_work

    def cb_init(self, tctx):
        _confd.dp.trans_set_fd(tctx, self.s_work)

    def cb_finish(self, tctx):
        pass


class InterfaceProvider(object):
    def __init__(self, keys, if_data):
        self.idx = 0
        self.keys = keys
        self.if_data = if_data

    def cb_num_instances(self, tctx, kp):
        _confd.dp.data_reply_value(tctx, _confd.Value(len(self.keys)))

    def cb_get_elem(self, tctx, kp):
        split_kp = str(kp).split('/')
        split_kp2 = str(kp).split('{')
        split_kp3 = split_kp2[1].split('}')
        keyname = split_kp3[0]
        relevant_ifdata = self.if_data.get(keyname)

        if split_kp[-1] == 'mac':
            macs = [x.address for x in relevant_ifdata if x.family == 17]
            if not macs:
                _confd.dp.data_reply_not_found(tctx)
            else:
                my_mac = str(macs[0])
                val = _confd.Value(my_mac, _confd.C_BUF)
                _confd.dp.data_reply_value(tctx, val)
        elif split_kp[-1] == 'in-packets':
            io_cntr = psutil.net_io_counters(pernic=True)
            if io_cntr.get(keyname) is not None:
                packets_in = io_cntr.get(keyname).packets_recv
                val = _confd.Value(packets_in, _confd.C_UINT32)
                _confd.dp.data_reply_value(tctx, val)
            else:
                _confd.dp.data_reply_not_found(tctx)
        elif split_kp[-1] == 'ipv4-address':
            if self.if_data.get(keyname)[0].family != 2:
                _confd.dp.data_reply_not_found(tctx)
            else:
                formatted_ip = str(relevant_ifdata[0].address)
                val = _confd.Value(formatted_ip, _confd.C_IPV4)
                _confd.dp.data_reply_value(tctx, val)
        return _confd.OK

    def cb_get_next(self, tctx, kp, next_i):
        if self.idx < len(self.keys):
            _confd.dp.data_reply_next_key(
                tctx=tctx, keys=[self.keys[self.idx]], next=self.idx)
            self.idx += 1
        else:
            _confd.dp.data_reply_next_key(tctx, None, 0)
            self.idx = 0

    def cb_get_attrs(self, tctx, kp, attrs):
        return _confd.dp.data_reply_attrs(tctx, [])


@contextlib.contextmanager
def dp_ctx(name):
    ctx = _confd.dp.init_daemon(name)
    try:
        s_ctrl = socket.socket()
        try:
            s_work = socket.socket()
            try:
                _confd.dp.connect(ctx, s_ctrl, _confd.dp.CONTROL_SOCKET,
                                  ip='127.0.0.1', port=_confd.CONFD_PORT)
                _confd.dp.connect(ctx, s_work, _confd.dp.WORKER_SOCKET,
                                  ip='127.0.0.1', port=_confd.CONFD_PORT)

                yield (ctx, s_ctrl, s_work)

            finally:
                s_work.close()
        finally:
            s_ctrl.close()
    finally:
        _confd.dp.release_daemon(ctx)


def select_loop(ctx, s_ctrl, s_work, s_finish):
    while True:
        r, w, e = select.select([s_ctrl, s_work, s_finish], [], [])

        if s_finish in r:
            break

        for sock in r:
            _confd.dp.fd_ready(ctx, sock)


def main():
    # load schemas
    with confd.maapi.single_read_trans('admin', 'system'):
        pass

    interfaces = psutil.net_if_addrs()
    keys = [_confd.Value(key) for key in interfaces.keys()]

    with dp_ctx('example-interface') as info:
        ctx, s_ctrl, s_work = info

        _confd.dp.register_usess_cb(ctx, UsessCb())
        _confd.dp.register_trans_cb(ctx, TransCb(s_work))
        _confd.dp.register_data_cb(ctx, 'interfaceCP',
                                   InterfaceProvider(keys, interfaces))
        _confd.dp.register_done(ctx)

        select_loop(ctx, s_ctrl, s_work, sys.stdin)


if __name__ == '__main__':
    main()
