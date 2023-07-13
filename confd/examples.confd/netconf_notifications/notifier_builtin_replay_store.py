"""
*********************************************************************
* NETCONF Notification Streams                                      *
* Python version.                                                   *
*                                                                   *
* (C) 2021 Tail-f Systems                                           *
* Permission to use this code as a starting point hereby granted    *
*                                                                   *
* See the README file for more information                          *
*********************************************************************
"""

from __future__ import print_function
import argparse
import logging
import socket
import select
import datetime
import sys
import textwrap

import notif_ns as ns
import _confd
import _confd.dp as dp

xmltag = _confd.XmlTag
value = _confd.Value
tagvalue = _confd.TagValue

log_level = logging.INFO
logging.basicConfig(
    format="%(asctime)s:%(relativeCreated)s"
           "%(levelname)s:%(filename)s:%(lineno)s:%(funcName)s  %(message)s",
    level=log_level)
log = logging.getLogger("confd_example_logger")

class NotifCallbacks(object):
    def cb_get_log_times(self, nctx):
        pass
    def cb_replay(self, nctx, start, stop):
        pass


def get_date_time():
    now = datetime.datetime.now()
    ConfdNow = _confd.DateTime(
        year=now.year,
        month=now.month,
        day=now.day,
        hour=now.hour,
        min=now.minute,
        sec=now.second,
        micro=now.microsecond,
        timezone=0,
        timezone_minutes=0)
    return ConfdNow


def send_notifup(livectx, index, flags1, flags2):
    Now = get_date_time()
    ret = [
        tagvalue(xmltag(ns.ns.hash,
                        ns.ns.notif_link_up),
                 value((ns.ns.notif_link_up, ns.ns.hash),
                       _confd.C_XMLBEGIN)
                 ),
        tagvalue(xmltag(ns.ns.hash,
                        ns.ns.notif_if_index),
                 value(index, _confd.C_UINT32)),
        tagvalue(xmltag(ns.ns.hash,
                        ns.ns.notif_link_property),
                 value((ns.ns.notif_link_property, ns.ns.hash),
                       _confd.C_XMLBEGIN)
                 ),
        tagvalue(xmltag(ns.ns.hash,
                        ns.ns.notif_flags),
                 value(flags1, _confd.C_UINT32)),
        tagvalue(xmltag(ns.ns.hash,
                        ns.ns.notif_link_property),
                 value((ns.ns.notif_link_property, ns.ns.hash),
                       _confd.C_XMLEND)
                 ),
        tagvalue(xmltag(ns.ns.hash,
                        ns.ns.notif_link_property),
                 value((ns.ns.notif_link_property, ns.ns.hash),
                       _confd.C_XMLBEGIN)
                 ),
        tagvalue(xmltag(ns.ns.hash,
                        ns.ns.notif_flags),
                 value(flags2, _confd.C_UINT32)),
        tagvalue(xmltag(ns.ns.hash,
                        ns.ns.notif_link_property),
                 value((ns.ns.notif_link_property, ns.ns.hash),
                       _confd.C_XMLEND)
                 ),
        tagvalue(xmltag(ns.ns.hash,
                        ns.ns.notif_link_up),
                 value((ns.ns.notif_link_up, ns.ns.hash),
                       _confd.C_XMLEND)
                 )
    ]
    dp.notification_send(livectx, Now, ret)
    log.debug("notif up sent")


def send_notifdown(livectx, index):
    Now = get_date_time()
    ret = [
        tagvalue(xmltag(ns.ns.hash,
                        ns.ns.notif_link_down),
                 value((ns.ns.notif_link_down, ns.ns.hash),
                       _confd.C_XMLBEGIN)
                 ),
        tagvalue(xmltag(ns.ns.hash,
                        ns.ns.notif_if_index),
                 value(index, _confd.C_UINT32)),
        tagvalue(xmltag(ns.ns.hash,
                        ns.ns.notif_link_down),
                 value((ns.ns.notif_link_down, ns.ns.hash),
                       _confd.C_XMLEND)
                 )
    ]
    dp.notification_send(livectx, Now, ret)
    log.debug("notif down sent")


def notif_loop():
    csocket = socket.socket()
    wsocket = socket.socket()
    ctx = dp.init_daemon("notifier")
    dp.connect(dx=ctx,
               sock=csocket,
               type=dp.CONTROL_SOCKET,
               ip='127.0.0.1',
               port=4565)
    dp.connect(dx=ctx,
               sock=wsocket,
               type=dp.WORKER_SOCKET,
               ip='127.0.0.1',
               port=4565)
    ncbs = NotifCallbacks()
    livectx = dp.register_notification_stream(ctx, ncbs, wsocket, 'interface')
    dp.register_done(ctx)
    log.debug("register_done called")

    _r = [csocket, sys.stdin]
    _w = []
    _e = []

    while (True):
        (r, w, e) = select.select(_r, _w, _e, 1)
        for rs in r:
            if rs.fileno() == csocket.fileno():
                try:
                    dp.fd_ready(ctx, csocket)
                except (_confd.error.Error) as e:
                    if e.confd_errno is _confd.ERR_EXTERNAL:
                        log.debug("csocket> " + str(e))
                    else:
                        raise e
            elif rs == sys.stdin:
                input = sys.stdin.readline().rstrip()
                if input == "exit":
                    log.debug("Bye!")
                    return False
                else:
                    if input == "u" or input == "up":
                        send_notifup(livectx, 1, 2112, 32)
                    elif input == "d" or input == "down":
                        send_notifdown(livectx, 1)

    wsocket.close()
    csocket.close()
    dp.release_daemon(ctx)

if __name__ == "__main__":
    debug_levels = {
        's': _confd.SILENT,
        'd': _confd.DEBUG,
        't': _confd.TRACE,
        'p': _confd.PROTO_TRACE,
    }
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
    args = parser.parse_args()
    confd_debug_level = debug_levels.get(args.debuglevel, _confd.TRACE)
    _confd.set_debug(confd_debug_level, sys.stderr)
    notif_loop()
