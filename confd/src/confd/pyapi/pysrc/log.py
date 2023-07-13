"""This module provides some logging utilities."""
import logging
import os
import time
import unittest


_log_file_name = None
_log_file = None
_log_handler = None


def log_format():
    """Return log format."""
    return '<%(levelname)s> %(asctime)s.%(msecs)d %(name)s ' \
        '%(threadName)s: - %(message)s'


def log_datefmt():
    """Return date format used in logging."""
    return '%d-%b-%Y::%H:%M:%S'


def mk_log_formatter():
    """Create log formatter with log and date format setup"""
    return logging.Formatter(log_format(), log_datefmt())


def log_file():
    """Return log file used, if any else None"""
    global _log_file
    return _log_file


def log_handler():
    """Return log handler used, if any else None"""
    global _log_handler
    return _log_handler


def init_logging(vmid, log_file, log_level):
    """Initialize logging"""
    global _log_file_name, _log_file, _log_handler

    _log_file_name = '{0}-{1}.log'.format(log_file, vmid)
    _log_file = open(_log_file_name, 'a')
    _log_handler = logging.StreamHandler(_log_file)
    _log_handler.setFormatter(mk_log_formatter())

    logging.root.addHandler(_log_handler)
    logging.root.setLevel(log_level)


def reopen_logs():
    """Re-open log files if log handler is set"""
    global _log_file
    global _log_handler
    if _log_handler is None:
        return False

    # For future updates, since Python 3.7 StreamHandler has setStream
    # that takes care of flushing
    _log_handler.acquire()
    _log_handler.flush()
    _log_file.close()
    _log_file = open(_log_file_name, 'a')
    _log_handler.stream = _log_file
    _log_handler.release()

    return True


def set_log_level(vmid, log_level):
    """Set log level on the vmid logger and root logger"""
    logging.getLogger(vmid).setLevel(log_level)
    logging.root.setLevel(log_level)


def _timestamp():
    return time.strftime('%d-%b-%Y::%H:%M:%S.000 - ', time.localtime())


def _no_timestamp():
    return ''


def _join_args(*args):
    return ''.join(str(x) for x in args)


class Log(object):
    """A log helper class.

    This class makes it easier to write log entries. It encapsulates
    another log object that supports Python standard log interface, and
    makes it easier to format the log message be adding the ability to
    support multiple arguments.

    Example use:

        import logging
        import confd.log

        logger = logging.getLogger(__name__)
        mylog = confd.log.Log(logger)

        count = 3
        name = 'foo'
        mylog.debug('got ', count, ' values from ', name)
    """

    def __init__(self, logobject, add_timestamp=False):
        """Initialize a Log object.

        The argument 'logobject' is mandatory and can be any object which
        should support as least one of the standard log methods (info, warning,
        error, critical, debug). If 'add_timestamp' is set to True a time stamp
        will precede your log message.
        """
        if add_timestamp:
            self._add_timestamp = _timestamp
        else:
            self._add_timestamp = _no_timestamp

        self._info = getattr(logobject, 'info', None)
        self._warn = getattr(logobject, 'warning', None)
        self._err = getattr(logobject, 'error', None)
        self._crit = getattr(logobject, 'critical', None)
        self._dbg = getattr(logobject, 'debug', None)

    def info(self, *args):
        """Log an information message."""
        return self._do_log(self._info, _join_args(*args))

    def warning(self, *args):
        """Log a warning message."""
        return self._do_log(self._warn, _join_args(*args))

    def error(self, *args):
        """Log an error message."""
        return self._do_log(self._err, _join_args(*args))

    def critical(self, *args):
        """Log a critical message."""
        return self._do_log(self._crit, _join_args(*args))

    def fatal(self, *args):
        """Just calls critical()."""
        return self.critical(*args)

    def debug(self, *args):
        """Log a debug message."""
        return self._do_log(self._dbg, _join_args(*args))

    def _do_log(self, logfn, msg):
        if logfn is None:
            return None
        return logfn(self._add_timestamp() + msg)


class ParentProcessLogHandler(logging.StreamHandler):
    def __init__(self, log_q):
        super(ParentProcessLogHandler, self).__init__()
        self._log_q = log_q
        self._pid = os.getpid()

    def emit(self, record):
        """Emit log record by sending a pre-formatted record to the parent
        process"""
        raw_msg = self.format(record)
        self._log_q.put((self._pid, ('raw_log', raw_msg + self.terminator)))


#
# UNIT TESTS
#
class _Test(unittest.TestCase):

    class MyLog(object):
        def info(self, msg):
            return 'INFO: ' + msg

        def warning(self, msg):
            return 'WARNING: ' + msg

        def error(self, msg):
            return 'ERROR: ' + msg

        def critical(self, msg):
            return 'CRITICAL: ' + msg

        def debug(self, msg):
            return 'DEBUG: ' + msg

    def test__timestamp(self):
        import re
        ts = _timestamp()
        res = re.match(
            '^[0-3][0-9]-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-'
            '20[1-9][0-9]::[0-2][0-9]:[0-5][0-9]:[0-5][0-9].000 - $', ts)
        self.assertNotEqual(res, None)

    def test__no_timestamp(self):
        self.assertEqual('', _no_timestamp())

    def test__join_args(self):
        self.assertEqual('', _join_args())
        self.assertEqual('foobar1', _join_args('foo', 'bar', 1))
        self.assertEqual('()[]', _join_args((), []))
        self.assertEqual('(1, 2)[3, 4]', _join_args((1, 2), [3, 4]))

    def test_log_init_none(self):
        log = Log(None)
        self.assertEqual(log._info, None)
        self.assertEqual(log._warn, None)
        self.assertEqual(log._err, None)
        self.assertEqual(log._crit, None)
        self.assertEqual(log._dbg, None)
        self.assertEqual(log._add_timestamp, _no_timestamp)
        log = Log(None, add_timestamp=True)
        self.assertEqual(log._add_timestamp, _timestamp)

    def test_log_init_something(self):
        mylog = _Test.MyLog()
        log = Log(mylog)
        self.assertEqual(log._info, mylog.info)
        self.assertEqual(log._warn, mylog.warning)
        self.assertEqual(log._err, mylog.error)
        self.assertEqual(log._crit, mylog.critical)
        self.assertEqual(log._dbg, mylog.debug)

    def test_log_all(self):
        mylog = _Test.MyLog()
        log = Log(mylog)
        self.assertEqual('INFO: 1+2=3', log.info(1, '+', 2, '=', 3))
        self.assertEqual('WARNING: 1+2=3', log.warning(1, '+', 2, '=', 3))
        self.assertEqual('ERROR: 1+2=3', log.error(1, '+', 2, '=', 3))
        self.assertEqual('CRITICAL: 1+2=3', log.critical(1, '+', 2, '=', 3))
        self.assertEqual('CRITICAL: 1+2=3', log.fatal(1, '+', 2, '=', 3))
        self.assertEqual('DEBUG: 1+2=3', log.debug(1, '+', 2, '=', 3))


if __name__ == '__main__':
    unittest.main()
