"""Resource Pool"""

import time
import threading
import traceback

try:
    from Queue import Queue
except ImportError:
    from queue import Queue


def _ensure_callable(obj, name):
    if not hasattr(obj, name):
        raise ValueError('callback {0} not set'.format(name))

    fun = getattr(obj, name)
    if not callable(fun):
        raise ValueError('callback {0} must be callable'.format(name))


class PoolConfig(object):
    """Size and time configuration for Pool."""
    __slots__ = ['min_size', 'max_size', 'idle_timeout_s']

    def __init__(self, min_size, max_size, idle_timeout_s):
        self.min_size = min_size
        self.max_size = max_size
        self.idle_timeout_s = idle_timeout_s


class PoolItemCb(object):
    def __init__(self, log):
        self.log = log

    def create_item(self):
        """Create new item."""
        raise NotImplementedError()

    def take_item(self, item):
        """Mark item as taken from the pool."""
        pass

    def return_item(self, item):
        """Mark item as available in the pool."""
        pass

    def delete_item(self, item):
        """Free resources used by item."""
        raise NotImplementedError()


class Pool(object):
    """Size restricted resource pool."""

    class _PoolItem(object):
        __slots__ = ['item', 'created', 'touched', 'deleted']

        def __init__(self, item):
            self.item = item
            self.created = time.time()
            self.touched = time.time()
            self.deleted = False

    def __init__(self, log, name, cfg, item_cb):
        for cb_name in ('create_item', 'delete_item',
                        'take_item', 'return_item'):
            _ensure_callable(item_cb, cb_name)

        self.log = log
        self._name = name
        self._cfg = cfg
        self._item_cb = item_cb
        self._stop = False

        self._items_busy = []
        self._items_idle = []
        self._items_cond = threading.Condition()

    def take_item(self):
        """Take, and if required create, item from pool.

        Takes idle item or creates new one if none exists. If max size
        is reached call will block until item is available OR pool is
        stopped.

        None return value indicates that the pool is stopped.
        """
        with self._items_cond:
            item = None
            while item is None and not self._stop:
                if len(self._items_idle) > 0:
                    item = self._items_idle.pop()
                    item.touched = time.time()
                elif (self._cfg.max_size < 1
                      or self._get_size_unlocked() < self._cfg.max_size):
                    cb_item = self._item_cb.create_item()
                    item = Pool._PoolItem(cb_item)
                else:
                    self._items_cond.wait()

            if item is None:
                return None

            self._items_busy.append(item)
            self._item_cb.take_item(item.item)
            return item.item

    def return_item(self, cb_item, is_failed=False):
        """Return item to pool.

        Set is_failed to True whenever a operation failed while using
        this item to ensure the item is not re-used.
        """
        with self._items_cond:
            item = self._find_item_unlocked(cb_item)
            self._items_busy.remove(item)

            # item already deleted in stop, no further processing
            # required.
            if not item.deleted:
                self._item_return(item)
                if self._stop or is_failed or not self._can_fit_items(1):
                    self._item_delete(item)
                else:
                    self._items_idle.append(item)

            self._items_cond.notify()

    def maintenance(self):
        """Resource maintenance, times out idle items."""
        num_timed_out = 0

        with self._items_cond:
            now = time.time()

            max_timeout = len(self._items_idle)
            if self._cfg.min_size > 0:
                max_timeout -= self._cfg.min_size
                if max_timeout < 1:
                    return

            items_idle = []
            for item in self._items_idle:
                time_since_touched = now - item.touched
                if (num_timed_out < max_timeout
                        and time_since_touched > self._cfg.idle_timeout_s):
                    self._item_delete(item)
                    num_timed_out += 1
                else:
                    items_idle.append(item)

            self._items_idle = items_idle
            self._items_cond.notify_all()

        return num_timed_out

    def stop(self):
        """Stop Pool, deletes all items and disallows enqueue of new items."""
        self.log.debug('Pool({0}) stopping...'.format(self._name))
        with self._items_cond:
            self._stop = True
            for item_idle in self._items_idle:
                self._item_delete(item_idle)
            self._items_idle = []

            for item_busy in self._items_busy:
                self._item_delete(item_busy)
            self._items_cond.notify_all()

            # wait for all items to be removed
            size = self._get_size_unlocked()
            while size > 0:
                self.log.debug(
                    'Pool({0}) waiting for {1} item(s) to complete...'.format(
                        self._name, size))
                self._items_cond.wait()
                size = self._get_size_unlocked()

        self.log.debug('Pool({0}) stopped'.format(self._name))

    def _get_size_unlocked(self):
        self.log.debug('Pool({0}) idle: {1} busy: {2}'.format(
            self._name, len(self._items_idle), len(self._items_busy)))
        return len(self._items_idle) + len(self._items_busy)

    def _can_fit_items(self, num_items):
        num_total = self._get_size_unlocked()
        return (self._cfg.max_size < 1
                or (num_total + num_items) <= self._cfg.max_size)

    def _find_item_unlocked(self, item):
        item = next((i for i in self._items_busy if i.item == item), None)
        if item is None:
            raise ValueError(
                'Pool({0}) does not contain item {1}'.format(self._name, item))
        return item

    def _item_return(self, item):
        try:
            self._item_cb.return_item(item.item)
        except Exception as ex:
            self.log.error('Pool({0}) return_item {1} failed: {2}'.format(
                self._name, item.item, ex.message))
            self.log.error(traceback.format_exc())

    def _item_delete(self, item):
        if not item.deleted:
            self._item_cb.delete_item(item.item)
        item.deleted = True


class ThreadPool(object):
    """Thread pool executing callables on associated data items."""

    class _WorkerThread(threading.Thread):
        def __init__(self, log, thread_id, dequeue_fun, item):
            super(ThreadPool._WorkerThread, self).__init__(name=str(thread_id))
            self.log = log
            self.item = item

            self._dequeue_fun = dequeue_fun
            self._queue = Queue()

        def enqueue(self, fun, name):
            if not callable(fun):
                raise ValueError('fun must be callable')
            self._queue.put((fun, name))

        def stop(self):
            self.log.debug(
                'ThreadPool._WorkerThread.stop (queue_size={}) {}'.format(
                    self._queue.qsize(), self))
            self._queue.put((None, None))

        def run(self):
            name = self.name
            self.log.debug('ThreadPool._WorkerThread started {}'.format(self))

            fun, fun_name = self._queue.get(True)
            while fun is not None:
                self.name = '{0}-{1}'.format(name, fun_name)
                self.log.debug('_WorkerThread running {}, item {}'.
                               format(self, name))
                try:
                    fun(self.item)
                    self.log.debug(
                        '_WorkerThread finished {}, item {}'.format(self, name))

                    self._dequeue_fun(self, failed=False)
                    fun, fun_name = self._queue.get(True)
                except Exception as ex:
                    self.log.error(
                        'failed {0}'.format(ex.message))
                    self.log.error(traceback.format_exc())
                    self._dequeue_fun(self, failed=True)
                    fun = None
                finally:
                    self.name = name

            self.log.debug('ThreadPool._WorkerThread finished {}'.format(self))

    class _WorkerThreadCb(object):
        def __init__(self, log, name, dequeue_fun, finished_queue, item_cb):
            self.log = log
            self._name = name
            self._dequeue_fun = dequeue_fun
            self._finished_queue = finished_queue
            self._item_cb = item_cb
            self._id = 0

        def create_item(self):
            item = self._item_cb.create_item()
            self._id += 1
            wthread = ThreadPool._WorkerThread(
                self.log, self._id, self._dequeue_fun, item)
            wthread.name = '{0}-{1}'.format(self._name, wthread.name)
            wthread.start()
            return wthread

        def take_item(self, wthread):
            self._item_cb.take_item(wthread.item)

        def return_item(self, wthread):
            self._item_cb.return_item(wthread.item)

        def delete_item(self, wthread):
            # signal thread to stop and delay deletion of thread data
            # until thread has finished.
            wthread.stop()
            self._finished_queue.put(wthread, True)

    def __init__(self, log, name, cfg, item_cb):
        self.log = log
        self.name = name
        self._item_cb = item_cb
        self._finished_queue = Queue()
        self._stop_event = threading.Event()

        wthread_item_cb = ThreadPool._WorkerThreadCb(
            log, name, self._dequeue, self._finished_queue, item_cb)
        self._pool = Pool(log, name, cfg, wthread_item_cb)

    def enqueue(self, fun, name):
        """Enqueue fun to execute in pool"""
        thread = self._pool.take_item()
        if thread is not None:
            thread.enqueue(fun, name)
        return thread

    def start(self):
        """Start ThreadPool"""
        maintenance_name = '{0} maintenance'.format(self.name)
        self._maintenance_thread = threading.Thread(
            target=self._maintenance_main, name=maintenance_name)
        self._maintenance_thread.start()

        join_name = '{0} join'.format(self.name)
        self._join_thread = threading.Thread(
            target=self._join_main, name=join_name)
        self._join_thread.start()

    def stop(self):
        """Stop ThreadPool and all worker threads"""
        self._pool.stop()

        self._stop_event.set()
        self._finished_queue.put(None, True)
        self._maintenance_thread.join()
        self._join_thread.join()

    def _dequeue(self, wthread, failed):
        self._pool.return_item(wthread, failed)

    def _maintenance_main(self):
        self.log.debug('ThreadPool._maintenance_main started {}'.format(self))
        while not self._stop_event.is_set():
            idle_time = max(1, self._cfg.idle_timeout_s)
            self._pool.maintenance()
            self._stop_event.wait(idle_time)
        self.log.debug('ThreadPool._maintenance_main finished {}'.format(self))

    def _join_main(self):
        self.log.debug('ThreadPool._join_main started {}'.format(self))
        wthread = self._finished_queue.get(True)
        while wthread is not None:
            self.log.debug('ThreadPool joining thread {0}'.format(wthread))
            wthread.join()
            self.log.debug('ThreadPool joined thread {0}'.format(wthread))

            self.log.debug('ThreadPool deleting thread {0} item {1}'.format(
                wthread, wthread.item))
            self._item_cb.delete_item(wthread.item)
            self.log.debug('ThreadPool deleted thread {0} item {1}'.format(
                wthread, wthread.item))
            wthread = self._finished_queue.get(True)
        self.log.debug('ThreadPool._join_main finished {}'.format(self))


if __name__ == '__main__':
    import unittest

    class ItemCb(object):
        def __init__(self):
            self._id = 0

        def create_item(self):
            self._id += 1
            print('create_item {0}'.format(self._id))
            return self._id

        def take_item(self, item):
            print('take_item {0}'.format(item))

        def return_item(self, item):
            print('return_item {0}'.format(item))

        def delete_item(self, item):
            print('delete_item {0}'.format(item))

    class TestPool(unittest.TestCase):
        def test_return_max_size(self):
            cfg = PoolConfig(0, 3, 0)
            pool = Pool(None, 'test', cfg, ItemCb())

            # fill pool busy with 3 items
            item_1 = pool.take_item()
            self.assertEqual(item_1, 1)
            item_2 = pool.take_item()
            self.assertEqual(item_2, 2)
            item_3 = pool.take_item()
            self.assertEqual(item_3, 3)

            # reduce size to 1, removing all but the last element
            cfg.max_size = 1
            pool.return_item(item_1)
            pool.return_item(item_2)
            pool.return_item(item_3)

            # increase max and take from idle and create new element
            cfg.max_size = 3
            item_3 = pool.take_item()
            self.assertEqual(item_3, 3)
            item_4 = pool.take_item()
            self.assertEqual(item_4, 4)

        def test_take_max_size(self):
            cfg = PoolConfig(0, 1, 0)
            pool = Pool(None, 'test', cfg, ItemCb())

            item_id = pool.take_item()
            self.assertEqual(item_id, 1)

            # item_id = pool.take_item()
            # self.assertEqual(item_id, 2)

    unittest.main()
