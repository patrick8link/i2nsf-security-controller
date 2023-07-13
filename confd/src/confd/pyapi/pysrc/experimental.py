"""Experimental stuff.

This module contains experimental and totally unsupported things that
may change or disappear at any time in the future. If used, it must be
explicitly imported.
"""
import traceback

try:
    long
except NameError:
    long = int

from . import maagic
from . import tm

_tm = __import__(tm.TM)


def _have_callable(obj, name):
    return hasattr(obj, name) and callable(getattr(obj, name))


def _is_tag(node, tag):
    return _have_callable(node, 'tag') and node.tag() == tag


def _to_tm_value(value, node):
    try:
        return maagic._python_to_yang(value, node)
    except Exception as e:
        obj_name = _tm.hash2str(node.tag())
        if node.parent() is not None:
            obj_name = '%s.%s' % (
                _tm.hash2str(node.parent().tag()), obj_name)
        raise Exception('failed to convert %s = %s to Value due to %s' % (
            obj_name, value, str(e)), e)


def _find_nested_obj(kp, idx, obj):
    # no object to match agains or full kp was consumed
    if obj is None or idx < 0:
        return obj

    while idx >= 0 and obj is not None:
        name = _tm.hash2str(kp[idx].tag)
        if name not in obj:
            return None
        idx -= 1

        obj = obj[name]
        if idx >= 0 and isinstance(kp[idx], tuple):
            obj = _find_list_entry(kp, idx, obj)
            idx -= 1

    return obj


def _find_list_entry(kp, idx, lst):
    node = _tm.find_cs_node(kp, len(kp) - idx)
    keys = [_tm.hash2str(t) for t in node.info().keys()]
    for obj in lst:
        for i in range(len(keys)):
            key = keys[i]
            if key not in obj or obj[key] != kp[idx][i].as_pyval():
                continue
            return obj
    return None


def _obj_to_key(kp, obj):
    node = _find_node(kp)
    if node is None:
        raise Exception('no node found for %s' % (str(kp), ))

    if node.is_leaf_list():
        key = _encode_leaf_list(node, obj, -1)
    else:
        key = []
        for tag in node.info().keys():
            value = _to_value(obj, node, tag)
            key.append(value)

    return key


def _to_value(obj, node, tag):
    name = _tm.hash2str(tag)
    if name not in obj or obj[name] is None:
        return _tm.Value(_tm.C_NOEXISTS)

    if node.tag() != tag:
        node = _find_child_node(node, tag)
        if node is None:
            raise Exception('unable to find node for tag %d' % (tag, ))

    return _to_tm_value(obj[name], node)


def _to_value_array(obj, node):
    values = []

    while node is not None:
        value = None

        name = _tm.hash2str(node.tag())
        if name in obj and obj[name] is not None:
            if node.is_leaf():
                value = _to_tm_value(obj[name], node)
                tag_value = _tm.TagValue(
                    _tm.XmlTag(node.ns(), node.tag()), value)
                values.append(tag_value)
            elif node.is_container() and isinstance(obj[name], dict):
                values.append(_create_value(node, _tm.C_XMLBEGIN))
                container_values = _to_value_array(obj[name], node.children())
                values.extend(container_values)
                values.append(_create_value(node, _tm.C_XMLEND))

        node = node.next()

    return values


def _to_value_arrays(lst, children, next):
    values = []

    for idx in range(next, len(lst)):
        obj = lst[idx]

        if obj is None:
            values.append((None, long(idx + 1)))
            break

        obj_values = _to_value_array(obj, children)
        values.append((obj_values, long(idx + 1)))

    return values


def _to_case_array(node, obj, case_entries):
    case_node, entries = case_entries
    # TODO: implement support for case in case
    return _tm.Value((case_node.tag(), case_node.ns()), _tm.C_XMLTAG)


def _find_node(kp):
    root = kp[len(kp)-1]
    node = _find_next_node(_tm.find_cs_root(root.ns), root.tag)
    if node is None:
        return None

    for idx in range(len(kp) - 2, -1, -1):
        if isinstance(kp[idx], tuple):
            continue

        node = _find_child_node(node, kp[idx].tag)
        if node is None:
            return None

    return node


def _find_next_node(node, tag):
    while node is not None:
        if _is_tag(node, tag):
            return node
        node = node.next()
    return None


def _find_child_node(node, tag):
    child = node.children()
    while child is not None:
        if _is_tag(child, tag):
            return child
        child = child.next()
    return None


def _create_value(node, type):
    return _tm.TagValue(
        _tm.XmlTag(node.ns(), node.tag()),
        _tm.Value((node.ns(), node.tag()), type))


def _get_cases(node):
    cases = []

    choice = node.info().choices()
    case = choice.cases()
    while case is not None:
        entries = []
        entry = case.first()
        while entry is not None:
            entries.append(_tm.hash2str(entry.tag()))
            if entry.tag() == case.last().tag():
                break
            entry = entry.next()
        cases.append((case, entries))

        case = case.next()

    return cases


class Query:
    """Class encapsulating a MAAPI query operation.

    Supports the pattern of executing a query and iterating over the result
    sets as they are requested. The class handles the calls to query_start,
    query_result and query_stop, which means that one can focus on describing
    the query and handle the result.

    Example query:

        with Query(trans, 'device', '/devices', ['name', 'address', 'port'],
                   result_as=ncs.QUERY_TAG_VALUE) as q:
            for r in q:
                print(r)
    """

    def __init__(self, trans, expr, context_node, select, chunk_size=1000,
                 initial_offset=1, result_as=_tm.QUERY_TAG_VALUE, sort=[]):
        """Initialize a Query."""
        self.trans = trans
        self.qh = self.trans.query_start(expr, context_node,
                                         chunk_size, initial_offset, result_as,
                                         select, sort)
        self.total = self.trans.maapi.query_result_count(self.qh)
        self.result = None
        self.count = 0

    def __enter__(self):
        """Python magic method."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Python magic method."""
        self.stop()

    def __iter__(self):
        """Return a query result iterator."""
        return self

    def __next__(self):
        """Return next object."""
        return self.next()

    def next(self):
        """Get the next query result row."""
        if self.result is None or self.offset >= self.result.nresults:
            if self.count >= self.total:
                raise StopIteration
            self.result = self.trans.maapi.query_result(self.qh)
            if self.result.nresults == 0:
                raise StopIteration
            self.offset = 0
        current_offset = self.offset
        self.offset += 1
        self.count += 1
        return self.result[current_offset]

    def stop(self):
        """Stop the running query.

        Any resources associated with the query will be released.
        """
        return self.trans.maapi.query_stop(self.qh)


class DataCallbacks(object):
    """High-level API for implementing data callbacks.

    Higher level abstraction for the DP API. Currently supports read
    operations only, as such it is suitable for config false; data.

    Registered callbacks are searched for in registration order. Most
    specific points must be registered first.

    args parameter to handler callbacks is a dictionary with keys
    matching list names in the keypath. If multiple lists with the
    same name exists the keys are named list-0, list-1 etc where 0 is
    the top-most list with name list. Values in the dictionary are
    python types (.as_pyval()), if the list has multiple keys it is
    set as a list else the single key value is set.

    Example args for keypath
    /root/single-key-list{name}/conflict{first}/conflict{second}/multi{1 one}

        {'single-key-list': 'name',
         'conflict-0': 'first',
         'conflict-1': 'second',
         'multi': [1, 'one']}

    Example handler and registration:

        class Handler(object):
            def get_object(self, tctx, kp, args):
                return {'leaf1': 'value', 'leaf2': 'value'}

            def get_next(self, tctx, kp, args, next):
                return None

            def count(self):
                return 0

        dcb = DataCallbacks(log)
        dcb.register('/namespace:container', Handler())
        _confd.dp.register_data_cb(dd.ctx(), example_ns.callpoint_handler, dcb)

    """
    class Pattern(object):
        """Pattern matching key-path, internal to DataCallbacks"""

        def __init__(self, path):
            self._tags = self.parse(path)

        def match(self, kp):
            # pattern is longer than kp, ignore
            num_kp = sum([1 for k in kp if not isinstance(k, tuple)])
            if len(self._tags) > num_kp:
                return -1, False

            args = {}
            args_num = {}

            idx = len(kp) - 1
            for ns, tag in self._tags:
                if idx < 0 or ns != kp[idx].ns or tag != kp[idx].tag:
                    return idx, False

                idx -= 1
                if idx >= 0 and isinstance(kp[idx], tuple):
                    values = [v.as_pyval() for v in kp[idx]]
                    if len(values) == 1:
                        values = values[0]

                    name = _tm.hash2str(tag)
                    if name in args_num:
                        # conflicting name, -0 etc
                        if args_num[name] == 1:
                            args['%s-0' % (name, )] = args[name]
                            del args[name]
                        args['%s-%d' % (name, args_num[name])] = values
                        args_num[name] += 1
                    else:
                        args[name] = values
                        args_num[name] = 1

                    idx -= 1

            return idx, args

        def parse(self, path):
            ns_lookup = dict([(ns[1], ns[0]) for ns in _tm.get_nslist()])

            tags = []
            for part in path[1:].split('/'):
                try:
                    ns, name = part.split(':', 1)
                except ValueError:
                    raise Exception(
                        'path element %s must take form namespace:name' % (
                            part, ))

                if ns not in ns_lookup:
                    raise Exception(
                        'path element %s namespace %s unknown' % (part, ns))

                ns_tag = ns_lookup[ns]
                name_tag = _tm.str2hash(name)
                if name_tag == 0:
                    raise Exception(
                        'path element %s name %s unknown' % (part, name))

                tags.append((ns_tag, name_tag))
            return tags

    class RegisterPoint(object):
        """Registered handler point, internal to DataCallbacks"""

        __slots__ = ['path', 'pattern', 'handler']

        def __init__(self, path, pattern, handler):
            self.path = path
            self.pattern = pattern
            self.handler = handler

    def __init__(self, log):
        self._log = log
        self._points = []

    def register(self, path, handler):
        """Register data handler for path.

        If handler is a type it will be instantiated with the DataCallbacks
        log as the only parameter.

        The following methods will be called on the handler:

        * get_object(kp, args)

            Return single object as dictionary.

        * get_next(kp, args, next)

            Return next object as dictionary, list of dictionaries can be
            returned to use result caching reducing the amount of calls
            required.

        * count(kp, args)

            Return number of elements in list.
        """
        if type(handler) == type:
            handler = handler(self._log)

        missing = []
        for name in ('get_object', 'find_next', 'count'):
            if not _have_callable(handler, 'get_object'):
                missing.append(name)

        if len(missing) > 0:
            raise Exception('missing required method(s) %s' % (
                ','.join(missing), ))

        if self._find_handler_from_path(path) is not None:
            raise Exception('handler already registered for %s' % (path, ))

        pattern = DataCallbacks.Pattern(path)
        point = DataCallbacks.RegisterPoint(path, pattern, handler)
        self._points.append(point)

    def cb_num_instances(self, tctx, kp):
        """low-level cb_num_instances implementation"""
        self._log.debug('cb_num_instances %s' % (str(kp), ))

        num = 0
        try:
            idx, handler, args = self._find_handler_from_kp(kp)
            if handler is not None:
                if idx >= 0:
                    obj = _find_nested_obj(
                        kp, idx, handler.get_object(tctx, kp, args))
                    if obj is not None:
                        num = len(obj)
                else:
                    num = handler.count(tctx, kp, args)
        except Exception as e:
            self._log.error(e)
            self._log.error(traceback.format_exc())
            raise

        _tm.dp.data_reply_value(tctx, _tm.Value(num, _tm.C_INT32))
        return _tm.CONFD_OK

    def cb_exists_optional(self, tctx, kp):
        """low-level cb_exists_optional implementation"""
        self._log.debug('cb_exists_optional %s' % (str(kp), ))

        try:
            idx, handler, args = self._find_handler_from_kp(kp)
            if handler is None:
                _tm.dp.data_reply_not_found(tctx)
            else:
                obj = _find_nested_obj(
                    kp, idx, handler.get_object(tctx, kp, args))
                if obj in (None, False):
                    _tm.dp.data_reply_not_found(tctx)
                else:
                    _tm.dp.data_reply_found(tctx)

        except Exception as e:
            self._log.error(e)
            self._log.error(traceback.format_exc())
            raise

        return _tm.CONFD_OK

    def cb_get_elem(self, tctx, kp):
        """low-level cb_elem implementation"""
        self._log.debug('cb_get_elem %s' % (str(kp), ))

        try:
            idx, handler, args = self._find_handler_from_kp(kp)
            if handler is None:
                _tm.dp.data_reply_not_found(tctx)
            else:
                obj = _find_nested_obj(
                    kp, idx, handler.get_object(tctx, kp, args))
                if obj is None:
                    _tm.dp.data_reply_not_found(tctx)
                else:
                    node = _find_node(kp)
                    value = _to_tm_value(obj, node)
                    _tm.dp.data_reply_value(tctx, value)

        except Exception as e:
            self._log.error(e)
            self._log.error(traceback.format_exc())
            raise

        return _tm.CONFD_OK

    def cb_get_next(self, tctx, kp, next):
        """low-level cb_get_next implementation"""
        self._log.debug('cb_get_next %s %s' % (str(kp), str(next)))

        if next == -1:
            next = 0

        try:
            idx, handler, args = self._find_handler_from_kp(kp)
            if handler is None:
                _tm.dp.data_reply_next_key(tctx, None, 0)
            else:
                if idx >= 0:
                    obj = _find_nested_obj(
                        kp, idx, handler.get_object(tctx, kp, args))
                    if obj is None or next >= len(obj):
                        obj = None
                    else:
                        obj = obj[next]
                else:
                    obj = handler.get_next(tctx, kp, args, next)

                if obj is None:
                    _tm.dp.data_reply_next_key(tctx, None, 0)
                else:
                    if isinstance(obj, (list, tuple)):
                        obj = obj[0]

                    key = _obj_to_key(kp, obj)
                    _tm.dp.data_reply_next_key(tctx, key, next + 1)

        except Exception as e:
            self._log.error(e)
            self._log.error(traceback.format_exc())
            raise

        return _tm.CONFD_OK

    def cb_get_object(self, tctx, kp):
        """low-level cb_get_object implementation"""
        self._log.debug('cb_get_object %s' % (str(kp), ))

        try:
            idx, handler, args = self._find_handler_from_kp(kp)
            if handler is None:
                _tm.dp.data_reply_not_found(tctx)
            else:
                obj = _find_nested_obj(
                    kp, idx, handler.get_object(tctx, kp, args))
                if obj is None:
                    _tm.dp.data_reply_not_found(tctx)
                else:
                    node = _find_node(kp)
                    values = _to_value_array(obj, node.children())
                    _tm.dp.data_reply_tag_value_array(tctx, values)

        except Exception as e:
            self._log.error(e)
            self._log.error(traceback.format_exc())
            raise

        return _tm.CONFD_OK

    def cb_get_next_object(self, tctx, kp, next):
        """low-level cb_get_next_object implementation"""
        self._log.debug('cb_get_next_object %s %s' % (str(kp), str(next)))

        if next == -1:
            next = 0

        try:
            idx, handler, args = self._find_handler_from_kp(kp)
            if handler is None:
                _tm.dp.data_reply_next_object_tag_value_array(tctx, None, 0)
            else:
                if idx >= 0:
                    obj = _find_nested_obj(
                        kp, idx, handler.get_object(tctx, kp, args))
                else:
                    obj = handler.get_next(tctx, kp, args, next)

                if (obj is None or
                        (isinstance(obj, (tuple, list)) and next >= len(obj))):
                    _tm.dp.data_reply_next_object_tag_value_array(
                        tctx, None, 0)
                else:
                    node = _find_node(kp)
                    if node.is_leaf_list():
                        self._reply_get_next_object_leaf_list(
                            tctx, node, obj, next)
                    else:
                        self._reply_get_next_object(
                            tctx, node, obj, next)

        except Exception as e:
            self._log.error(e)
            self._log.error(traceback.format_exc())
            raise

        return _tm.CONFD_OK

    def cb_get_case(self, tctx, kp, choice):
        """low-level cb_get_case implementation"""
        self._log.debug('cb_get_case %s' % (str(kp), ))

        try:
            idx, handler, args = self._find_handler_from_kp(kp)
            if handler is None:
                _tm.dp.data_reply_not_found(tctx)
            else:
                if idx >= 0:
                    obj = _find_nested_obj(
                        kp, idx, handler.get_object(tctx, kp, args))
                else:
                    obj = handler.get_object(tctx, kp, args)

                if obj is None:
                    _tm.dp.data_reply_not_found(tctx)
                else:
                    node = _find_node(kp)
                    cases = _get_cases(node)
                    selected_cases = [c for c in cases
                                      if any((e in obj and obj[e] is not None
                                              for e in c[1]))]
                    if len(selected_cases) == 0:
                        _tm.dp.data_reply_not_found(tctx)
                    elif len(selected_cases) == 1:
                        values = _to_case_array(node, obj, selected_cases[0])
                        _tm.dp.data_reply_value(tctx, values)
                    else:
                        raise Exception(
                            'no more than one case allowed at %s' % (str(kp), ))
        except Exception as e:
            self._log.error(e)
            self._log.error(traceback.format_exc())
            raise

        return _tm.CONFD_OK

    def _reply_get_next_object(self, tctx, node, obj, next):
        children = node.children()
        if isinstance(obj, (list, tuple)):
            values = _to_value_arrays(obj, children, next)
            if len(values) == 0:
                _tm.dp.data_reply_next_object_tag_value_array(
                    tctx, None, 0)
            else:
                _tm.dp.data_reply_next_object_tag_value_arrays(
                    tctx, values, next + len(values))
        else:
            values = _to_value_array(obj, children)
            _tm.dp.data_reply_next_object_tag_value_array(
                tctx, values, next + 1)

    def _reply_get_next_object_leaf_list(self, tctx, node, obj, next):
        values = _encode_leaf_list(node, obj, next)
        if len(values) == 0:
            _tm.dp.data_reply_next_object_tag_value_array(
                tctx, None, 0)
        elif len(values) == 1:
            _tm.dp.data_reply_next_object_array(
                tctx, values, next + 1)
        else:
            _tm.dp.data_reply_next_object_arrays(
                tctx, values, next + len(values))

    def _find_handler_from_kp(self, kp):
        for rp in self._points:
            idx, args = rp.pattern.match(kp)
            if args is not False:
                return idx, rp.handler, args
        return -1, None, None

    def _find_handler_from_path(self, path):
        for rp in self._points:
            if rp.path == path:
                return rp.handler
        return None


def _encode_leaf_list(node, value, next):
    cs_type = _tm.get_leaf_list_type(node)
    if isinstance(value, (tuple, list)):
        return _encode_leaf_list_values(cs_type, value, next)
    else:
        return _encode_leaf_list_value(cs_type, value)


def _encode_leaf_list_values(cs_type, values, next):
    next = long(next)
    tm_values = []
    for value in values:
        next += 1
        tm_values.append((_encode_leaf_list_value(cs_type, value), next))
    return tm_values


def _encode_leaf_list_value(cs_type, value):
    if isinstance(value, _tm.Value):
        tm_value = value
    else:
        value_s = str(value)
        if isinstance(value, bool):
            value_s = value_s.lower()
        tm_value = _tm.Value.str2val(value_s, cs_type)
    return [tm_value]
