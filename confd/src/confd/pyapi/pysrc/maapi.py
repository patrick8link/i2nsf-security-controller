"""
MAAPI high level module.

This module defines a high level interface to the low-level maapi functions.

The 'Maapi' class encapsulates a MAAPI connection which upon constructing,
sets up a connection towards ConfD/NCS. An example of setting up a transaction
and manipulating data:

    import ncs

    m = ncs.maapi.Maapi()
    m.start_user_session('admin', 'test_context')
    t = m.start_write_trans()
    t.get_elem('/model/data{one}/str')
    t.set_elem('testing', '/model/data{one}/str')
    t.apply()

Another way is to use context managers, which will handle all cleanup
related to transactions, user sessions and socket connections:

    with ncs.maapi.Maapi() as m:
        with ncs.maapi.Session(m, 'admin', 'test_context'):
            with m.start_write_trans() as t:
                t.get_elem('/model/data{one}/str')
                t.set_elem('testing', '/model/data{one}/str')
                t.apply()

Finally, a really compact way of doing this:

    with ncs.maapi.single_write_trans('admin', 'test_context') as t:
        t.get_elem('/model/data{one}/str')
        t.set_elem('testing', '/model/data{one}/str')
        t.apply()
"""
import contextlib
import enum
import functools
import socket
import sys
import threading
import traceback
from io import StringIO
from . import maagic
from . import tm

_tm = __import__(tm.TM)

# constants
LOAD_SCHEMAS_LOAD = True
LOAD_SCHEMAS_SKIP = False
LOAD_SCHEMAS_RELOAD = 2

# Python files part of our library that may call
# Maapi.start_user_session() or Maapi.start_trans().
_client_id_skip_files = [
    '/application.py',
    '/experimental.py',
    '/dp.py',
    '/maagic.py',
    '/maapi.py'
]


def _sanitize_docstring(help_text, remove_args):
    """Internal function.

    Used to sanitize help text of low-level _ncs.maapi APIs to be used in
    high-level ncs.maapi APIs
    """
    import re
    s_help = help_text
    for arg in remove_args:
        # sanitize keyword arguments text
        s_help = re.sub("".join([".*\* ", arg, ".*\n?"]), "", s_help)
    # sanitize method arguments
    s_help = re.sub(", ".join(remove_args), "self", s_help)
    if s_help.count("* ") == 0:
        return s_help.split("Keyword arguments")[0]
    return s_help


def _mk_client_id():
    """Internal function.

    Make a useful client_id for passing into Maapi.start_user_session()
    and Maapi.start_trans().
    """
    stack = traceback.extract_stack()
    for item in reversed(stack):
        filename = item.filename
        lineno = item.lineno
        _fname = '/' + filename.split('/')[-1]

        if _fname not in _client_id_skip_files:
            if not filename.startswith(sys.prefix):
                return '%s:%d' % (filename, lineno)


def connect(ip=_tm.ADDR, port=_tm.PORT, path=None):
    """
    Convenience function for connecting to ConfD/NCS.

    The 'ip' and 'port' arguments are ignored if path is specified.

    Arguments:

    * ip -- ConfD/NCS instance ip address (str)
    * port -- ConfD/NCS instance port (int)
    * path -- ConfD/NCS instance location path (str)

    Returns:

    * socket (Python socket)
    """
    msock = socket.socket()
    if path is None:
        _tm.maapi.connect(msock, ip, port)
    else:
        _tm.maapi.connect(msock, path=path)
    return msock


def retry_on_conflict(retries=10, log=None):
    """Function/method decorator to retry a transaction in case of conflicts.

    When executing multiple concurrent transactions against the NCS RUNNING
    datastore, read-write conflicts are resolved by rejecting transactions
    having potentially stale data with ERR_TRANSACTION_CONFLICT.

    This decorator restarts a function, should it run into a conflict, giving
    it multiple attempts to apply. The decorated function must start its own
    transaction because a conflicting transaction must be thrown away entirely
    and a new one started.

    Example usage:

        @retry_on_conflict()
        def do_work():
            with ncs.maapi.single_write_trans('admin', 'python') as t:
                root = ncs.maagic.get_root(t)
                root.some_value = str(root.some_other_value)
                t.apply()

    Arguments:

    * retries -- number of times to retry (int)
    * log -- optional log object for logging conflict details
    """
    def decorate(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            retries_left = retries
            while True:
                try:
                   return f(*args, **kwargs)
                except _tm.error.Error as ex:
                    conflict = ex.confd_errno == _tm.ERR_TRANSACTION_CONFLICT
                    if not conflict or retries_left <= 0:
                        raise
                    if log is not None:
                        log.debug(str(ex))
                        log.warning('Transaction conflict, will retry' +
                                    ' {} more times'.format(retries_left))
                    retries_left -= 1
        return wrapper
    return decorate


@contextlib.contextmanager
def single_read_trans(user, context, groups=[],
                      db=_tm.RUNNING, ip=_tm.ADDR,
                      port=_tm.PORT, path=None, src_ip=_tm.ADDR,
                      src_port=0, proto=_tm.PROTO_TCP, vendor=None,
                      product=None, version=None, client_id=None,
                      load_schemas=LOAD_SCHEMAS_LOAD):
    """Context manager for a single READ transaction.

    This function connects to ConfD/NCS, starts a user session and finally
    starts a new READ transaction.

    Function signature:

        def single_read_trans(user, context, groups=[],
                              db=RUNNING, ip=<CONFD-OR-NCS-ADDR>,
                              port=<CONFD-OR-NCS-PORT>, path=None,
                              src_ip=<CONFD-OR-NCS-ADDR>, src_port=0,
                              proto=PROTO_TCP,
                              vendor=None, product=None, version=None,
                              client_id=_mk_client_id(),
                              load_schemas=LOAD_SCHEMAS_LOAD):

    For argument db see Maapi.start_trans(). For arguments user,
    context, groups, src_ip, src_port, proto, vendor, product, version and
    client_id see Maapi.start_user_session().
    For arguments ip, port and path see connect().
    For argument load_schemas see __init__().

    Arguments:

    * user - username (str)
    * context - context for the session (str)
    * groups - groups (list)
    * db -- database (int)
    * ip -- ConfD/NCS instance ip address (str)
    * port -- ConfD/NCS instance port (int)
    * path -- ConfD/NCS instance location path (str)
    * src_ip - source ip address (str)
    * src_port - source port (int)
    * proto - protocol used by for connecting (i.e. ncs.PROTO_TCP)
    * vendor -- lock error information (str, optional)
    * product -- lock error information (str, optional)
    * version -- lock error information (str, optional)
    * client_id -- lock error information (str, optional)
    * load_schemas - passed on to Maapi.__init__()

    Returns:

    * read transaction object (maapi.Transaction)
    """
    client_id = client_id or _mk_client_id()
    with Maapi(ip, port, path, load_schemas=load_schemas) as m:
        m.start_user_session(user, context, groups, src_ip, src_port, proto,
                             vendor, product, version, client_id)
        with m.start_read_trans(db, vendor=vendor, product=product,
                                version=version, client_id=client_id) as t:
            yield t


@contextlib.contextmanager
def single_write_trans(user, context, groups=[],
                       db=_tm.RUNNING, ip=_tm.ADDR,
                       port=_tm.PORT, path=None, src_ip=_tm.ADDR,
                       src_port=0, proto=_tm.PROTO_TCP, vendor=None,
                       product=None, version=None, client_id=None,
                       load_schemas=LOAD_SCHEMAS_LOAD):
    """Context manager for a single READ/WRITE transaction.

    This function connects to ConfD/NCS, starts a user session and finally
    starts a new READ/WRITE transaction.

    Function signature:

        def single_write_trans(user, context, groups=[],
                               db=RUNNING, ip=<CONFD-OR-NCS-ADDR>,
                               port=<CONFD-OR-NCS-PORT>, path=None,
                               src_ip=<CONFD-OR-NCS-ADDR>, src_port=0,
                               proto=PROTO_TCP,
                               vendor=None, product=None, version=None,
                               client_id=_mk_client_id(),
                               load_schemas=LOAD_SCHEMAS_LOAD):

    For argument db see Maapi.start_trans(). For arguments user,
    context, groups, src_ip, src_port, proto, vendor, product, version and
    client_id see Maapi.start_user_session().
    For arguments ip, port and path see connect().
    For argument load_schemas see __init__().

    Arguments:

    * user - username (str)
    * context - context for the session (str)
    * groups - groups (list)
    * db -- database (int)
    * ip -- ConfD/NCS instance ip address (str)
    * port -- ConfD/NCS instance port (int)
    * path -- ConfD/NCS instance location path (str)
    * src_ip - source ip address (str)
    * src_port - source port (int)
    * proto - protocol used by the client for connecting (int)
    * vendor -- lock error information (str, optional)
    * product -- lock error information (str, optional)
    * version -- lock error information (str, optional)
    * client_id -- lock error information (str, optional)
    * load_schemas - passed on to Maapi.__init__()

    Returns:

    * write transaction object (maapi.Transaction)
    """
    client_id = client_id or _mk_client_id()
    with Maapi(ip, port, path, load_schemas=load_schemas) as m:
        m.start_user_session(user, context, groups, src_ip, src_port, proto,
                             vendor, product, version, client_id)
        with m.start_write_trans(db, vendor=vendor, product=product,
                                 version=version, client_id=client_id) as t:
            yield t


class Maapi(object):
    """Class encapsulating a MAAPI connection."""

    _schemas_loaded = False
    _schemas_loaded_lock = threading.RLock()

    def __init__(self, ip=_tm.ADDR, port=_tm.PORT, path=None,
                 load_schemas=LOAD_SCHEMAS_LOAD, msock=None):
        """Create a Maapi instance.

        Arguments:

        * ip -- ConfD/NCS instance ip address (str, optional)
        * port -- ConfD/NCS instance port (int, optional)
        * path -- ConfD/NCS instance location path (str, optional)
        * msock -- already connected MAAPI socket (socket.socket, optional)
                   (ip, port and path ignored)
        * load_schemas -- whether schemas should be loaded/reloaded or not
                          LOAD_SCHEMAS_LOAD = load schemas unless already loaded
                          LOAD_SCHEMAS_SKIP = do not load schemas
                          LOAD_SCHEMAS_RELOAD = force reload of schemas

        The option LOAD_SCHEMAS_RELOAD can be used to force a reload of
        schemas, for example when connecting to a different ConfD/NSO node.
        Note that previously constructed maagic objects will be invalid and
        using them will lead to undefined behavior. Use this option with care,
        for example in a small script querying a list of running nodes.
        """
        if msock:
            self.msock = msock
        else:
            self.msock = connect(ip, port, path)

        if load_schemas == LOAD_SCHEMAS_RELOAD:
            with Maapi._schemas_loaded_lock:
                Maapi._schemas_loaded = False
        if load_schemas:
            self.load_schemas()

        self._ip = ip
        self._port = port
        self._path = path

    @property
    def ip(self):
        """Return address to connect to the IPC port"""
        return self._ip

    @property
    def port(self):
        """Return port to connect to the IPC port"""
        return self._port

    @property
    def path(self):
        """Return path to connect to the IPC port"""
        return self._path

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self):
        """Python magic method."""
        return self

    def __exit__(self, exc_type, exc_value, tb):
        """Python magic method."""
        detached = self._force_detach()

        try:
            if getattr(self, '_started_usess', False):
                self.end_user_session()
        except Exception:
            pass

        try:
            self.close()
        except Exception:
            pass

        if detached:
            raise Exception(
                'user code error, transaction must be detached before Maapi '
                'object goes out of scope')

    def __repr__(self):
        """Get internal representation."""
        return 'Maapi msock=' + str(self.msock.fileno())

    def __dir__(self):
        """Return a list of all available methods in Maapi."""
        methods = dir(Maapi)
        methods.extend(dir(_tm.maapi))
        return methods

    # Hack: When a method is not found, look for it in low level Maapi
    # instead and call it with self.msock as the first argument.
    def __getattr__(self, name):
        """Python magic method.

        This method will be called whenever an attribute not present here
        is accessed. It will try to find a corresponding attribute in the
        low-level maapi module which takes a maapi socket as the first
        arument and forward the call there.

        Example (pseudo code):

            import ncs     # high-level module
            import _ncs    # low-level module

            maapi = ncs.maapi.Maapi()

            Now, these two calls are equal:
                1. maapi.install_crypto_keys()
                1. _ncs.maapi.install_crypto_keys(maapi.msock)
        """
        try:
            real = getattr(_tm.maapi, name)
        except AttributeError:
            raise AttributeError("Maapi has no attribute '" + name + "'")

        # for access to constants
        if not callable(real):
            return real

        def proxy(self2, *args, **kwargs):
            return real(self2.msock, *args, **kwargs)
        proxy.__doc__ = _sanitize_docstring(real.__doc__, ["sock"])
        setattr(Maapi, name, proxy)
        return getattr(self, name)

    # trans encapsulation
    def attach_init(self):
        """Attach to phase0 for CDB initialization and upgrade."""
        th = _tm.maapi.attach_init(self.msock)
        t = Transaction(self, th)
        t._attached = True
        self._attached_trans = th
        return t

    # trans encapsulation
    def attach(self, ctx_or_th, hashed_ns=0, usid=0):
        """Attach to an existing transaction.

        'ctx_or_th' may be either a TransCtxRef or a transaction handle.
        The 'hashed_ns' argument is basically just there to save a call to
        set_namespace(). 'usid' is only used if 'ctx_or_th' is a transaction
        handle and if set to 0 the user session id that is the owner of the
        transaction will be used.

        Arguments:

        * ctx_or_th (TransCtxRef or transaction handle)
        * hashed_ns (int)
        * usid (int)

        Returns:

        * transaction object (maapi.Transaction)
        """
        if isinstance(ctx_or_th, _tm.TransCtxRef):
            _tm.maapi.attach(self.msock, hashed_ns, ctx_or_th)
            th = ctx_or_th.th
        else:
            _tm.maapi.attach2(self.msock, hashed_ns, usid, ctx_or_th)
            th = ctx_or_th
        t = Transaction(self, th)
        t._attached = True
        self._attached_trans = th
        return t

    # convenience
    def detach(self, ctx_or_th):
        """Detach the underlying MAAPI socket.

        Arguments:

        * ctx_or_th (TransCtxRef or transaction handle)
        """
        del self._attached_trans
        if isinstance(ctx_or_th, _tm.TransCtxRef):
            _tm.maapi.detach(self.msock, ctx_or_th)
        else:
            _tm.maapi.detach2(self.msock, ctx_or_th)

    # convenience
    def authenticate(self, user, password, n,
                     src_addr=None, src_port=None, context=None, prot=None):
        """Authenticate a user using the AAA configuration.

        Use src_addr, src_port, context and prot to use an external
        authentication executable.
        Use the 'n' to get a list of n-1 groups that the user is a member of.
        Use n=1 if the function is used in a context where the group names
        are not needed.

        Returns 1 if accepted without groups. If the authentication failed
        or was accepted a tuple with first element status code, 0 for
        rejection and 1 for accepted is returned. The second element either
        contains the reason for the rejection as a string OR a list groupnames.

        Arguments:

        * user - username (str)
        * password - passwor d (str)
        * n - number of groups to return (int)
        * src_addr - source ip address (str)
        * src_port - source port (int)
        * context - context for the session (str)
        * prot - protocol used by the client for connecting (int)

        Returns:

        * status (int or tuple)

        """
        if src_addr is not None or \
           src_port is not None or \
           context is not None or \
           prot is not None:
            return _tm.maapi.authenticate2(self.msock, user, password,
                                           src_addr, src_port, context,
                                           prot, n)
        else:
            return _tm.maapi.authenticate(self.msock, user, password, n)

    # cursor iterator encapsulation
    def cursor(self, th, path, enum_cs_nodes=None, want_values=False,
               secondary_index=None, xpath_expr=None):
        """Get an iterable list cursor."""
        return _CursorContextAndIterator(self.msock, th, path,
                                         enum_cs_nodes, want_values,
                                         secondary_index, xpath_expr)

    # no msock
    def destroy_cursor(self, mc):
        """Destroy cursor.

        Arguments:

        * cursor (maapi.Cursor)
        """
        _tm.maapi.destroy_cursor(mc)

    # no msock
    def get_next(self, mc):
        """Iterate and get the keys for the next entry in a list.

        When no more keys are found, False is returned

        Arguments:

        * cursor (maapi.Cursor)

        Returns:

        * keys (list or boolean)
        """
        return _tm.maapi.get_next(mc)

    # no msock
    def find_next(self, mc, type, inkeys):
        """Find next.

        Update the cursor 'mc' with the key(s) for the list entry designated
        by the 'type' and 'inkeys' arguments. This function may be used to
        start a traversal from an arbitrary entry in a list. Keys for
        subsequent entries may be retrieved with the get_next() function.
        When no more keys are found, False is returned.

        The strategy to use is defined by 'type':

            FIND_NEXT - The keys for the first list entry after the one
                        indicated by the 'inkeys' argument.
            FIND_SAME_OR_NEXT - If the values in the 'inkeys' array completely
                        identifies an actual existing list entry, the keys for
                        this entry are requested. Otherwise the same logic as
                        for FIND_NEXT above.
        """
        return _tm.maapi.find_next(mc, type, inkeys)

    # no msock
    def get_objects(self, mc, n, nobj):
        """Get objects.

        Read at most n values from each nobj lists starting at cursor mc.
        Returns a list of Value's.

        Arguments:

        * mc (maapi.Cursor)
        * n -- at most n values will be read (int)
        * nobj -- number of nobj lists which n elements will be taken from (int)

        Returns:

        * list of values (list)
        """
        return _tm.maapi.get_objects(mc, n, nobj)

    # no msock
    def query_free_result(self, qrs):
        """Deallocate QueryResult memory.

        Deallocated memory inside the QueryResult object 'qrs' returned from
        query_result(). It is not necessary to call this method as deallocation
        will be done when the Python library garbage collects the QueryResult
        object.

        Arguments:

        * qrs -- the query result structure to free
        """
        _tm.maapi.query_free_result(qrs)

    # boolean conversion
    def do_display(self, th, path):
        """Do display.

        If the data model uses the YANG when or tailf:display-when
        statement, this function can be used to determine if the item
        given by the path should be displayed or not.

        Arguments:

        * th -- transaction handle
        * path -- path to the 'display-when' statement (str)

        Returns

        * boolean
        """
        return True if _tm.maapi.do_display(self.msock, th, path) else False

    # boolean conversion
    def exists(self, th, path):
        """Check if path exists.

        Arguments:

        * th -- transaction handle
        * path -- path to the node in the data tree (str)

        Returns:

        * boolean
        """
        return True if _tm.maapi.exists(self.msock, th, path) else False

    # boolean conversion
    def get_running_db_status(self):
        """Get running db status.

        Gets the status of the running db. Returns True if consistent and
        False otherwise.

        Returns:

        * boolean
        """
        return True if _tm.maapi.get_running_db_status(self.msock) else False

    # convenience
    def load_schemas(self, use_maapi_socket=False):
        """Load the schemas to Python (using shared memory if enabled).

        If 'use_maapi_socket' is set to True, the schmeas are loaded through
        the NSO daemon via a MAAPI socket.
        """
        if Maapi._schemas_loaded:
            return

        # clear maagic cache
        maagic._clear_root_node_cache()

        with Maapi._schemas_loaded_lock:
            if not Maapi._schemas_loaded:
                if use_maapi_socket:
                    _tm.maapi.load_schemas(self.msock)
                    Maapi._schemas_loaded = True
                else:
                    try:
                        path = _tm.maapi.get_schema_file_path(self.msock)
                        _tm.mmap_schemas(path)
                        Maapi._schemas_loaded = True
                    except _tm.error.Error:
                        # Shared memory not enabled?
                        # Fallback to schema load over socket!
                        _tm.maapi.load_schemas(self.msock)
                        Maapi._schemas_loaded = True

    # convenience
    def safe_create(self, th, path):
        """Safe version of create.

        Create a new list entry, a presence container, or a leaf of
        type empty in the data tree - if it doesn't already exist.

        Arguments:

        * th -- transaction handle
        * path -- path to the new element (str)
        """
        if not self.exists(th, path):
            self.create(th, path)

    # convenience
    def safe_delete(self, th, path):
        """Safe version of delete.

        Delete an existing list entry, a presence container, or an
        optional leaf and all its children (if any) from the data
        tree. If it exists.

        Arguments:

        * th -- transaction handle
        * path -- path to the element (str)
        """
        if self.exists(th, path):
            self.delete(th, path)

    # convenience
    def safe_get_elem(self, th, path):
        """Safe version of get_elem.

        Read the element at 'path', returns 'None' if it doesn't
        exist.

        Arguments:

        * th -- transaction handle
        * path -- path to the element (str)

        Returns:

        * configuration element
        """
        try:
            return self.get_elem(th, path)
        except _tm.error.Error as e:
            if e.confd_errno == _tm.ERR_NOEXISTS:
                return None
            else:
                raise e

    # convenience
    def safe_get_object(self, th, n, path):
        """Safe version of get_object.

        This function reads at most 'n' values from the list entry or
        container specified by the 'path'. Returns 'None' the path is
        empty.

        Arguments:

        * th -- transaction handle
        * n -- at most n values (int)
        * path -- path to the object (str)

        Returns:

        * configuration object
        """
        try:
            return self.get_object(th, n, path)
        except _tm.error.Error as e:
            if e.confd_errno == _tm.ERR_NOEXISTS:
                return None
            else:
                raise e

    # convenience
    def set_elem(self, th, value, path):
        """Set the node at 'path' to 'value'.

        If 'value' is not of type Value it will be converted to a string
        before calling set_elem2() under the hood.

        Arguments:

        * th -- transaction handle
        * value -- element value (Value or str)
        * path -- path to the element (str)
        """
        if isinstance(value, _tm.Value):
            try:
                _tm.maapi.set_elem(self.msock, th, value, path)
            except Exception as original_ex:
                # FIXME: This is a poor mans hack for dealing with unions
                #        of string/enumeration (and possible other combos).
                #        In maagic we do str2val on all values which in
                #        the case of a model like this, and doing
                #        union_x = 'one'...
                #
                #        leaf union-x {
                #          type string {
                #            pattern "(foo|bar)";
                #          }
                #          type enumeration {
                #            enum one;
                #            enum two;
                #          }
                #        }
                #
                #        ... will give us a C_BUF value back, which we will
                #        try to set using set_elem(C_BUF), which in turn will
                #        fail due to the string validation pattern.
                #        If this is the case we try to set the value using its
                #        string representation and set_elem2() instead.
                #
                #        The *correct* way of dealing with this is to use
                #        set_elem2() for most cases and only use set_elem()
                #        for specific cases where nothing else can be done.
                #        One of these specific cases is when validating utf-8
                #        strings, as such, we are required to try set_elem
                #        since we can't convert it to a string
                try:
                    _tm.maapi.set_elem2(self.msock, th, str(value), path)
                except Exception:
                    raise original_ex
        else:
            _tm.maapi.set_elem2(self.msock, th, str(value), path)

    # trans encapsulation and convenience
    def start_trans(self, rw, db=_tm.RUNNING, usid=0, flags=0,
                    vendor=None, product=None, version=None, client_id=None):
        """Start a transaction towards the 'db'.

        This function starts a new a new transaction towards the given
        data store.

        Arguments:

        * rw -- Either READ or READ_WRITE flag (ncs)
        * db -- Either CANDIDATE, RUNNING or STARTUP flag (cdb)
        * usid -- user id (int)
        * flags -- additional transaction flags (int)
        * vendor -- lock error information (str, optional)
        * product -- lock error information (str, optional)
        * version -- lock error information (str, optional)
        * client_id -- lock error information (str, optional)

        Returns:

        * transaction (maapi.Transaction)

        Flags (maapi):

        * FLAG_HINT_BULK
        * FLAG_NO_DEFAULTS
        * FLAG_CONFIG_ONLY
        * FLAG_HIDE_INACTIVE
        * FLAG_DELAYED_WHEN
        * FLAG_NO_CONFIG_CACHE
        * FLAG_CONFIG_CACHE_ONLY
        """
        client_id = client_id or _mk_client_id()
        th = _tm.maapi.start_trans_flags2(self.msock, db, rw, usid, flags,
                                          vendor, product, version, client_id)
        return Transaction(self, th)

    def start_read_trans(self, db=_tm.RUNNING, usid=0, flags=0,
                         vendor=None, product=None, version=None,
                         client_id=None):
        """Start a read transaction.

        For details see start_trans().
        """
        client_id = client_id or _mk_client_id()
        return self.start_trans(_tm.READ, db, usid, flags, vendor,
                                product, version, client_id)

    def start_write_trans(self, db=_tm.RUNNING, usid=0, flags=0,
                          vendor=None, product=None, version=None,
                          client_id=None):
        """Start a write transaction.

        For details see start_trans().
        """
        client_id = client_id or _mk_client_id()
        return self.start_trans(_tm.READ_WRITE, db, usid, flags, vendor,
                                product, version, client_id)

    # trans encapsulation and convenience
    def start_trans_in_trans(self, th, readwrite, usid=0):
        """Start a new transaction within a transaction.

        This function makes it possible to start a transaction with another
        transaction as backend, instead of an actual data store. This can be
        useful if we want to make a set of related changes, and then either
        apply or discard them all based on some criterion, while other changes
        remain unaffected. The thandle identifies the backend transaction to
        use. If 'usid' is 0, the transaction will be started within the user
        session associated with the MAAPI socket, otherwise it will be started
        within the user session given by usid. If we call apply() on this
        "transaction in a transaction" object, the changes (if any) will be
        applied to the backend transaction. To discard the changes, call
        finish() without calling apply() first.

        Arguments:

        * th -- transaction handle
        * readwrite -- Either READ or READ_WRITE flag (ncs)
        * usid -- user id (int)

        Returns:

        * transaction (maapi.Transaction)
        """
        newth = _tm.maapi.start_trans_in_trans(self.msock, readwrite, usid, th)
        return Transaction(self, newth)

    # convenience
    def start_user_session(self, user, context, groups=[], src_ip=_tm.ADDR,
                           src_port=0, proto=_tm.PROTO_TCP, vendor=None,
                           product=None, version=None, client_id=None):
        """Start a new user session.

        This method gives some resonable defaults.

        Arguments:

        * user - username (str)
        * context - context for the session (str)
        * groups - groups (list)
        * src_ip - source ip address (str)
        * src_port - source port (int)
        * proto - protocol used by for connecting (i.e. ncs.PROTO_TCP)
        * vendor -- lock error information (str, optional)
        * product -- lock error information (str, optional)
        * version -- lock error information (str, optional)
        * client_id -- lock error information (str, optional)

        Protocol flags (ncs):

        * PROTO_CONSOLE
        * PROTO_HTTP
        * PROTO_HTTPS
        * PROTO_SSH
        * PROTO_SSL
        * PROTO_SYSTEM
        * PROTO_TCP
        * PROTO_TLS
        * PROTO_TRACE
        * PROTO_UDP

        Example use:

            maapi.start_user_session(
                  sock_maapi,
                  'admin',
                  'python',
                  [],
                  _ncs.ADDR,
                  _ncs.PROTO_TCP)
        """
        client_id = client_id or _mk_client_id()
        # Keep track of started user session so we only end user
        # session in __exit__ if we did started it.
        self._started_usess = True
        _tm.maapi.start_user_session3(self.msock, user, context, groups,
                                      src_ip, src_port, proto,
                                      vendor, product, version, client_id)

    def close(self):
        """Ends session and closes socket."""
        detached = self._force_detach()
        _tm.maapi.close(self.msock)
        if detached:
            raise Exception(
                'user code error, transaction must be detached before closing '
                'Maapi object')

    def report_progress(self, th, verbosity, msg, package=None):
        """Report transaction/action progress.

        The 'package' argument is only available to NCS.
        """
        if package is None:
            _tm.maapi.report_progress(self.msock, th, verbosity, msg)
        elif tm.TM == '_ncs':
            _tm.maapi.report_progress2(
                self.msock, th, verbosity, msg, package)
        else:
            raise Exception("The 'package' argument is only available to NCS")

    def report_progress_start(self, th, verbosity, msg, package=None):
        """Report transaction/action progress.

        Used for calculation of the duration between two events. The method
        returns a _Progress object to be passed to report_progress_stop()
        once the event has finished.

        The 'package' argument is only available to NCS.
        """
        if (package is not None and tm.TM != '_ncs'):
            raise Exception("The 'package' argument is only available to NCS")
        else:
            timestamp = _tm.maapi.report_progress_start(
                self.msock, th, verbosity, msg, package)
            return _Progress(verbosity, timestamp, msg, package)

    def report_progress_stop(self, th, progress, annotation=None):
        """Report transaction/action progress.

        Used for calculation of the duration between two events. The method
        takes a _Progress object returned from report_progress_start().
        """
        _tm.maapi.report_progress_stop(
            self.msock, th, progress.verbosity, progress.msg,
            annotation, progress.package, progress.timestamp)

    def netconf_ssh_call_home(self, host, port=4334):
        """Initiate NETCONF SSH Call Home."""
        _tm.maapi.netconf_ssh_call_home(self.msock, host, port)

    def netconf_ssh_call_home_opaque(self, host, opaque, port=4334):
        """Initiate NETCONF SSH Call Home w. opaque data."""
        _tm.maapi.netconf_ssh_call_home_opaque(self.msock, host, opaque, port)

    @tm.ncs_only
    def run_with_retry(self, fun, max_num_retries=10, commit_params=None,
                       usid=0, flags=0, vendor=None, product=None,
                       version=None, client_id=None):
        """Run fun with a new read-write transaction against RUNNING.

        The transaction is applied if fun returns True. The fun is
        only retried in case of transaction conflicts. Each retry is
        run using a new transaction.

        The last conflict error.Error is thrown in case of max number of
        retries is reached.

        Arguments:

        * fun - work fun (fun(maapi.Transaction) -> bool)
        * usid - user id (int)
        * max_num_retries - maximum number of retries (int)

        Returns:

        * bool True if transation was applied, else False.
        """
        retries_left = max_num_retries
        while retries_left >= 0:
            with self.start_write_trans(usid=usid, flags=flags, vendor=vendor,
                                        product=product, version=version,
                                        client_id=client_id) as trans:
                if fun(trans):
                    try:
                        trans.apply_params(False, commit_params)
                        return True
                    except _tm.error.Error as ex:
                        retries_left -= 1
                        if (retries_left < 0
                            or ex.confd_errno != _tm.ERR_TRANSACTION_CONFLICT):
                            raise
                else:
                    return False
        return False

    @tm.ncs_only
    def apply_template(self, th, name, path, vars=None, flags=0):
        """Apply a template."""
        _tm.maapi.apply_template(self.msock, th, name, vars, flags, path)

    @tm.ncs_only
    def shared_apply_template(self, th, name, path, vars=None, flags=0):
        """FASTMAP version of apply_template()."""
        _tm.maapi.shared_apply_template(self.msock, th, name, vars,
                                        flags, path)

    @tm.ncs_only
    def shared_copy_tree(self, th, from_path, to_path, flags=0):
        """FASTMAP version of copy_tree()."""
        _tm.maapi.shared_copy_tree(self.msock, th, flags, from_path, to_path)

    @tm.ncs_only
    def shared_create(self, th, path, flags=0):
        """FASTMAP version of create()."""
        _tm.maapi.shared_create(self.msock, th, flags, path)

    @tm.ncs_only
    def shared_insert(self, th, path, flags=0):
        """FASTMAP version of insert()."""
        _tm.maapi.shared_insert(self.msock, th, flags, path)

    @tm.ncs_only
    def shared_set_elem(self, th, value, path, flags=0):
        """FASTMAP version of set_elem().

        If 'value' is not of type Value it will be converted to a string
        before calling shared_set_elem2() under the hood.
        """
        if isinstance(value, _tm.Value):
            try:
                _tm.maapi.shared_set_elem(self.msock, th, value, flags, path)
            except Exception as original_ex:
                # see set_elem for a description of why we need this try
                try:
                    _tm.maapi.shared_set_elem2(self.msock, th, str(value),
                                               flags, path)
                except Exception:
                    raise original_ex
        else:
            _tm.maapi.shared_set_elem2(self.msock, th, str(value), flags, path)

    @tm.ncs_only
    def shared_set_values(self, th, values, path, flags=0):
        """FASTMAP version of set_values()."""
        _tm.maapi.shared_set_values(self.msock, th, values, flags, path)

    @tm.ncs_only
    def write_service_log_entry(self, path, msg, type, level):
        """Write service log entries.

        This function makes it possible to write service log entries from
        FASTMAP code.
        """
        _tm.maapi.write_service_log_entry(self.msock, path, msg, type, level)

    @tm.ncs_only
    def report_service_progress(self, th, verbosity, msg, path, package=None):
        """Report transaction progress for a FASTMAP service."""
        if package is None:
            _tm.maapi.report_service_progress(
                self.msock, th, verbosity, msg, path)
        else:
            _tm.maapi.report_service_progress2(
                self.msock, th, verbosity, msg, path, package)

    @tm.ncs_only
    def report_service_progress_start(self, th, verbosity, msg, path,
                                      package=None):
        """Report transaction progress for a FASTMAP service.

        Used for calculation of the duration between two events. The method
        returns a _Progress object to be passed to
        report_service_progress_stop() once the event has finished.
        """
        timestamp = _tm.maapi.report_service_progress_start(
            self.msock, th, verbosity, msg, path, package)
        return _Progress(verbosity, timestamp, msg, package, path)

    @tm.ncs_only
    def report_service_progress_stop(self, th, progress, annotation=None):
        """Report transaction progress for a FASTMAP service.

        Used for calculation of the duration between two events. The method
        takes a _Progress object returned from report_service_progress_start().
        """
        _tm.maapi.report_service_progress_stop(
            self.msock, th, progress.verbosity, progress.msg, annotation,
            progress.path, progress.package, progress.timestamp)

    def _force_detach(self):
        if hasattr(self, '_attached_trans'):
            try:
                self.detach(self._attached_trans)
            except Exception:
                pass
            return True
        return False


class Session(object):
    """Encapsulate a MAAPI user session.

    Context manager for user sessions. This class makes it easy to use
    a single Maapi connection and switch user session along the way.
    For example:

        with Maapi() as m:
            for user, context, device in devlist:
                with Session(m, user, context):
                    with m.start_write_trans() as t:
                        # ...
                        # do something using the correct user session
                        # ...
                        t.apply()
    """

    def __init__(self, maapi, user, context, groups=[], src_ip=_tm.ADDR,
                 src_port=0, proto=_tm.PROTO_TCP, vendor=None, product=None,
                 version=None, client_id=None):
        """Initialize a Session object via start_user_session().

        Arguments:

        * maapi -- maapi object (maapi.Maapi)
        * for all other arguments see start_user_session()
        """
        client_id = client_id or _mk_client_id()
        maapi.start_user_session(user, context, groups, src_ip, src_port, proto,
                                 vendor, product, version, client_id)
        self.maapi = maapi

    def __enter__(self):
        """Python magic method."""
        return self

    def __exit__(self, exc_type, exc_value, tb):
        """Python magic method."""
        self.close()

    def close(self):
        """Close the user session."""
        try:
            self.maapi.end_user_session()
        except Exception:
            pass

class _Progress(object):
    """Class representing a progress object."""
    def __init__(self, verbosity, timestamp, msg, package=None, path=None):
        self.verbosity = verbosity
        self.timestamp = timestamp
        self.msg = msg
        self.package = package
        self.path = path

@tm.ncs_only
class DryRunOutformat(enum.Enum):
    XML    = 1
    CLI    = 2
    NATIVE = 3
    CLI_C  = 4

@tm.ncs_only
class CommitParams(object):
    """Class representing NSO commit parameters.

    Start with creating an empty instance of this class and set commit
    parameters using helper methods.
    """
    class _Node(object):
        def __init__(self, name):
            self.name = name
            self.children = []
            self.type = _tm.C_XMLTAG
            self.value = None

        def add(self, name):
            node = self.__class__(name)
            self.children.append(node)
            self.container()
            return node

        def container(self):
            self.type = _tm.C_XMLBEGIN

        def node(self, name):
            node = self.descendant(name)
            if node is None:
                node = self.add(name)
            return node

        def descendant(self, *names):
            # found all children provided, return ourself
            if len(names) == 0:
                return self

            for child in self.children:
                if child.name == names[0]:
                    return child.descendant(*names[1:])

            return None

        def is_descendant(self, *names):
            return self.descendant(*names) is not None

        def set(self, value, type):
            self.value = _tm.Value(value, type)
            self.type = None

        def get(self):
            if self.type is None:
                return self.value
            else:
                return None

        def tag_values(self, ns):
            tvs = []
            if self.name is not None:
                xt = _tm.XmlTag(ns, self.name)
                if self.value is None:
                    self.value = _tm.Value((ns, self.name), self.type)
                tvs.append(_tm.TagValue(xt, self.value))
            if self.type == _tm.C_XMLBEGIN:
                for child in self.children:
                    tvs.extend(child.tag_values(ns))
                if self.name is not None:
                    endv = _tm.Value((ns, self.name), _tm.C_XMLEND)
                    tvs.append(_tm.TagValue(xt, endv))
            return tvs

        def add_tag_values(self, tvs):
            i = 0
            while i < len(tvs):
                tv = tvs[i]
                value = tv.v
                node = self.add(tv.tag)
                if value.confd_type() == _tm.C_XMLBEGIN:
                    start = i + 1
                    node.container()
                    while i < len(tvs):
                        if tvs[i].v.confd_type() == _tm.C_XMLEND and \
                           tvs[i].ns == tv.ns and \
                           tvs[i].tag == tv.tag:
                            break
                        i = i + 1
                        if i == len(tvs):
                            raise Exception('Missing XML end tag')
                    node.add_tag_values(tvs[start:i])
                elif value.confd_type() != _tm.C_XMLTAG:
                    node.value = value
                    node.type = None
                i = i + 1

        def __repr__(self, prefix=""):
            if self.name is not None and len(self.children) == 0:
                if self.value is None:
                    return "{}{}".format(prefix, _tm.hash2str(self.name))
                else:
                    return "{}{}={}".format(prefix,
                            _tm.hash2str(self.name),
                            self.value.as_pyval())

            if self.name is not None:
                prefix = "{}{}/".format(prefix, _tm.hash2str(self.name))

            cr = []
            for child in self.children:
                cr.append(child.__repr__(prefix))

            return " ".join(cr)


    def __init__(self, result=None):
        from .ns.netconf_ncs_ns import ns as ns_netconf_ncs
        from .ns.ncs_ns import ns as ns_ncs
        self.ns_netconf_ncs = ns_netconf_ncs
        self.ns_ncs = ns_ncs
        self.root = CommitParams._Node(None)
        if result is not None:
            self.root.add_tag_values(result)

    def _tag_values(self):
        return self.root.tag_values(self.ns_netconf_ncs.hash)

    def commit_queue_async(self):
        """Set commit queue asynchronous mode of operation."""
        self.root.node(self.ns_netconf_ncs.ncsnc_commit_queue) \
                 .node(self.ns_netconf_ncs.ncsnc_async)

    def is_commit_queue_async(self):
        """Get commit queue asynchronous mode of operation."""
        return self.root.is_descendant(self.ns_netconf_ncs.ncsnc_commit_queue,
                                       self.ns_netconf_ncs.ncsnc_async)

    def commit_queue_sync(self, timeout=None):
        """Set commit queue synchronous mode of operation."""
        sync = self.root.node(self.ns_netconf_ncs.ncsnc_commit_queue) \
                        .node(self.ns_netconf_ncs.ncsnc_sync)
        if timeout is not None and timeout > -1:
            sync.node(self.ns_netconf_ncs.ncsnc_timeout) \
                .set(timeout, _tm.C_UINT32)
        elif timeout is not None:
            sync.node(self.ns_netconf_ncs.ncsnc_infinity)
        else:
            sync.container()

    def is_commit_queue_sync(self):
        """Get commit queue synchronous mode of operation."""
        return self.root.is_descendant(self.ns_netconf_ncs.ncsnc_commit_queue,
                                       self.ns_netconf_ncs.ncsnc_sync)

    def get_commit_queue_sync_timeout(self):
        """Get commit queue synchronous mode of operation timeout."""
        timeout = self.root.descendant(self.ns_netconf_ncs.ncsnc_commit_queue,
                                       self.ns_netconf_ncs.ncsnc_sync,
                                       self.ns_netconf_ncs.ncsnc_timeout)
        if timeout is None:
            return None
        else:
            return timeout.get().as_pyval()

    def commit_queue_bypass(self):
        """Make the commit transactional even if commit queue is
        configured by default.
        """
        self.root.node(self.ns_netconf_ncs.ncsnc_commit_queue) \
                 .node(self.ns_netconf_ncs.ncsnc_bypass)

    def is_commit_queue_bypass(self):
        """Check if the commit is transactional even if commit queue is
        configured by default.
        """
        return self.root.is_descendant(self.ns_netconf_ncs.ncsnc_commit_queue,
                                       self.ns_netconf_ncs.ncsnc_bypass)

    def commit_queue_tag(self, tag):
        """Set commit-queue tag. Implicitly enabled commit queue commit."""
        self.root.node(self.ns_netconf_ncs.ncsnc_commit_queue) \
                 .node(self.ns_netconf_ncs.ncsnc_tag) \
                 .set(tag, _tm.C_BUF)

    def get_commit_queue_tag(self):
        """Get commit-queue tag."""
        tag = self.root.descendant(self.ns_netconf_ncs.ncsnc_commit_queue,
                                   self.ns_netconf_ncs.ncsnc_tag)
        if tag is None:
            return None
        else:
            return tag.get().as_pyval()

    def commit_queue_lock(self):
        """Make the commit queue item locked."""
        self.root.node(self.ns_netconf_ncs.ncsnc_commit_queue) \
                 .node(self.ns_netconf_ncs.ncsnc_lock)

    def is_commit_queue_lock(self):
        """Check if the commit queue item should be locked."""
        return self.root.is_descendant(self.ns_netconf_ncs.ncsnc_commit_queue,
                                       self.ns_netconf_ncs.ncsnc_lock)

    def commit_queue_block_others(self):
        """Make the commit queue item block other commit queue items for
        this device.
        """
        self.root.node(self.ns_netconf_ncs.ncsnc_commit_queue) \
                 .node(self.ns_netconf_ncs.ncsnc_block_others)

    def is_commit_queue_block_others(self):
        """Check if the the commit queue item should block other commit
        queue items for this device.
        """
        return self.root.is_descendant(self.ns_netconf_ncs.ncsnc_commit_queue,
                                       self.ns_netconf_ncs.ncsnc_block_others)

    def commit_queue_atomic(self):
        """Make the commit queue item atomic."""
        self.root.node(self.ns_netconf_ncs.ncsnc_commit_queue) \
                 .node(self.ns_netconf_ncs.ncsnc_atomic) \
                 .set(1, _tm.C_BOOL)

    def is_commit_queue_atomic(self):
        """Check if the commit queue item should be atomic."""
        atomic = self.root.descendant(self.ns_netconf_ncs.ncsnc_commit_queue,
                                      self.ns_netconf_ncs.ncsnc_atomic)
        if atomic is None:
            return False
        else:
            return atomic.get().as_pyval() == 1

    def commit_queue_non_atomic(self):
        """Make the commit queue item non-atomic."""
        self.root.node(self.ns_netconf_ncs.ncsnc_commit_queue) \
                 .node(self.ns_netconf_ncs.ncsnc_atomic) \
                 .set(0, _tm.C_BOOL)

    def is_commit_queue_non_atomic(self):
        """Check if the commit queue item should be non-atomic."""
        atomic = self.root.descendant(self.ns_netconf_ncs.ncsnc_commit_queue,
                                      self.ns_netconf_ncs.ncsnc_atomic)
        if atomic is None:
            return False
        else:
            return atomic.get().as_pyval() == 0

    def commit_queue_error_option(self, error_option):
        """Set commit queue item behaviour on error."""
        vals = \
            {'continue-on-error': self.ns_netconf_ncs.ncsnc_continue_on_error,
             'rollback-on-error': self.ns_netconf_ncs.ncsnc_rollback_on_error,
             'stop-on-error': self.ns_netconf_ncs.ncsnc_stop_on_error}
        if error_option not in vals:
            raise ValueError('Invalid error_option!')
        self.root.node(self.ns_netconf_ncs.ncsnc_commit_queue) \
                 .node(self.ns_netconf_ncs.ncsnc_error_option) \
                 .set(vals[error_option], _tm.C_ENUM_VALUE)

    def get_commit_queue_error_option(self):
        """Get commit queue item behaviour on error."""
        vals = \
            {self.ns_netconf_ncs.ncsnc_continue_on_error: 'continue-on-error',
             self.ns_netconf_ncs.ncsnc_rollback_on_error: 'rollback-on-error',
             self.ns_netconf_ncs.ncsnc_stop_on_error: 'stop-on-error'}
        error_option = self.root.descendant(
                self.ns_netconf_ncs.ncsnc_commit_queue,
                self.ns_netconf_ncs.ncsnc_error_option)
        if error_option is None:
            return None
        else:
            return vals.get(error_option.get().as_pyval(), None)

    def no_networking(self):
        """Only write the configuration to CDB, do not actually push it to
        the device.
        """
        self.root.node(self.ns_netconf_ncs.ncsnc_no_networking)

    def is_no_networking(self):
        """Check if the the configuration should only be written to CDB and
        not actually pushed to the device.
        """
        return self.root.is_descendant(self.ns_netconf_ncs.ncsnc_no_networking)

    def no_revision_drop(self):
        """Set no-revision-drop commit parameter."""
        self.root.node(self.ns_netconf_ncs.ncsnc_no_revision_drop)

    def is_no_revision_drop(self):
        """Get no-revision-drop commit parameter."""
        return self.root.is_descendant(
                self.ns_netconf_ncs.ncsnc_no_revision_drop)

    def no_overwrite(self):
        """Check that the parts of the device configuration to be modified are
        are up-to-date in CDB before pushing the configuration change to the
        device.
        """
        self.root.node(self.ns_netconf_ncs.ncsnc_no_overwrite)

    def is_no_overwrite(self):
        """Should a check be done that the parts of the device configuration
        to be modified are are up-to-date in CDB before pushing the
        configuration change to the device.
        """
        return self.root.is_descendant(self.ns_netconf_ncs.ncsnc_no_overwrite)

    def no_out_of_sync_check(self):
        """Do not check device sync state before pushing the configuration
        change.
        """
        self.root.node(self.ns_netconf_ncs.ncsnc_no_out_of_sync_check)

    def is_no_out_of_sync_check(self):
        """Do not check device sync state before pushing the configuration
        change.
        """
        return self.root.is_descendant(
                self.ns_netconf_ncs.ncsnc_no_out_of_sync_check)

    def no_lsa(self):
        """Set no-lsa commit parameter."""
        self.root.node(self.ns_netconf_ncs.ncsnc_no_lsa)

    def is_no_lsa(self):
        """Get no-lsa commit parameter."""
        return self.root.is_descendant(self.ns_netconf_ncs.ncsnc_no_lsa)

    def use_lsa(self):
        """Set use-lsa commit parameter."""
        self.root.node(self.ns_netconf_ncs.ncsnc_use_lsa)

    def is_use_lsa(self):
        """Get use-lsa commit parameter."""
        return self.root.is_descendant(self.ns_netconf_ncs.ncsnc_use_lsa)

    def no_deploy(self):
        """Do not invoke service's create method."""
        self.root.node(self.ns_netconf_ncs.ncsnc_no_deploy)

    def is_no_deploy(self):
        """Should service create method be invoked or not."""
        return self.root.is_descendant(self.ns_netconf_ncs.ncsnc_no_deploy)

    def reconcile_keep_non_service_config(self):
        """Set reconcile commit parameter with keep-non-service-config
        behaviour.
        """
        self.root.node(self.ns_netconf_ncs.ncsnc_reconcile) \
                 .node(self.ns_netconf_ncs.ncsnc_keep_non_service_config)

    def is_reconcile_keep_non_service_config(self):
        """Get reconcile commit parameter with keep-non-service-config
        behaviour.
        """
        return self.root.is_descendant(
                self.ns_netconf_ncs.ncsnc_reconcile,
                self.ns_netconf_ncs.ncsnc_keep_non_service_config)

    def reconcile_discard_non_service_config(self):
        """Set reconcile commit parameter with discard-non-service-config
        behaviour.
        """
        self.root.node(self.ns_netconf_ncs.ncsnc_reconcile) \
                 .node(self.ns_netconf_ncs.ncsnc_discard_non_service_config)

    def is_reconcile_discard_non_service_config(self):
        """Get reconcile commit parameter with discard-non-service-config
        behaviour.
        """
        return self.root.is_descendant(
                self.ns_netconf_ncs.ncsnc_reconcile,
                self.ns_netconf_ncs.ncsnc_discard_non_service_config)

    def is_dry_run(self):
        """Is dry-run enabled"""
        return self.root.is_descendant(self.ns_netconf_ncs.ncsnc_dry_run)

    def get_dry_run_outformat(self):
        """Get dry-run outformat"""
        outformat = self.root.descendant(self.ns_netconf_ncs.ncsnc_dry_run,
                                         self.ns_netconf_ncs.ncsnc_outformat)
        if outformat is None:
            return None

        outformat = outformat.get().as_pyval()
        if outformat == self.ns_ncs.ncs_outformat_xml:
            return DryRunOutformat.XML
        elif outformat == self.ns_ncs.ncs_outformat_cli:
            return DryRunOutformat.CLI
        elif outformat == self.ns_ncs.ncs_outformat_native:
            return DryRunOutformat.NATIVE
        elif outformat == self.ns_ncs.ncs_outformat_cli_c:
            return DryRunOutformat.CLI_C
        else:
            raise Exception("Unsupported outformat")

    def set_dry_run_outformat(self, outformat):
        """Set dry-run outformat"""
        node = self.root.node(self.ns_netconf_ncs.ncsnc_dry_run) \
                .node(self.ns_netconf_ncs.ncsnc_outformat)
        if outformat == DryRunOutformat.XML:
            node.set(self.ns_ncs.ncs_outformat_xml, _tm.C_ENUM_VALUE)
        elif outformat == DryRunOutformat.CLI:
            node.set(self.ns_ncs.ncs_outformat_cli, _tm.C_ENUM_VALUE)
        elif outformat == DryRunOutformat.NATIVE:
            node.set(self.ns_ncs.ncs_outformat_native, _tm.C_ENUM_VALUE)
        elif outformat == DryRunOutformat.CLI_C:
            node.set(self.ns_ncs.ncs_outformat_cli_c, _tm.C_ENUM_VALUE)
        else:
            raise Exception("Unsupported outformat")

    def dry_run_xml(self):
        """Dry-run commit outformat XML."""
        self.root.node(self.ns_netconf_ncs.ncsnc_dry_run) \
                 .node(self.ns_netconf_ncs.ncsnc_outformat) \
                 .set(self.ns_ncs.ncs_outformat_xml, _tm.C_ENUM_VALUE)

    def dry_run_cli(self):
        """Dry-run commit outformat CLI."""
        self.root.node(self.ns_netconf_ncs.ncsnc_dry_run) \
                 .node(self.ns_netconf_ncs.ncsnc_outformat) \
                 .set(self.ns_ncs.ncs_outformat_cli, _tm.C_ENUM_VALUE)

    def dry_run_native(self):
        """Dry-run commit outformat native."""
        self.root.node(self.ns_netconf_ncs.ncsnc_dry_run) \
                 .node(self.ns_netconf_ncs.ncsnc_outformat) \
                 .set(self.ns_ncs.ncs_outformat_native, _tm.C_ENUM_VALUE)

    def dry_run_cli_c(self):
        """Dry-run commit outformat cli-c."""
        self.root.node(self.ns_netconf_ncs.ncsnc_dry_run) \
                 .node(self.ns_netconf_ncs.ncsnc_outformat) \
                 .set(self.ns_ncs.ncs_outformat_cli_c, _tm.C_ENUM_VALUE)

    def dry_run_native_reverse(self):
        """Dry-run commit outformat native reverse."""
        dry_run = self.root.node(self.ns_netconf_ncs.ncsnc_dry_run)
        dry_run.node(self.ns_netconf_ncs.ncsnc_outformat) \
               .set(self.ns_ncs.ncs_outformat_native, _tm.C_ENUM_VALUE)
        dry_run.node(self.ns_netconf_ncs.ncsnc_reverse)

    def dry_run_cli_c_reverse(self):
        """Dry-run commit outformat cli-c reverse."""
        dry_run = self.root.node(self.ns_netconf_ncs.ncsnc_dry_run)
        dry_run.node(self.ns_netconf_ncs.ncsnc_outformat) \
               .set(self.ns_ncs.ncs_outformat_cli_c, _tm.C_ENUM_VALUE)
        dry_run.node(self.ns_netconf_ncs.ncsnc_reverse)

    def is_dry_run_reverse(self):
        """Is dry-run reverse enabled."""
        return self.root.is_descendant(self.ns_netconf_ncs.ncsnc_dry_run,
                                       self.ns_netconf_ncs.ncsnc_reverse)

    def wait_device(self, devices):
        """Wait for device locks before entering transaction critical state.

        This method is deprecated and will be removed in future release.
        """
        devlist = []
        for device in devices:
            devlist.append(_tm.Value(device, _tm.C_BUF))
        self.root.add(self.ns_netconf_ncs.ncsnc_wait_device) \
                 .set(devlist, _tm.C_LIST)

    def get_wait_devices(self):
        """Get the devices that the transaction should wait for a device lock
        for before entering the transactions critical section.

        This method is deprecated and will be removed in future release.
        """
        wait_device = self.root.descendant(
                self.ns_netconf_ncs.ncsnc_wait_device)
        if wait_device is None:
            return []
        else:
            return [d.as_pyval() for d in wait_device.get()]

    def trace_id(self, trace_id):
        """Set trace id."""
        self.root.node(self.ns_netconf_ncs.ncsnc_trace_id) \
                 .set(trace_id, _tm.C_BUF)

    def get_trace_id(self):
        """Get trace id."""
        trace_id = self.root.descendant(self.ns_netconf_ncs.ncsnc_trace_id)
        if trace_id is None:
            return None
        else:
            return trace_id.get().as_pyval()

    def __repr__(self):
        return "CommitParams({})".format(repr(self.root))


# Class that corresponds to a single maapi transaction
class Transaction(object):
    """Class that corresponds to a single MAAPI transaction."""

    # This list should contain all Maapi methods available to Transaction
    # (i.e. all methods requiring a transaction handle).
    _th_calls = [
        'abort_trans',
        'apply_template',
        'apply_trans',
        'apply_trans_flags',
        'apply_trans_params',
        'cs_node_cd',
        'cs_node_children',
        'cd',
        'cli_cmd_to_path2',
        'cli_diff_cmd',
        'cli_path_cmd',
        'cursor',
        'commit_queue_result',
        'commit_trans',
        'copy',
        'copy_path',
        'copy_tree',
        'create',
        'delete',
        'delete_all',
        'detach2',
        'diff_iterate',
        'do_display',
        'exists',
        'finish_trans',
        'get_attrs',
        'get_case',
        'get_elem',
        'get_object',
        'get_trans_params',
        'get_values',
        'getcwd',
        'getcwd_kpath',
        'init_cursor',
        'insert',
        'iterate',
        'keypath_diff_iterate',
        'load_config',
        'load_config_cmds',
        'load_config_stream',
        'load_rollback',
        'move',
        'move_ordered',
        'num_instances',
        'netconf_ssh_call_home',
        'netconf_ssh_call_home_opaque',
        'popd',
        'prepare_trans',
        'prepare_trans_flags',
        'pushd',
        'query_start',
        'request_action_str_th',
        'request_action_th',
        'report_progress',
        'report_progress2',
        'report_progress_start',
        'report_progress_stop',
        'report_service_progress',
        'report_service_progress2',
        'report_service_progress_start',
        'report_service_progress_stop',
        'revert',
        'roll_config',
        'save_config',
        'set_attr',
        'set_comment',
        'set_delayed_when',
        'set_elem',
        'set_elem2',
        'set_flags',
        'set_label',
        'set_namespace',
        'set_object',
        'set_values',
        'safe_create',
        'safe_delete',
        'safe_get_elem',
        'safe_get_object',
        'shared_apply_template',
        'shared_copy_tree',
        'shared_create',
        'shared_insert',
        'shared_set_elem',
        'shared_set_elem2',
        'shared_set_values',
        'start_trans_in_trans',
        'validate_trans',
        'xpath_eval',
        'xpath_eval_expr'
    ]

    def __init__(self, maapi, th=None, rw=None, db=_tm.RUNNING, vendor=None,
                 product=None, version=None, client_id=None):
        """Initialize a Transaction object.

        When created one may access the maapi and th arguments like this:

            trans = Transaction(mymaapi, th=myth)
            trans.maapi # the Maapi object
            trans.th # the transaction handle

        An instance of this class is also a context manager:

            with Transaction(mymaapi, th=myth) as trans:
                # do something here...

        When exiting the with statement, finish() will be called.

        If 'th' is left out (or None) a new transaction is started using
        the 'db' and 'rw' arguments, otherwise 'db' and 'rw' are ignored.

        Arguments:

        * maapi -- a Maapi object (maapi.Maapi)
        * th -- a transaction handle or None
        * rw -- Either READ or READ_WRITE flag (ncs)
        * db -- Either CANDIDATE, RUNNING or STARTUP flag (cdb)
        * vendor -- lock error information (optional)
        * product -- lock error information (optional)
        * version -- lock error information (optional)
        * client_id -- lock error information (optional)
        """
        if not th:
            if rw is None:
                raise Exception('Must specify rw argument')
            client_id = client_id or _mk_client_id()
            th = _tm.maapi.start_trans_flags2(maapi.msock, db, rw, 0, 0,
                                              vendor, product, version,
                                              client_id)
        self.maapi = maapi
        self.th = th
        self._finished = False

    def __repr__(self):
        """Get internal representation."""
        return 'Transaction th=' + str(self.th)

    def __dir__(self):
        """Return a list of all available methods in Transaction."""
        methods = dir(Transaction)
        methods.extend(Transaction._th_calls)
        return methods

    def __enter__(self):
        """Python magic method."""
        return self

    def __exit__(self, exc_type, exc_value, tb):
        """Python magic method."""
        if getattr(self, '_attached', False):
            self.maapi.detach(self.th)
            del self._attached
            self._finished = True
        elif not self._finished:
            try:
                self.finish()
            except Exception:
                pass

    # Hack: When a method is not found we simply forward the call by calling
    # getattr on self.maapi.
    def __getattr__(self, name):
        """Python magic method.

        This method will be called whenever an attribute not present here
        is accessed. It will try to find a corresponding attribute in the Maapi
        object which takes a transaction handle as the second argument and
        forward the call there.

        Example (pseudo code):

            import ncs     # high-level module
            import _ncs    # low-level module

            maapi = ncs.maapi.Maapi()
            trans = maapi.start_read_trans()

            Now, these three calls are equal:
                1. trans.get_elem('/path/to/leaf')
                2. maapi.get_elem(trans.th, '/path/to/leaf')
                3. _ncs.maapi.get_elem(maapi.msock, trans.th, '/path/to/leaf')
        """
        if name not in Transaction._th_calls:
            raise AttributeError("Transaction has no attribute '" + name + "'")

        if hasattr(Maapi, name):
            real = getattr(Maapi, name)

            def proxy(self2, *args, **kwargs):
                return real(self2.maapi, self2.th, *args, **kwargs)
        else:
            real = getattr(_tm.maapi, name)

            def proxy(self2, *args, **kwargs):
                return real(self2.maapi.msock, self2.th, *args, **kwargs)

        proxy.__doc__ = _sanitize_docstring(real.__doc__, ["sock", "thandle"])
        setattr(Transaction, name, proxy)
        return getattr(self, name)

    def validate(self, unlock, forcevalidation=False):
        """Validate the transaction.

        This function validates all data written in the transaction. This
        includes all data model constraints and all defined semantic
        validation, i.e. user programs that have registered functions under
        validation points.

        If 'unlock' is True, the transaction is open for further editing even
        if validation succeeds. If 'unlock' is False and the function succeeds
        next function to be called MUST be prepare() or finish().

        'unlock = True' can be used to implement a 'validate' command which
        can be given in the middle of an editing session. The first thing that
        happens is that a lock is set. If 'unlock' == False, the lock is
        released on success. The lock is always released on failure.

        The 'forcevalidation' argument should normally be False. It has no
        effect for a transaction towards the running or startup data stores,
        validation is always performed. For a transaction towards the
        candidate data store, validation will not be done unless
        'forcevalidation' is True. Avoiding this validation is preferable if
        we are going to commit the candidate to running, since otherwise the
        validation will be done twice. However if we are implementing a
        'validate' command, we should give a True value for 'forcevalidation'.

        Arguments:

        * unlock (boolean)
        * forcevalidation (boolean)
        """
        self.maapi.validate_trans(self.th, unlock, forcevalidation)

    def prepare(self, flags=0):
        """Prepare transaction.

        This function must be called as first part of two-phase commit. After
        this function has been called, commit() or abort() must be called.

        It will invoke the prepare callback in all participants in the
        transaction. If all participants reply with OK, the second phase of
        the two-phase commit procedure is commenced.

        Arguments:

        * flags - additional transaction flags (int)

        Flags (maapi):

        * COMMIT_NCS_NO_REVISION_DROP
        * COMMIT_NCS_NO_DEPLOY
        * COMMIT_NCS_NO_NETWORKING
        * COMMIT_NCS_NO_OUT_OF_SYNC_CHECK
        * COMMIT_NCS_COMMIT_QUEUE_BYPASS
        * COMMIT_NCS_COMMIT_QUEUE_ASYNC
        * COMMIT_NCS_COMMIT_QUEUE_SYNC
        * COMMIT_NCS_NO_OVERWRITE
        * COMMIT_NCS_COMMIT_QUEUE_LOCK
        * COMMIT_NCS_COMMIT_QUEUE_BLOCK_OTHERS
        * COMMIT_NCS_COMMIT_QUEUE_ATOMIC
        * COMMIT_NCS_COMMIT_QUEUE_NONATOMIC
        * COMMIT_NCS_COMMIT_QUEUE_CONTINUE_ON_ERROR
        * COMMIT_NCS_COMMIT_QUEUE_ROLLBACK_ON_ERROR
        * COMMIT_NCS_COMMIT_QUEUE_STOP_ON_ERROR
        * COMMIT_NCS_USE_LSA
        * COMMIT_NCS_NO_LSA
        * COMMIT_NCS_RECONCILE_KEEP_NON_SERVICE_CONFIG
        * COMMIT_NCS_RECONCILE_DISCARD_NON_SERVICE_CONFIG
        """
        self.maapi.prepare_trans_flags(self.th, flags)

    def commit(self):
        """Commit the transaction."""
        self.maapi.commit_trans(self.th)

    def abort(self):
        """Abort the transaction."""
        self.maapi.abort_trans(self.th)

    def apply(self, keep_open=True, flags=0):
        """Apply the transaction.

        Validates, prepares and eventually commits or aborts the
        transaction. If the validation fails and the 'keep_open'
        argument is set to True (default), the transaction is left
        open and the developer can react upon the validation errors.

        Arguments:

        * keep_open -- keep transaction open (boolean)
        * flags - additional transaction flags (int)

        Flags (maapi):

        * COMMIT_NCS_NO_REVISION_DROP
        * COMMIT_NCS_NO_DEPLOY
        * COMMIT_NCS_NO_NETWORKING
        * COMMIT_NCS_NO_OUT_OF_SYNC_CHECK
        * COMMIT_NCS_COMMIT_QUEUE_BYPASS
        * COMMIT_NCS_COMMIT_QUEUE_ASYNC
        * COMMIT_NCS_COMMIT_QUEUE_SYNC
        * COMMIT_NCS_NO_OVERWRITE
        * COMMIT_NCS_COMMIT_QUEUE_LOCK
        * COMMIT_NCS_COMMIT_QUEUE_BLOCK_OTHERS
        * COMMIT_NCS_COMMIT_QUEUE_ATOMIC
        * COMMIT_NCS_COMMIT_QUEUE_NONATOMIC
        * COMMIT_NCS_COMMIT_QUEUE_CONTINUE_ON_ERROR
        * COMMIT_NCS_COMMIT_QUEUE_ROLLBACK_ON_ERROR
        * COMMIT_NCS_COMMIT_QUEUE_STOP_ON_ERROR
        * COMMIT_NCS_USE_LSA
        * COMMIT_NCS_NO_LSA
        * COMMIT_NCS_RECONCILE_KEEP_NON_SERVICE_CONFIG
        * COMMIT_NCS_RECONCILE_DISCARD_NON_SERVICE_CONFIG
        """
        if 'applied' in self.__dict__:
            raise Exception('Transaction already applied')
        self.maapi.apply_trans_flags(self.th, keep_open, flags)
        self.__dict__['applied'] = True

    @tm.ncs_only
    def apply_params(self, keep_open=True, params=None):
        """Apply the transaction and return the result in form of dict().

        Validates, prepares and eventually commits or aborts the
        transaction. If the validation fails and the 'keep_open'
        argument is set to True (default), the transaction is left
        open and the developer can react upon the validation errors.

        The 'params' argument represent commit parameters. See CommitParams
        class for available commit parameters.

        The result is a dictionary representing the result of applying
        transaction. If dry-run was requested, then the resulting dictionary
        will have 'dry-run' key set along with the actual results. If commit
        through commit queue was requested, then the resulting dictionary
        will have 'commit-queue' key set. Otherwise the dictionary will
        be empty.

        Arguments:

        * keep_open -- keep transaction open (boolean)
        * params -- list of commit parameters (maapi.CommitParams)

        Returns:

        * dict (see above)

        Example use:

            with ncs.maapi.single_write_trans('admin', 'python') as t:
                root = ncs.maagic.get_root(t)
                dns_list = root.devices.device['ex1'].config.sys.dns.server
                dns_list.create('192.0.2.1')
                params = t.get_params()
                params.dry_run_native()
                result = t.apply_params(True, params)
                print(result['device']['ex1'])
                t.apply_params(True, t.get_params())
        """
        from .ns.netconf_ncs_ns import ns as ns_netconf_ncs
        tvparams = params._tag_values() if params is not None else []
        tvresult = self.maapi.apply_trans_params(self.th, keep_open, tvparams)
        self.__dict__['applied'] = True
        if len(tvresult) == 0:
            result = {}
        elif tvresult[0].tag == ns_netconf_ncs.ncsnc_dry_run_result:
            result = {'dry-run': True}
            current = None
            name = None
            for tv in tvresult[1:]:
                if tv.v.confd_type() == _tm.C_XMLBEGIN:
                    if tv.tag == ns_netconf_ncs.ncsnc_result_xml:
                        result['outformat'] = 'xml'
                    elif tv.tag == ns_netconf_ncs.ncsnc_cli:
                        result['outformat'] = 'cli'
                    elif tv.tag == ns_netconf_ncs.ncsnc_native:
                        result['outformat'] = 'native'
                    elif tv.tag == ns_netconf_ncs.ncsnc_cli_c:
                        result['outformat'] = 'cli-c'
                    elif tv.tag == ns_netconf_ncs.ncsnc_local_node:
                        current = 'local-node'
                    elif tv.tag == ns_netconf_ncs.ncsnc_lsa_node:
                        current = 'lsa-node'
                    elif tv.tag == ns_netconf_ncs.ncsnc_device:
                        current = 'device'
                else:
                    if tv.tag == ns_netconf_ncs.ncsnc_name:
                        name = str(tv.v)
                    elif tv.tag == ns_netconf_ncs.ncsnc_data:
                        if name is not None:
                            if current not in result:
                                result[current] = {}
                            result[current][name] = str(tv.v)
                        else:
                            result[current] = str(tv.v)
        else:
            result = {'commit-queue': True}
            name = None
            for tv in tvresult:
                if tv.tag == ns_netconf_ncs.ncsnc_id:
                    result['id'] = int(tv.v)
                elif tv.tag == ns_netconf_ncs.ncsnc_status:
                    valmap = {
                         ns_netconf_ncs.ncsnc_commit_cq_async: 'async',
                         ns_netconf_ncs.ncsnc_commit_cq_completed: 'completed',
                         ns_netconf_ncs.ncsnc_commit_cq_timeout: 'timeout',
                         ns_netconf_ncs.ncsnc_commit_cq_deleted: 'deleted',
                         ns_netconf_ncs.ncsnc_commit_cq_failed: 'failed'}
                    result['status'] = valmap[int(tv.v)]
                elif tv.tag == ns_netconf_ncs.ncsnc_failed_device:
                    if 'failed-device' not in result:
                        result['failed-device'] = {}
                elif tv.tag == ns_netconf_ncs.ncsnc_name:
                    name = str(tv.v)
                elif tv.tag == ns_netconf_ncs.ncsnc_reason:
                    result['failed-device'][name] = str(tv.v)
        return result

    @tm.ncs_only
    def get_params(self):
        """Get the current commit parameters for the transaction.

        The result is an instance of the CommitParams class.
        """
        result = self.maapi.get_trans_params(self.th)
        return CommitParams(result)

    def finish(self):
        """Finish the transaction.

        This will finish the transaction. If the transaction is implemented
        by an external database, this will invoke the finish() callback.
        """
        if not self._finished:
            self.maapi.finish_trans(self.th)
            self._finished = True


class _CursorContextAndIterator(object):
    def __init__(self, sock, th, path, enum_cs_nodes, want_values,
                 secondary_index, xpath_expr):
        self._enum_cs_nodes = enum_cs_nodes
        self._want_values = want_values

        self.cur = _tm.maapi.init_cursor(
            sock, th, path, secondary_index, xpath_expr)

    def __enter__(self):
        return self

    def __exit__(self, type_, value, tb):
        self.delete()

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def __del__(self):
        self.delete()

    def next(self):
        key = _tm.maapi.get_next(self.cur)
        if key:
            if self._want_values:
                return key
            else:
                return Key(key, self._enum_cs_nodes)
        else:
            raise StopIteration()

    def delete(self):
        if getattr(self, 'cur', None) is not None:
            _tm.maapi.destroy_cursor(self.cur)
            self.cur = None


class Key(object):
    """Key string encapsulation and helper."""

    def __init__(self, key, enum_cs_nodes=None):
        """Initialize a key.

        'key' may be a string or a list of strings.
        """
        if isinstance(key, str):
            key = (key,)

        def _bool_conv(key):
            if isinstance(key, bool):
                return 'true' if key else 'false'
            return key

        try:
            if enum_cs_nodes:
                self._key = []
                for val, node in zip(key, enum_cs_nodes):
                    if node is not None:
                        self._key.append(val.val2str(node))
                    else:
                        self._key.append(val)
            else:
                self._key = [_bool_conv(x) for x in key]
        except Exception:
            self._key = [_bool_conv(key)]

        self._keystr = '{""}' if not self._key else None

    def _key_str(self):
        self._keystr = '{' + ' '.join([_quote(str(k)) for k in self._key]) + '}'
        return self._keystr

    def __str__(self):
        """Get string representation."""
        return self._keystr or self._key_str()

    def __repr__(self):
        """Get internal representation."""
        return "Key values = " + repr(self._key)

    def __len__(self):
        """Get number of keys."""
        return len(self._key)

    def __getitem__(self, key):
        """Get key at index 'key'."""
        return self._key[key]

    def __iter__(self):
        """Return a key iterator object."""
        return self._key.__iter__()


def _decode(s):
    keys = []

    buf = StringIO()
    in_quote = False
    in_escape = False
    in_xpath = False
    for c in s:
        if in_escape:
            buf.write(c)
            in_escape = False
        elif c == '\\':
            in_escape = True
        elif in_quote:
            if c == '"':
                keys.append(buf.getvalue())
                buf.truncate(0)
                in_quote = False
            else:
                buf.write(c)
        elif c == '[':
            in_xpath = True
            buf.write(c)
        elif c == ']':
            in_xpath = False
            buf.write(c)
        elif c == '"' and not in_xpath:
            in_quote = True
        elif c == ' ':
            if buf.tell() > 0:
                keys.append(buf.getvalue())
            buf.truncate(0)
        else:
            buf.write(c)

    if buf.tell() > 0:
        keys.append(buf.getvalue())

    buf.close()
    return keys


def _quote(s):
    if s == '':
        return '""'
    require_quote = (' ', '"', '\\', '{', '}')
    if any(c in s for c in require_quote):
        return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
    return s


if __name__ == '__main__':
    import unittest

    class _TestDecode(unittest.TestCase):
        def test_decode_single_unquoted(self):
            self.assertEqual(_decode('plain'), ['plain'])

        def test_decode_multiple_unquoted(self):
            self.assertEqual(_decode('one two'), ['one', 'two'])

        def test_decode_single_quoted(self):
            self.assertEqual(_decode('"quoted"'), ['quoted'])

        def test_decode_multiple_quoted(self):
            self.assertEqual(_decode('"one" "two"'), ['one', 'two'])

        def test_decode_multiple_mix(self):
            self.assertEqual(_decode('"one" two'), ['one', 'two'])

        def test_decode_xpath_key(self):
            self.assertEqual(_decode('/service[name="test"]'),
                             ['/service[name="test"]'])


    class _TestCommitParamsNode(unittest.TestCase):
        def test_descendant(self):
            tree = CommitParams._Node(None)
            a = tree.node("a")
            b = a.node("b")
            c = b.node("c")
            self.assertTrue(tree.is_descendant())
            self.assertTrue(tree.is_descendant("a", "b", "c"))
            self.assertFalse(tree.is_descendant("a", "d", "c"))
            self.assertEqual(tree.descendant(), tree)
            self.assertEqual(tree.descendant("a", "b", "c"), c)
            self.assertEqual(tree.descendant("a", "d", "c"), None)


    unittest.main()
