"""Confd/NCS data access module.

This module implements classes and function for easy access to the data store.
There is no need to manually instantiate any of the classes herein. The only
functions that should be used are cd(), get_node() and get_root().

N.B.
In this version of maagic a yang leaf-list is represented differently
than before. Reading a leaf-list using maagic used to result in an
ordinary Python list or None if the leaf-list was non-existent.
Now, reading a leaf-list will give back a LeafList instance whether
it exists or not. The LeafList instance may be iterated like a Python list
and you may check for existence using the exists() method.
A maagic leaf-list node may be assigned using a Python list, just like
before, and you may convert it to a Python list using the as_list() method
or by doing list(my_leaf_list_node).

You should update your code to cope with the new behaviour. If you for
any reason are unable to do so you can instruct maagic to behave as in
previous versions by setting the environment variable
DEPRECATED_MAAGIC_WANT_LEAF_LIST_AS_LEAF to 'true', 'yes' or '1' before
starting your Python process (or NSO).

Please note that this environment variable is deprecated and will go away
in the future.
"""
import functools
import numbers
import collections
import os
import threading

from . import maapi
from . import keypath
from . import childlist
from . import tm

_tm = __import__(tm.TM)

NODE_NAME_FULL = 0
NODE_NAME_SHORT = 1
NODE_NAME_PY_FULL = 2
NODE_NAME_PY_SHORT = 3

# Construction of the Root node can be expensive if the system has a
# lot of namespaces and is in heavy concurrent use. This is a cache of
# the root node that is shallow copied on construct.
_all_ns_root_node = None
_all_ns_root_node_lock = threading.RLock()


def _clear_root_node_cache():
    global _all_ns_root_node, _all_ns_root_node_lock
    with _all_ns_root_node_lock:
        if _all_ns_root_node:
            _all_ns_root_node = None


def _want_leaf_list_as_leaf():
    e = os.getenv('DEPRECATED_MAAGIC_WANT_LEAF_LIST_AS_LEAF', '')
    e = e.lower()
    return e in ['yes', 'true', '1']


def _get_nslist():
    return _tm.get_nslist()


def _get_ns_root_nodes(ns_hash):
    cs_node = _tm.find_cs_root(ns_hash)
    return [(child, _tm.ns2prefix(child.ns()), _tm.hash2str(child.tag()))
            for child in _CsNodeIter(cs_node)]


class BackendError(Exception):
    """Exception type used within maagic backends."""

    pass


class MaagicError(Exception):
    """Exception type used within maagic."""

    pass


# A backend should strive to implement the following methods
# get_elem, set_elem, create, delete, exists, num_instances, get_case,
# request_action, cursor, move_ordered
# They should be semantically equivalent to the maapi implementations.
# Any method that is not implemented must throw an exception.
# The simplest possible backend just passes all calls on to a
# maapi.Transaction object.
class _MaagicBackend(object):
    def __init__(self):
        pass


class _TransactionBackend(_MaagicBackend):
    """Backend that uses a maapi.Transaction object to talk to the CDB."""

    def __init__(self, trans):
        """Initialize a _TransactionBackend.

        Used by 'get_root()', should not normally be called explicitly.

        Arguments:

        * trans -- Transaction object to use (maapi.Transaction)
        """
        super(_TransactionBackend, self).__init__()
        if not isinstance(trans, maapi.Transaction):
            raise BackendError("Not a Transaction object")
        self.trans = trans
        self._shared = False

    def __repr__(self):
        """Get internal representation."""
        return repr(self.trans)

    @tm.ncs_only
    def _set_shared(self):
        """Make this backend use FASTMAP-friendly methods."""
        self.copy_tree = self.shared_copy_tree
        self.create = self.shared_create
        self.insert = self.shared_insert
        self.set_elem = self.shared_set_elem
        self.set_values = self.shared_set_values
        self.apply_template = self.shared_apply_template
        self._shared = True

    def __dir__(self):
        return dir(self.trans)

    def __getattr__(self, name):
        return getattr(self.trans, name)

    def _apply(self, keep_open=True, flags=0):
        self.apply(keep_open, flags)

    def _get_elem(self, path):
        return self.safe_get_elem(path)

    def _set_elem(self, value, path):
        self.set_elem(value, path)

    def _exists(self, path):
        return self.exists(path)

    def _delete(self, path):
        self.delete(path)

    def _num_instances(self, path):
        return self.num_instances(path)

    def _cursor(self, path, enum_cs_nodes, want_values,
                secondary_index, xpath_expr):
        return self.cursor(path, enum_cs_nodes, want_values,
                           secondary_index, xpath_expr)

    def _request_action(self, params, _ns, path):
        return self.request_action_th(params, path)


class _MaapiBackend(_MaagicBackend):
    """Backend that uses a maapi.Maapi object to talk to the CDB."""

    def __init__(self, maapi_o):
        """Initialize a _MaapiBackend.

        Used by 'get_root()', should not normally be called explicitly.

        Arguments:

        * maapi_o -- Maapi object to use (maapi.Maapi)
        """
        super(_MaapiBackend, self).__init__()
        if not isinstance(maapi_o, maapi.Maapi):
            raise BackendError("Not a Maapi object")
        self.maapi = maapi_o

    def __repr__(self):
        """Get internal representation."""
        return repr(self.maapi)

    def __dir__(self):
        return dir(self.maapi)

    def __getattr__(self, name):
        return getattr(self.maapi, name)

    def _apply(self, keep_open=True, flags=0):
        raise BackendError("Not a Transaction backend")

    def _get_elem(self, path):
        raise BackendError("Not a Transaction backend")

    def _set_elem(self, value, path):
        raise BackendError("Not a Transaction backend")

    def _exists(self, path):
        raise BackendError("Not a Transaction backend")

    def _delete(self, path):
        raise BackendError("Not a Transaction backend")

    def _num_instances(self, path):
        raise BackendError("Not a Transaction backend")

    def _cursor(self, path, enum_cs_nodes, want_values,
                secondary_index, xpath_expr):
        raise BackendError("Not a Transaction backend")

    def _request_action(self, params, ns, path):
        return self.request_action(params, ns, path)


@functools.total_ordering
class Enum(object):
    """Simple represention of a yang enumeration instance.

    Contains the string and integer representation of the enumeration.
    An Enum object supports comparisons with other 'Enum' objects as well as
    with other objects. For equality checks, strings, numbers, 'Enum' objects
    and 'Value' objects are allowed. For relational operators,
    all of the above except strings are acceptable.

    Attributes:

    * string -- string representation of the enumeration
    * value -- integer representation of the enumeration
    """

    def __init__(self, string, value):
        """Initialize an Enum object from a given string and integer.

        Note that an Enum object has no connection to the yang model and will
        not check that the given value matches the string representation
        according to the schema. Normally it is not necessary to create
        Enum objects using this constructor as enum leaves can be set using
        strings alone.

        Arguments:

        * string -- string representation of the enumeration (str)
        * value -- integer representation of the enumeration (int)
        """
        self.string = str(string)
        self.value = int(value)

    def __str__(self):
        """Return the string representation of the enumeration."""
        return self.string

    def __int__(self):
        """Return the integer representation of the enumeration."""
        return self.value

    def __eq__(self, other):
        """Check enumeration for equality with another object.

        The enumeraion is considered equal to the other object if one of the
        following is true:
        - 'other' is a number type and is equal to 'self.value'
        - 'other' is a string and is equal to 'self.string'
        - 'other' is a 'Value' object of type ENUM and its value value
          is equal to 'self.value'
        - 'other' is also an 'Enum' and has the same string and value
          attributes as self
        """
        if isinstance(other, numbers.Number) and not isinstance(other, bool):
            return self.value == other
        elif isinstance(other, str):
            return self.string == other
        elif isinstance(other, _tm.Value):
            return other.confd_type() == _tm.C_ENUM_VALUE \
                and int(other) == self.value
        else:
            try:
                return other.string == self.string \
                    and other.value == self.value
            except Exception:
                raise MaagicError("Comparison with Enum not possible")

    def __ne__(self, other):
        """Check for inequality."""
        return not self.__eq__(other)

    def __lt__(self, other):
        """Compare enumeration to another object.

        The value attribute of the enumeration is compared to one of the
        following (the first one that is applicable):
        - 'other' itself if 'other' is a number
        - 'int(other)' if 'other' is a Value object
        - 'other.value' if 'other' is an Enum object
        """
        if isinstance(other, numbers.Number) and not isinstance(other, bool):
            return self.value < other
        elif isinstance(other, _tm.Value):
            return self.value < int(other)
        else:
            try:
                self.value < other.value
            except Exception:
                raise MaagicError("Comparison with Enum not possible")

    def __repr__(self):
        """Get internal representation."""
        return 'Enum string="%s" value="%d"' % (self.string, self.value)


class Bits(object):
    """Representation of a yang bits leaf with position > 63."""

    def __init__(self, value, cs_node=None):
        """Initialize a Bits object.

        Note that a Bits object has no connection to the yang model and will
        not check that the given value matches the string representation
        according to the schema. Normally it is not necessary to create
        Bits objects using this constructor as bits leaves can be set using
        bytearrays alone.

        Attributes:

        * value -- a Value object of type C_BITBIG
        * cs_node -- a CsNode representing the yang bits leaf. Without this
                     you cannot get a string representation of the bits
                     value; in that case repr(self) will be returned for
                     the str() call. (default: None)
        """
        self._value = value
        self._cs_node = cs_node
        self._ba = None

    def __repr__(self):
        """Get internal representation."""
        return 'Bits %s' % (self._value)

    def __str__(self):
        """Return the string representation of the bits object."""
        if self._cs_node is None:
            return repr(self)
        else:
            return self._value.val2str(self._cs_node)

    def __len__(self):
        """Return the needed size in bytes for the bits object."""
        return len(self.bytearray())

    def __eq__(self, other):
        """Check bits for equality with another object.

        The Bits is considered equal to the other object if one of the
        following is true:
        - 'other' is a 'Bits' type and 'other.bytearray()' is equal
          to 'self.bytearray()
        - 'other' is a bytearray and is equal to 'self.bytearray()'
        - 'other' is a 'Value' object of type BITBIG and its 'as_pyval()'
          value is equal to 'self.bytearray()'
        - 'other' is a 'bytes' or a 'str' object and is equal to
          self.bytearray()
        """
        if isinstance(other, Bits):
            return self.bytearray() == other.bytearray()

        if isinstance(other, bytearray):
            return self.bytearray() == other

        if isinstance(other, _tm.Value):
            return (other.confd_type() == _tm.C_BITBIG and
                    self.bytearray() == other.as_pyval())

        if isinstance(other, (bytes, str)):
            return self.bytearray() == bytearray(other)

        raise MaagicError("Comparison with Bits not possible")

    def __ne__(self, other):
        """Check for inequality."""
        return not self.__eq__(other)

    def bytearray(self):
        """Return a 'little-endian' byte array."""
        if not self._ba:
            self._ba = self._value.as_pyval()
        return self._ba

    def set_bit(self, position):
        """Set a bit at a specific position in the internal byte array."""
        bpos = int(position / 8)
        bit = position % 8
        self.bytearray()[bpos] |= 2**bit

    def clr_bit(self, position):
        """Clear a bit at a specific position in the internal byte array."""
        bpos = int(position / 8)
        bit = position % 8
        self.bytearray()[bpos] &= (255 - 2**bit)

    def is_bit_set(self, position):
        """Check if a bit at a specific position is set."""
        bpos = int(position / 8)
        bit = position % 8
        return bool(self.bytearray()[bpos] & 2**bit)


# The config tree is represented as a tree of Node objects.
# Data is loaded lazily from the cdb. In order to save time and memory, very
# little work is done in the node constructor. Instead, the method _populate()
# is used to do things like figuring out the node's name and keypath.
# The magic method __getattr__, which runs when someone tries to access an
# attribute that does not exist, will run _populate() (which will possibly
# create the requested attribute) if it has not already been run.
#
# If _populate() is overridden, the overriding method should take care to
# either:
#  a. immediately call super(MyType, self)._populate()
#  b. set self._populated to True before accessing any potentially non-existent
#     attributes
#
# For any attribute which is to be calculated in _populate(), it is important
# that the constructor does not create that attribute at all as that would
# prevent __getattr__ from triggering when that attribute is requested.
# In Node itself, such attributes are _path and _name.

class Node(object):
    """Base class of all nodes in the configuration tree.

    Contains magic overrides that make children in the yang tree appear as
    attributes of the Node object and as elements in the list 'self'.

    Attributes:

    * _name -- the yang name of this node (str)
    * _path -- the keypath of this node in string form (HKeypathRef)
    * _parent -- the parent of this node, or None if this node
                has no parent (maagic.Node)
    * _cs_node -- the schema node of this node, or None if this node is not in
                  the schema (maagic.Node)
    """

    def __init__(self, backend, cs_node, parent=None, is_root=False):
        """Initialize a Node object. Should not be called explicitly."""
        super(Node, self).__init__()
        self._set_attr('_populated', False)
        self._set_attr('_backend', backend)
        self._set_attr('_cs_node', cs_node)
        self._set_attr('_parent', parent)
        self._set_attr('_is_root', is_root)

    def __str__(self):
        """Return the name of this node in the schema."""
        return _tm.hash2str(self._cs_node.tag())

    def __int__(self):
        """Return the tag value of this node in the schema."""
        return self._cs_node.tag()

    def _populate(self):
        if not self._populated:
            self._set_attr('_populated', True)
            self._set_name_path()

    def _set_name_path(self):
        if self._is_root:
            self._set_attr('_name', '')
            self._set_attr('_path', '')
        else:
            self._set_attr('_name', _tm.hash2str(self._cs_node.tag()))
            self._set_attr('_path', self._mk_path())

    def _mk_path(self):
        if (self._parent is not None and
                self._parent._cs_node is not None):
            parent_ns = self._parent._cs_node.ns()
            parent_path = self._parent._path
        else:
            parent_ns = None
            parent_path = ''
        my_ns = self._cs_node.ns()
        if my_ns == parent_ns:
            prefix = ''
        else:
            prefix = _tm.ns2prefix(my_ns) + ':'
        return parent_path + '/' + prefix + self._name

    def __getattr__(self, name):
        """Python magic method."""
        if not self._populated:
            self._populate()
            return getattr(self, name)
        children = self.__dict__.get('_children', [])
        if name in children:
            child = children.get_by_py(self._backend, self, name)
            if hasattr(child, 'get_value'):
                return child.get_value()
            else:
                return child
        else:
            super(Node, self).__getattribute__(name)

    def __setattr__(self, name, value):
        """Python magic method."""
        if not self._populated:
            self._populate()
            return setattr(self, name, value)
        children = self.__dict__.get('_children', [])
        if name in children:
            child = children.get_by_py(self._backend, self, name)
            if hasattr(child, 'set_value'):
                child.set_value(value)
            else:
                raise MaagicError("Node type does not support assignment")
        else:
            raise MaagicError("Node has no attribute '%s'" % (name,))

    def __delattr__(self, name):
        """Python magic method."""
        if not self._populated:
            self._populate()
        children = self.__dict__.get('_children', [])
        if name in children:
            child = children.get_by_py(self._backend, self, name)
            if hasattr(child, 'delete'):
                child.delete()
                return
            else:
                raise MaagicError("Node type cannot be deleted")
        super(Node, self).__delattr__(name)

    def __getitem__(self, name):
        """Python magic method."""
        if not self._populated:
            self._populate()
        if '_children' not in self.__dict__:
            raise TypeError("Node type does not have children")
        if name == "..":
            p = self._parent
            if p._parent is not None and p._cs_node is self._cs_node:
                # Take an extra step if we are backing out of a list item
                p = p._parent
            return p
        elif name == ".":
            return self
        else:
            child = self._children.get_by_yang(self._backend, self, name)
            if hasattr(child, 'get_value'):
                return child.get_value()
            else:
                return child

    def __setitem__(self, name, value):
        """Python magic method."""
        if not self._populated:
            self._populate()
        if '_children' not in self.__dict__:
            raise TypeError("Node type does not have children")

        child = self._children.get_by_yang(self._backend, self, name)
        if hasattr(child, 'set_value'):
            child.set_value(value)
        else:
            raise MaagicError("Node type does not support assignment")

    def __delitem__(self, name):
        """Python magic method."""
        if not self._populated:
            self._populate()
        if '_children' in self.__dict__:
            child = self._children.get_by_yang(self._backend, self, name)
            if hasattr(child, 'delete'):
                child.delete()
            else:
                raise MaagicError("Node type cannot be deleted")
        else:
            raise MaagicError("Node type does not have children")

    def __dir__(self):
        """Return a list of children available under this Node."""
        if not self._populated:
            self._populate()
        children = dir(super(Node, self))
        if '_children' in self.__dict__:
            children += self._children.get_shortest_py_names()
        return children

    def __iter__(self):
        """Iterate over children names under this Node."""
        if not self._populated:
            self._populate()
        if '_children' not in self.__dict__:
            raise TypeError("Node type is not iterable")
        children = self.__dict__['_children']
        return iter(children.children.keys())

    def _get_node(self, path):
        """Return the node at path 'path' in this tree.

        Arguments:

        * path -- relative or absolute keypath as a string (HKeypathRef or
                  maagic.Node)

        Returns:

        * node (maagic.Node)
        """
        return cd(self, path)

    def _tagvalues(self):
        """Return this node and all children as a tagvalue array.

        Must be overridden by any subclass that has a tagvalue representation.
        """
        return []

    def _apply(self, keep_open=True, flags=0):
        if self._backend:
            self._backend._apply(keep_open, flags)

    def _set_attr(self, name, value):
        self.__dict__[name] = value

    def _set_cache(self, value):
        self.__dict__['_cache'] = value
        self.__dict__['_cached'] = True

    def _clear_cache(self, cache_object=None):
        self.__dict__['_cache'] = cache_object
        self.__dict__['_cached'] = False


class Root(Node):
    """Represents the root node in the configuration tree.

    The root node is not represented in the schema, it is added for convenience
    and can contain the top level nodes from any number of namespaces as
    children.
    """

    def __init__(self, backend=None, namespaces=None):
        """Initialize a Root node.

        Should not be called explicitly. Instead, use the function
        'get_root()'.

        Arguments:

        * backend -- backend to use, or 'None' for an in-memory tree
                    (maapi.Maapi or maapi.Transaction)
        * namespaces -- which namespaces to include in the tree (list)
        """
        super(Root, self).__init__(backend, cs_node=None, is_root=True)
        self._set_name_path()
        self._set_attr('_namespaces', namespaces)

    def __repr__(self):
        """Get internal representation."""
        return 'Root backend=' + repr(self._backend)

    def __str__(self):
        """Return the string "(root)"."""
        return "(root)"

    def __int__(self):
        """Return the number 0."""
        return 0

    def _populate(self):
        if self._populated:
            return
        self._set_attr('_populated', True)

        def read_namespace(children, ns_hash):
            _add_cached_children(children, _get_ns_root_nodes(ns_hash))

        def read_ns(children, ns):
            if isinstance(ns, str):
                ns = _tm.str2hash(ns)
            read_namespace(children, ns)

        def read_all_namespaces(children):
            for nshash, prefix, uri, revision, module in _get_nslist():
                root = _tm.find_cs_root(nshash)
                if root:
                    read_namespace(children, nshash)

        forbidden = dir(super(Root, self))
        if self._namespaces is None:
            global _all_ns_root_node
            if _all_ns_root_node is None:
                all_ns_root_node = childlist._ChildList(None, forbidden,
                                                        _make_node)
                read_all_namespaces(all_ns_root_node)
                global _all_ns_root_node_lock
                with _all_ns_root_node_lock:
                    if _all_ns_root_node is None:
                        _all_ns_root_node = all_ns_root_node
            self._set_attr('_children', _all_ns_root_node.shallow_copy())
        else:
            self._set_attr('_children', childlist._ChildList(None, forbidden,
                                                             _make_node))
            if isinstance(self._namespaces, list):
                for ns in self._namespaces:
                        read_ns(self._children, ns)
            else:
                read_ns(self._children, self._namespaces)


# A container represents a container node. If the cs_node.is_list() is True,
# the container is an element in a list.
class Container(Node):
    """Represents a yang container.

    A (non-presence) container node or a list element, contains other nodes.
    """

    def __init__(self, backend, cs_node, parent=None):
        """Initialize Container node. Should not be called explicitly."""
        super(Container, self).__init__(backend, cs_node, parent=parent)
        self._set_name_path()
        self._set_attr('_keystr', None)

    # Find all children in the schema. By not doing this in the constructor
    # we save ourselves some cpu cycles.
    # The optional parameter keys contains the key values used to acces this
    # element. These values will be cached in the corresponding child nodes.
    # If this is a keyless list, key should contain a single integer.
    def _populate(self, keys=[]):
        if self._populated:
            return
        self._set_attr('_populated', True)
        ns = _tm.ns2prefix(self._cs_node.ns())
        forbidden = dir(super(Container, self))
        self._set_attr('_children',
                       childlist._ChildList(ns, forbidden, _make_node))

        # setup _path and _keystr attributes
        schema_keys = self._cs_node.info().keys()
        if schema_keys:
            if len(keys) == len(schema_keys):
                keystr = str(maapi.Key(keys))
                self._set_attr('_keystr', keystr)
                self._set_attr('_path', self._parent._path + keystr)
        elif len(keys) == 1:
            self._set_attr('_keystr', "{%d}" % (keys[0]))
            self._set_attr('_path', self._parent._path + "{%d}" % (keys[0]))
        else:
            self._set_attr('_path', self._mk_path())

        # add children
        if self._backend and self._cs_node.is_mount_point():
            if isinstance(self._backend, _TransactionBackend):
                mp_children = self._backend.cs_node_children(
                    self._cs_node, self._path)
            elif isinstance(self._backend, _MaapiBackend):
                mp_children = self._backend.cs_node_children(
                    -1, self._cs_node, self._path)
            else:
                raise MaagicError('unknown backend {}'.format(
                    repr(self._backend)))
            _add_children(self, mp_children)
        else:
            child = self._cs_node.children()
            _add_children(self, _CsNodeIter(child))
            child = self._cs_node.info().choices()
            _add_children(self, _CsNodeIter(child))

        # cache list keys
        if schema_keys and len(keys) == len(schema_keys):
            for key, child in zip(keys,
                                  self._children.get_children(self._backend,
                                                              self)):
                child.set_cache(key)

    def _tagvalues(self):
        acc = []
        for child in self._children.get_children(self._backend, self):
            acc.extend(child._tagvalues())
        if acc:
            v = _tm.Value((self._cs_node.tag(), self._cs_node.ns()),
                          _tm.C_XMLBEGIN)
            v2 = _tm.Value((self._cs_node.tag(), self._cs_node.ns()),
                           _tm.C_XMLEND)
            xmltag = _tm.XmlTag(self._cs_node.ns(), self._cs_node.tag())
            start = _tm.TagValue(xmltag=xmltag, v=v)
            end = _tm.TagValue(xmltag=xmltag, v=v2)
            acc = [start] + acc + [end]
        return acc

    def _from_tagvalues(self, tagvalues):
        """Update the cache of children from the tagvalue array 'tagvalues'."""
        _tagvalues_to_container(self, tagvalues)

    def __repr__(self):
        """Get internal representation."""
        tag = self._cs_node.tag()
        return "Container name=%s tag=%d" % (_tm.hash2str(tag), tag)

    def delete(self):
        """Delete the container.

        Deletes all nodes inside the container. The container itself is not
        affected as it carries no state of its own.

        Example use:

            root.container.delete()
        """
        if self._cs_node.is_list():
            raise MaagicError(
                "To delete a list item, use del list[key]")
        if self._backend:
            self._backend._delete(self._path)
        self._set_attr('_populated', False)
        if '_children' in self.__dict__:
            del self.__dict__['_children']


class PresenceContainer(Container):
    """Represents a presence container."""

    def __init__(self, backend, cs_node, parent=None):
        """Initialize a PresenceContainer. Should not be called explicitly."""
        super(PresenceContainer, self).__init__(backend, cs_node,
                                                parent=parent)
        self._set_attr('_cached', False)
        self._set_attr('_cache', None)

    def __repr__(self):
        """Get internal representation."""
        tag = self._cs_node.tag()
        return "Presence container name=%s tag=%d cached=%s%s" % \
            (_tm.hash2str(tag), tag, self._cached,
             (" exists=" + str(self._cache)) if self._cached else "")

    def __nonzero__(self):
        """Return true if this presence container exists in the data tree."""
        return self.exists()

    def __bool__(self):
        """Return true if this presence container exists in the data tree."""
        return self.__nonzero__()

    def _tagvalues(self):
        acc = []
        if self.exists():
            for child in self._children.get_children(self._backend, self):
                acc.extend(child._tagvalues())
            v = _tm.Value((self._cs_node.tag(), self._cs_node.ns()),
                          _tm.C_XMLBEGIN)
            v2 = _tm.Value((self._cs_node.tag(), self._cs_node.ns()),
                           _tm.C_XMLEND)
            xmltag = _tm.XmlTag(self._cs_node.ns(), self._cs_node.tag())
            start = _tm.TagValue(xmltag=xmltag, v=v)
            end = _tm.TagValue(xmltag=xmltag, v=v2)
            acc = [start] + acc + [end]
        return acc

    def _from_tagvalues(self, tagvalues):
        """Update the cache of children from the tagvalue array 'tagvalues'."""
        if tagvalues:
            self._set_cache(True)
        _tagvalues_to_container(self, tagvalues)

    def exists(self):
        """Return true if the presence container exists in the data tree.

        Example use:

            root.container.presence_container.exists()
        """
        if self._backend and not self._cached:
            self._set_cache(self._backend._exists(self._path))
        return (self._cache is True)

    def create(self):
        """Create and return this presence container in the data tree.

        Example use:

            pc = root.container.presence_container.create()
        """
        if self._cached and self._cache is True:
            return self
        if self._backend:
            if self._backend._shared:
                self._backend.create(self._path)
            else:
                if not self._backend.exists(self._path):
                    self._backend.create(self._path)
            self._clear_cache()
        else:
            self._set_cache(True)
        return self

    def delete(self):
        """Delete this presence container from the data tree.

        Example use:

            root.container.presence_container.delete()
        """
        if self._cached and not self._cache:
            return
        if self._backend:
            self._backend._delete(self._path)
            self._clear_cache()
        else:
            self._set_cache(None)
        self._set_attr('_populated', False)
        if '_children' in self.__dict__:
            del self.__dict__['_children']


class Leaf(Node):
    """Base class for leaf nodes.

    Subclassed by NonEmptyLeaf, EmptyLeaf and LeafList.
    """

    def __init__(self, backend, cs_node, parent=None):
        """Initialize Leaf node. Should not be called explicitly."""
        super(Leaf, self).__init__(backend, cs_node, parent=parent)
        self._set_attr('_cached', False)
        self._set_attr('_cache', None)

    def _populate(self):
        super(Leaf, self)._populate()
        self._set_attr('_type', self._cs_node.info().shallow_type())

    def delete(self):
        """Delete this leaf from the data tree.

        Example use:

            root.model.leaf.delete()
        """
        if self._cached and not self._cache:
            return
        if self._backend:
            self._backend._delete(self._path)
            self._clear_cache()
        else:
            self._set_cache(None)


class NonEmptyLeaf(Leaf):
    """Represents a leaf with a type other than "empty"."""

    def __init__(self, backend, cs_node, parent=None):
        """Initialize a NonEmptyLeaf node. Should not be called explicitly."""
        super(NonEmptyLeaf, self).__init__(backend, cs_node, parent=parent)

    def _tagvalues(self):
        if self._cached:
            v = self._cache
        else:
            v = self.get_value_object()
        if v is None:
            return []
        xmltag = _tm.XmlTag(self._cs_node.ns(), self._cs_node.tag())
        return [_tm.TagValue(xmltag=xmltag, v=v)]

    def __repr__(self):
        """Get internal representation."""
        tag = self._cs_node.tag()
        return "Leaf name=%s tag=%d cached=%s%s" % \
            (_tm.hash2str(tag), tag, self._cached,
             (" value=" + str(self.get_value())) if self._cached else "")

    def __nonzero__(self):
        """Return true if this leaf exists in the data tree."""
        return self.exists()

    def __bool__(self):
        """Return true if this leaf exists in the data tree."""
        return self.__nonzero__()

    def update_cache(self, force=False):
        """Read this leaf's value from the data tree and store it in the cache.

        There is no need to call this method explicitly.
        """
        if (force or not self._cached) and self._backend:
            self._set_cache(self._backend._get_elem(self._path))

    def set_cache(self, value):
        """Set the cached value of this leaf without updating the data tree.

        Use of this method is strongly discouraged.
        """
        value = _python_to_yang(value, self._cs_node)
        self._set_cache(value)

    def get_value(self):
        """Return the value of this leaf.

        The value is returned as the most appropriate python data type.
        """
        self.update_cache()
        if self._cached:
            return _yang_to_python(self._cache, self._cs_node)
        else:
            return None

    def get_value_object(self):
        """Return the value of this leaf as a Value object."""
        self.update_cache()
        return self._cache

    def set_value(self, value):
        """Set the value of this leaf.

        Arguments:

        * value -- the value to be set. If 'value' is not a Value object,
                it will be converted to one using Value.str2val.
        """
        if value is None:
            if self._backend and self._backend.exists(self._path):
                self._backend._delete(self._path)
                self._clear_cache()
            else:
                self._set_cache(None)
        else:
            value = _python_to_yang(value, self._cs_node)
            if self._backend:
                self._backend._set_elem(value, self._path)
                self._clear_cache()
            else:
                self._set_cache(value)

    def delete(self):
        """Delete this leaf from the data tree."""
        self.set_value(None)

    def exists(self):
        """Check if leaf exists.

        Return True if this leaf exists (has a value) in the data tree.
        """
        if self._cached:
            return self._cache is not None
        else:
            if self._backend:
                return self._backend._exists(self._path)
            else:
                return False

    def _from_tagvalues(self, tagvalues):
        """Update this leaf's cached value using tagvalue array 'tagvalues'."""
        self._set_cache(tagvalues[0].v)


class EmptyLeaf(Leaf):
    """Represents a leaf with the type "empty"."""

    def __init__(self, backend, cs_node, parent=None):
        """Initialize an EmptyLeaf node. Should not be called explicitly."""
        super(EmptyLeaf, self).__init__(backend, cs_node, parent=parent)

    def __repr__(self):
        """Get internal representation."""
        tag = self._cs_node.tag()
        return "Empty leaf name=%s tag=%d cached=%s%s" % \
            (_tm.hash2str(tag), tag, self._cached,
             (" exists=" + str(self._cache)) if self._cached else "")

    def __nonzero__(self):
        """Return True if this leaf exists in the data tree."""
        return self.exists()

    def __bool__(self):
        """Return True if this leaf exists in the data tree."""
        return self.__nonzero__()

    def _tagvalues(self):
        if self.exists():
            v = _tm.Value((self._cs_node.tag(), self._cs_node.ns()),
                          _tm.C_XMLTAG)
            xmltag = _tm.XmlTag(self._cs_node.ns(), self._cs_node.tag())
            return [_tm.TagValue(xmltag=xmltag, v=v)]
        else:
            return []

    def _from_tagvalues(self, tagvalues):
        """Set this leaf's cached value from tagvalue array 'tagvalues'."""
        if tagvalues:
            self._set_cache(True)

    def exists(self):
        """Return True if this leaf exists in the data tree."""
        if not self._cached and self._backend:
            self._set_cache(self._backend._exists(self._path))
        return (self._cache is True)

    def create(self):
        """Create and return this leaf in the data tree."""
        if self._cached and self._cache is True:
            return self
        if self._backend:
            if self._backend._shared:
                self._backend.create(self._path)
            else:
                if not self._backend.exists(self._path):
                    self._backend.create(self._path)
            self._clear_cache()
        else:
            self._set_cache(True)
        return self

    def delete(self):
        """Delete this leaf from the data tree."""
        if self._cached and not self._cache:
            return
        if self._backend:
            self._backend._delete(self._path)
            self._clear_cache()
        else:
            self._set_cache(None)


class List(Node):
    """Represents a list node.

    A list can be treated mostly like a python dictionary. It supports
    indexing, iteration, the len function, and the in and del operators.
    New items must, however, be created explicitly using the 'create' method.
    """

    def __init__(self, backend, cs_node, parent=None):
        """Initialize a List node. Should not be called explicitly."""
        super(List, self).__init__(backend, cs_node, parent=parent)
        self._set_attr('_cache', collections.OrderedDict())
        self._set_attr('_keyed', True if cs_node.info().keys() else False)

    def __len__(self):
        """Get the length of the list.

        Called when using 'len'.
        """
        if self._backend:
            return self._backend._num_instances(self._path)
        else:
            return len(self._cache)

    def __getitem__(self, keys):
        """Get a specific list item.

        Get a specific item from the list using [] notation.
        Return a ListElement representing the contents of the list at 'keys'.

        Arguments:

        * keys -- item keys (list[str] or maapi.Key )

        Returns:

        * list item (maagic.ListElement)
        """
        if not isinstance(keys, maapi.Key):
            keys = maapi.Key(keys)
        keystr = str(keys)
        if keystr in self._cache:
            return self._cache[keystr]
        elif (isinstance(self._backend, _MaapiBackend) or
              (isinstance(self._backend, _TransactionBackend) and
               self._backend._exists(self._path + keystr))):
            c = ListElement(self._backend, self._cs_node, parent=self)
            c._populate([k for k in keys])
            self._cache[keystr] = c
            return c
        else:
            raise KeyError('%s not in %s' % (keystr, self._path))

    def __iter__(self):
        """Python magic method.

        Return an iterator for the list. This method will be called e.g.
        when iterating the list like this:
            for item in mylist: ...
        """
        if self._backend:
            return ListIterator(self)
        else:
            return iter(self._cache.values())

    def __delitem__(self, keys):
        """Delete list item matching 'keys'.

        Called when deleting an item from the list.

        Example use:

            del mylist['key1']
        """
        if not self._backend and not self._keyed:
            raise MaagicError("Delete not available for " +
                              "keyless in-memory list")
        if not isinstance(keys, maapi.Key):
            keys = maapi.Key(keys)
        keystr = str(keys)
        if self._backend:
            if self._backend.exists(self._path + keystr):
                self._backend._delete(self._path + keystr)
        if keystr in self._cache:
            del self._cache[keystr]

    def __contains__(self, keys):
        """Check if list has an item matching 'keys'.

        Called when checking for existence using 'in' and 'not in'.
        """
        return self.exists(keys)

    def __setitem__(self, key, value):
        """Raise an error."""
        raise MaagicError("Must use create() method to create list items")

    def __repr__(self):
        """Get internal representation."""
        tag = self._cs_node.tag()
        return "List name=%s tag=%d" % (_tm.hash2str(tag), tag)

    def _tagvalues(self):
        acc = []
        for e in self:
            acc.extend(e._tagvalues())
        return acc

    def _from_tagvalues(self, tagvalues):
        # print "Building list " + repr(self) + " from " + str(tagvalues)
        # TODO: Why not use self.create() to create elements?
        listkeys = set()
        for child in _CsNodeIter(self._cs_node.children()):
            if child.is_key():
                listkeys.add(child.tag())

        if not listkeys:  # List has no keys, add it to the end of the list
            new = ListElement(self._backend, self._cs_node, parent=self)
            key = maapi.Key(len(self._cache))
            self._cache[str(key)] = new
            new._from_tagvalues(tagvalues)
        else:
            key = maapi.Key(_find_keys(listkeys, tagvalues[1:-1]))
            strkey = str(key)
            if strkey not in self._cache:
                new = ListElement(self._backend, self._cs_node, parent=self)
                self._cache[strkey] = new
                new._from_tagvalues(tagvalues)

    def exists(self, keys):
        """Check if list has an item matching 'keys'.

        Arguments:

        * keys -- item keys (list[str] or maapi.Key )

        Returns:

        * boolean
        """
        if not isinstance(keys, maapi.Key):
            keys = maapi.Key(keys)
        keystr = str(keys)
        if keystr in self._cache:
            return True
        elif self._backend:
            return self._backend._exists(self._path + keystr)
        return False

    def create(self, *keys):
        """Create and return a new list item with the key '*keys'.

        Arguments can be a single 'maapi.Key' object or one value for each key
        in the list. For a keyless oper or in-memory list (eg in action
        parameters), no argument should be given.

        Arguments:

        * keys -- item keys (list[str] or maapi.Key )

        Returns:

        * list item (maagic.ListElement)
        """
        if not self._keyed:
            if len(keys) != 0:
                raise MaagicError("For keyless list, use create()")
            keys = maapi.Key(len(self))
        elif len(keys) == 0:
            raise MaagicError("Missing key argument in create")
        elif len(keys) == 1:
            keys = maapi.Key(keys[0])
        else:
            keys = maapi.Key(keys)
        keystr = str(keys)
        if self._backend:
            path = self._path + keystr
            if self._backend._shared:
                self._backend.create(path)
            else:
                if not self._backend.exists(path):
                    self._backend.create(path)
            return self[keys]
        else:
            c = ListElement(self._backend, self._cs_node, parent=self)
            c._populate(keys)
            self._cache[keystr] = c
            return c

    def move(self, key, where, to=None):
        """Move the item with key 'key' in an ordered-by user list.

        The destination is given by the arguments 'where' and 'to'.

        Arguments:

        * key -- key of the element that is to be moved (str or maapi.Key)
        * where -- one of 'maapi.MOVE_BEFORE', 'maapi.MOVE_AFTER',
                   'maapi.MOVE_FIRST', or 'maapi.MOVE_LAST'

        Keyword arguments:

        * to -- key of the destination item for relative moves, only applicable
                if 'where' is either 'maapi.MOVE_BEFORE' or 'maapi.MOVE_AFTER'.
        """
        if not self._backend:
            raise MaagicError("Move is not available for in-memory list")
        if where in (_tm.maapi.MOVE_AFTER, _tm.maapi.MOVE_BEFORE) \
           and not to:
            raise MaagicError("to parameter is required for wanted move")
        if not isinstance(key, maapi.Key):
            key = maapi.Key(key)
        strkey = str(key)

        if to is not None:
            if not isinstance(to, (list, tuple)):
                to = [to]
            child = self._cs_node.children()
            kcs = [x for x in filter(lambda x: x.is_key(), _CsNodeIter(child))]
            if len(to) != len(kcs):
                raise MaagicError('wrong number of keys in parameter to')
            new_to = []
            for (val, cs_node) in zip(to, kcs):
                new_to.append(_python_to_yang(val, cs_node))
            to = new_to

        self._backend.move_ordered(where, to, self._path + strkey)

    def delete(self):
        """Delete the entire list."""
        if self._backend:
            self._backend._delete(self._path)
            self._clear_cache(collections.OrderedDict())
        else:
            self._set_cache(collections.OrderedDict())

    def keys(self, xpath_expr=None, secondary_index=None):
        """Return all keys in the list.

        Note that this will immediately retrieve every key value from the CDB.
        For a long list this could be a time-consuming operation. The keys
        selection may be filtered using 'xpath_expr' and 'secondary_index'.

        Not available for in-memory lists.

        Keyword arguments:

        * xpath_expr -- a valid XPath expression for filtering or None
                        (string, default: None) (optional)
        * secondary_index -- secondary index to use or None
                             (string, default: None) (optional)
        """
        if not self._backend:
            raise MaagicError("keys() is not available for in-memory list")
        enum_cs_nodes = self._key_enum_cs_nodes()
        cur = self._backend._cursor(self._path, enum_cs_nodes,
                                    want_values=False,
                                    secondary_index=secondary_index,
                                    xpath_expr=xpath_expr)
        return [x for x in cur]

    def _key_enum_cs_nodes(self):
        nodes = []
        child = self._cs_node.children()
        while child:
            if child.is_key():
                if (child.info().shallow_type() == _tm.C_ENUM_VALUE or
                        child.info().shallow_type() == _tm.C_UNION or
                        child.info().shallow_type() == _tm.C_IDENTITYREF or
                        child.info().shallow_type() == _tm.C_BINARY):
                    nodes.append(child)
                else:
                    nodes.append(None)
            child = child.next()
        return nodes

    def filter(self, xpath_expr=None, secondary_index=None):
        """Return a filtered iterator for the list.

        With this method it is possible to filter the selection using an XPath
        expression and/or a secondary index. If supported by the data provider,
        filtering will be done there.

        Not available for in-memory lists.

        Keyword arguments:

        * xpath_expr -- a valid XPath expression for filtering or None
                        (string, default: None) (optional)
        * secondary_index -- secondary index to use or None
                             (string, default: None) (optional)

        Returns:

        * iterator (maagic.ListIterator)
        """
        if self._backend:
            return ListIterator(self, secondary_index, xpath_expr)
        else:
            raise MaagicError("filter() is not available for in-memory lists")


class ListIterator(object):
    """List iterator.

    An instance of this class will be returned when iterating a list.
    """

    def __init__(self, l, secondary_index=None, xpath_expr=None):
        """Initialize this object.

        An instance of this class will be created when iteration of a
        list starts. Should not be called explicitly.
        """
        self._l = l
        self._cursor = l._backend._cursor(l._path,
                                          l._key_enum_cs_nodes(),
                                          want_values=False,
                                          secondary_index=secondary_index,
                                          xpath_expr=xpath_expr)

    def __iter__(self):
        """Return iterator (which is self)."""
        return self

    def __next__(self):
        """Iterator next."""
        return self.next()

    def __enter__(self):
        """Context manger entry point."""
        return self

    def __exit__(self, type_, value, tb):
        """Context manger exit point."""
        self.delete()

    def __del__(self):
        """Destructor. Destroy internal object."""
        self.delete()

    def next(self):
        """Get the next value from the iterator."""
        k = self._cursor.next()
        return self._l[k]

    def delete(self):
        """Delete the iterator."""
        if self._cursor is not None:
            self._cursor.delete()
            self._cursor = None


class ListElement(Container):
    """Represents a list element.

    This is a Container object with a specialized __repr__() method.
    """

    def __repr__(self):
        """Get internal representation."""
        tag = self._cs_node.tag()
        keystr = self.__dict__['_keystr']
        if keystr:
            return "ListElement name=%s tag=%d keys=%s" % (_tm.hash2str(tag),
                                                           tag, keystr)
        else:
            return "ListElement name=%s tag=%d" % (_tm.hash2str(tag), tag)


class LeafList(Leaf):
    """Represents a leaf-list node."""

    def __init__(self, backend, cs_node, parent=None):
        """Initialize a LeafList node. Should not be called explicitly."""
        super(LeafList, self).__init__(backend, cs_node, parent=parent)

    def __repr__(self):
        """Get internal representation."""
        tag = self._cs_node.tag()
        return "LeafList name=%s tag=%d" % (_tm.hash2str(tag), tag)

    def __iter__(self):
        """Python magic method.

        Return an iterator for the leaf-list. This method will be called e.g.
        when iterating the leaf-list like this:
            for item in myleaflist: ...
        """
        if self._backend:
            return LeafListIterator(self)
        else:
            return iter(self._cache) if self._cache else iter([])

    def __len__(self):
        """Get the length of the leaf-list.

        Called when using 'len'.
        """
        if self._backend:
            return self._backend._num_instances(self._path)
        else:
            return len(self._cache) if self._cache else 0

    def __delitem__(self, key):
        """Remove a specific leaf-list item'."""
        self.remove(key)

    def __nonzero__(self):
        """Return true if this leaf-list exists in the data tree."""
        return self.exists()

    def __bool__(self):
        """Return true if this leaf-list exists in the data tree."""
        return self.exists()

    def __eq__(self, other):
        """Check for equality.

        A LeafList node is considered equal to the following objects:
        - Any LeafList node that contains the same values as this node
        - Any list object that containes the same values as this node
        - None if this node doesn't exist
        """
        if isinstance(other, LeafList):
            return self.as_list() == other.as_list()
        if isinstance(other, list):
            return self.as_list() == other
        if other is None and not self.exists():
            return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def _tagvalues(self):
        plist = self.as_list()
        if plist:
            v = _python_to_yang(plist, self._cs_node)
            xmltag = _tm.XmlTag(self._cs_node.ns(), self._cs_node.tag())
            return [_tm.TagValue(xmltag=xmltag, v=v)]

        return []

    def _from_tagvalues(self, tagvalues):
        v = tagvalues[0].v
        pylist = v.as_pyval()
        self.set_value(pylist)

    def exists(self):
        """Return true if the leaf-list exists (has values) in the data tree.

        Example use:

            if root.model.ll.exists():
                do_things()
        """
        if self._backend:
            return self._backend.exists(self._path)
        if self._cache:
            return True
        return False

    def get_value(self):
        """Return this leaf-list."""
        if _want_leaf_list_as_leaf():
            return self.as_list() or None
        return self

    def set_value(self, value):
        """Set this leaf-list using a python list."""
        if isinstance(value, str):
            raise MaagicError('Argument must be a non-string iterable.')
        if value is not None and not hasattr(value, '__iter__'):
            raise MaagicError('Argument must be a non-string iterable.')
        if self._backend:
            self.delete()
            if value is not None:
                for item in value:
                    self.create(item)
        else:
            self._set_cache(value)

    def create(self, key):
        """Create a new leaf-list item.

        Arguments:

        * key -- item key (str or maapi.Key)

        Example use:

            root.model.ll.create('example')
        """
        if self._backend:
            path = self._path + str(maapi.Key(key))
            if self._backend._shared:
                self._backend.create(path)
            elif not self._backend.exists(path):
                self._backend.create(path)
        else:
            newlist = self._cache or []
            if key not in newlist:
                newlist.append(key)
            self._set_cache(newlist)

    def remove(self, key):
        """Remove a specific leaf-list item'.

        Arguments:

        * key -- item key (str or maapi.Key)

        Example use:

            root.model.ll.remove('example')
        """
        if self._backend:
            keystr = str(maapi.Key(key))
            path = self._path + keystr
            if self._backend._shared:
                self._backend.delete(path)
            elif self._backend.exists(path):
                self._backend.delete(path)
        elif self._cache:
            self._cache.remove(key)

    def delete(self):
        """Delete the entire leaf-list.

        Example use:

            root.model.ll.delete()
        """
        if self._backend:
            self._backend._delete(self._path)
        else:
            self._set_cache(None)

    def as_list(self):
        """Return leaf-list values in a list.

        Returns:

        * leaf list values (list)

        Example use:

            root.model.ll.as_list()
        """
        return [x for x in self]


class LeafListIterator(ListIterator):
    """LeafList iterator.

    An instance of this class will be returned when iterating a leaf-list.
    """

    def __init__(self, l):
        """Initialize this object.

        An instance of this class will be created when iteration of a
        leaf-list starts. Should not be called explicitly.
        """
        self._type = _tm.get_leaf_list_type(l._cs_node)
        self._cursor = l._backend._cursor(l._path, enum_cs_nodes=None,
                                          want_values=True,
                                          secondary_index=None,
                                          xpath_expr=None)

    def next(self):
        """Get the next value from the iterator."""
        key = self._cursor.next()[0]
        if key.confd_type() == _tm.C_ENUM_VALUE:
            keystr = key.val2str(self._type)
            return Enum(keystr, int(key))
        else:
            return key.as_pyval()


class Action(Node):
    """Represents a tailf:action node."""

    def __init__(self, backend, cs_node, parent=None):
        """Initialize an Action node. Should not be called explicitly."""
        super(Action, self).__init__(backend, cs_node, parent=parent)

    def __repr__(self):
        """Get internal representation."""
        tag = self._cs_node.tag()
        return "Action name=%s tag=%d" % (_tm.hash2str(tag), tag)

    def get_input(self):
        """Return a node tree representing the input node of this action.

        Returns:

        * action inputs (maagic.ActionParams)
        """
        return ActionParams(self._cs_node, parent=None)

    def get_output(self):
        """Return a node tree representing the output node of this action.

        Note that this does not actually request the action.
        Should not normally be called explicitly.

        Returns:

        * action outputs (maagic.ActionParams)
        """
        return ActionParams(self._cs_node, parent=None, output=True)

    def request(self, params=None):
        """Request the action and return the result as an ActionParams node.

        Arguments:

        * params -- input parameters of the action (maagic.ActionParams,
                    optional)

        Returns:

        * outparams -- output parameters of the action (maagic.ActionParams)
        """
        if not self._backend:
            raise MaagicError("Cannot request action without backend")
        tv = params._tagvalues() if params else []
        output = self._backend._request_action(tv, 0, self._path)
        outparams = ActionParams(self._cs_node, parent=None, output=True)
        outparams._from_tagvalues(output)
        return outparams

    def __call__(self, params=None):
        """Make object callable. Calls request()."""
        return self.request(params)


class ActionParams(Node):
    """Represents the input or output parameters of a tailf:action.

    The ActionParams node is the root of a tree representing either the input
    or the output parameters of an action. Action parameters can be read and
    set just like any other nodes in the tree.
    """

    def __init__(self, cs_node, parent, output=False):
        """Initialize an ActionParams node.

        Should not be called explicitly. Use 'get_input()' on an Action node
        to retrieve its input parameters or 'request()' to request the action
        and obtain the output parameters.
        """
        self._set_attr('_output', output)
        super(ActionParams, self).__init__(None, cs_node,
                                           parent=parent, is_root=True)

    def _populate(self):
        if self._populated:
            return
        self._set_attr('_populated', True)
        self._set_attr('_path', '')
        ns = _tm.ns2prefix(self._cs_node.ns())
        forbidden = dir(super(ActionParams, self))
        self._set_attr('_children',
                       childlist._ChildList(ns, forbidden, _make_node))

        child = self._cs_node.children()
        predicate = (lambda x: x.is_action_result()) if self._output \
            else (lambda x: x.is_action_param())
        _add_children(self, _CsNodeIter(child), predicate=predicate)

    def _from_tagvalues(self, tagvalues):
        _from_tagvalues(self, tagvalues)

    def _tagvalues(self):
        tv = []
        for child in self._children.get_children(self._backend, self):
            tv.extend(child._tagvalues())
        return tv


class Choice(Node):
    """Represents a choice node."""

    def __init__(self, backend, cs_node, cs_choice, parent):
        """Initialize a Choice node. Should not be called explicitly."""
        super(Choice, self).__init__(backend, cs_node, parent)
        self._set_attr('_cs_choice', cs_choice)

    def _populate(self):
        if self._populated:
            return
        self._set_attr('_populated', True)

        self._set_attr('_name', _tm.hash2str(self._cs_choice.tag()))
        self._set_attr('_path', self._parent._path)
        if isinstance(self._parent, Case):
            if self._cs_choice.ns() != self._parent._cs_case.ns():
                myname = '%s:%s' % (_tm.ns2prefix(self._cs_choice.ns()),
                                    self._name)
            else:
                myname = self._name
            self._set_attr('_full_name', "%s/%s/%s" % (
                self._parent._parent._full_name,
                self._parent._name,
                myname))
        else:
            self._set_attr('_full_name', self._name)
            if self._cs_choice.ns() != self._cs_node.ns():
                prefix = _tm.ns2prefix(self._cs_choice.ns())
                self._set_attr('_full_name', "%s:%s" % (prefix, self._name))

    def __repr__(self):
        """Get internal representation."""
        tag = self._cs_choice.tag()
        return "Choice name=%s tag=%d" % (_tm.hash2str(tag), tag)

    def __str__(self):
        """Get string representation."""
        return _tm.hash2str(self._cs_choice.tag())

    def __int__(self):
        """Get int representation (tag value)."""
        return self._cs_choice.tag()

    def get_value(self):
        """Return the currently selected case of this choice.

        The case is returned as a Case node. If no case is selected for this
        choice, None is returned.

        Returns:

        * current selection of choice (maagic.Case)
        """
        if self._backend:
            try:
                case = self._backend.get_case(self._full_name, self._path)
            except _tm.error.Error as e:
                if e.confd_errno == _tm.ERR_NOEXISTS:
                    return None  # No case set
                else:
                    raise e
            tag = case.as_xmltag().tag
            cn = self._cs_choice.cases()
            while cn:
                if cn.tag() == tag:
                    break
                cn = cn.next()
            node = Case(self._backend, self._cs_node, cn, self)
            return node

        raise MaagicError(
            'Cannot get active case of in-memory choice {}'.format(self._name))


class Case(Node):
    """Represents a case node.

    If this case node has any nested choice nodes, those will appear as
    children of this object.
    """

    def __init__(self, backend, cs_node, cs_case, parent):
        """Initialize a Case node. Should not be called explicitly."""
        super(Case, self).__init__(backend, cs_node, parent)
        self._set_attr('_cs_case', cs_case)

    def _populate(self):
        if self._populated:
            return
        self._set_attr('_populated', True)

        self._set_attr('_path', self._parent._path)
        self._set_attr('_name', _tm.hash2str(self._cs_case.tag()))
        ns = _tm.ns2prefix(self._cs_case.ns())
        forbidden = dir(super(Case, self))
        self._set_attr('_children',
                       childlist._ChildList(ns, forbidden, _make_node))

        if self._cs_case.ns() != self._parent._cs_choice.ns():
            self._set_attr('_full_name',
                           '%s:%s' % (_tm.ns2prefix(self._cs_case.ns()),
                                      self._name))
        else:
            self._set_attr('_full_name', self._name)

        choice = self._cs_case.choices()
        _add_children(self, _CsNodeIter(choice))

    def __repr__(self):
        """Get internal representation."""
        tag = self._cs_case.tag()
        return "Case name=%s tag=%d" % (_tm.hash2str(tag), tag)

    def __str__(self):
        """Get string representation."""
        return _tm.hash2str(self._cs_case.tag())

    def __int__(self):
        """Get int representation (tag value)."""
        return self._cs_case.tag()

    def __eq__(self, other):
        """Check for equality.

        A Case node is considered equal to the following objects:
        - Any number type object that matches the tag value of this case
        - Any string object that matches the yang name of this case
        - Any object with string and int representations that both match those
          of this case.
        """
        if isinstance(other, numbers.Number) and not isinstance(other, bool):
            return int(self) == other
        elif isinstance(other, str):
            return str(self) == other
        else:
            return int(self) == int(other) and str(self) == str(other)

    def __ne__(self, other):
        """Check for inequality."""
        return not self.__eq__(other)


def cd(node, path):
    """Return the node at path 'path', starting from node 'node'.

    Arguments:

    * path -- relative or absolute keypath as a string (HKeypathRef or
              maagic.Node)

    Returns:

    * node (maagic.Node)
    """
    if isinstance(path, Node):
        path = path._path
    else:
        path = str(path)

    if path.startswith('/'):
        while node._parent:
            node = node._parent

    for child in keypath._parse(path):
        if child == ".":
            continue
        elif child == "..":
            p = node._parent
            if p._parent is not None and p._cs_node is node._cs_node:
                # Take an extra step if we are backing out of a list item
                p = p._parent
            node = p
        else:
            if isinstance(child, list):
                # Child has a prefix
                child = ":".join(child)

            node = node[child]

    return node


class _CsNodeIter(object):
    def __init__(self, cs_node):
        self._cs_node = cs_node

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        if self._cs_node is None:
            raise StopIteration()
        ret = self._cs_node
        self._cs_node = self._cs_node.next()
        return ret


def _add_children(obj, childiter, predicate=lambda x: True):
    for child in childiter:
        if predicate(child):
            childname = _tm.hash2str(child.tag())
            childns = _tm.ns2prefix(child.ns())
            obj._children.add(child, childns, childname)


def _add_cached_children(children, cached_children):
    for child, childns, childname in cached_children:
        children.add(child, childns, childname)


def _tagvalues_to_container(c, tagvalues):
    _from_tagvalues(c, tagvalues[1:-1])


def _from_tagvalues(obj, tagvalues):
    taglookup = {}
    for child in obj._children.get_children(obj._backend, obj):
        taglookup[child._cs_node.tag()] = child
    tv = _split_tagvalues(tagvalues)
    for tags in tv:
        tag = tags[0].tag
        child = taglookup[tag]
        child._from_tagvalues(tags)


# Find the key elements from a list of tagvalue arrays
def _find_keys(listkeys, tagvalues):
    keys = []
    expected = len(listkeys)
    for tv in tagvalues:
        if tv.tag in listkeys:
            keys.append(tv.v)
            expected -= 1
            if expected == 0:
                break
    else:
        raise MaagicError("Missing keys in list")
    return keys


# Split a list of tagvalues into a list of lists.
# Each sublist containing all the tagvalues for an entire node or list element.
# ie [ <a/>, <b>, <c/>, </b>, <d/> ] -> [ [<a/>], [<b>,<c/>,</b>], [<d/>] ]
def _split_tagvalues(tagvalues):
    i = iter(tagvalues)
    acc = []
    try:
        t = next(i)
        while t:
            if t.v and t.v.confd_type() == _tm.C_XMLBEGIN:
                depth = 1
                block = [t]
                while depth > 0:
                    t = next(i)
                    block.append(t)
                    if t.v and t.v.confd_type() == _tm.C_XMLBEGIN:
                        depth += 1
                    elif t.v and t.v.confd_type() == _tm.C_XMLEND:
                        depth -= 1
                acc.append(block)
            else:
                acc.append([t])
            t = next(i)
    except StopIteration:
        return acc


def get_node(backend, path, shared=False):
    """Return the node at path 'path' using 'backend'.

    Arguments:

    * backend -- backend object (maapi.Transaction, maapi.Maapi or None)
    * path -- relative or absolute keypath as a string (HKeypathRef or
              maagic.Node)
    * shared -- if set to 'True', fastmap-friendly maapi calls, such as
                shared_set_elem, will be used within the returned tree (boolean)

    Example use:

        node = ncs.maagic.get_node(t, '/ncs:devices/device{ce0}')
    """
    root = get_root(backend, shared)
    return cd(root, path)


def _make_node(trans, cs_node, parent=None):
    if isinstance(cs_node, _tm.CsChoice):
        return Choice(trans, cs_node.parent(), cs_node, parent)
    elif cs_node.is_np_container():
        return Container(trans, cs_node, parent)
    elif cs_node.is_p_container():
        return PresenceContainer(trans, cs_node, parent)
    elif cs_node.is_list():
        return List(trans, cs_node, parent)
    elif cs_node.is_non_empty_leaf():
        return NonEmptyLeaf(trans, cs_node, parent)
    elif cs_node.is_empty_leaf():
        return EmptyLeaf(trans, cs_node, parent)
    elif cs_node.is_leaf_list():
        return LeafList(trans, cs_node, parent)
    elif cs_node.is_action():
        return Action(trans, cs_node, parent)


def _yang_to_python(value, schema_node):
    if value is None:
        return None
    elif value.confd_type() == _tm.C_ENUM_VALUE:
        string = value.val2str(schema_node)
        value = int(value)
        return Enum(string, value)
    elif value.confd_type() == _tm.C_BITBIG:
        return Bits(value, schema_node)
    elif value.confd_type() == _tm.C_OBJECTREF:
        return value.val2str(schema_node)
    elif value.confd_type() == _tm.C_IDENTITYREF:
        return value.val2str(schema_node)
    else:
        return value.as_pyval()


def _python_to_yang(value, cs_node):
    if isinstance(value, _tm.Value):
        return value
    t = cs_node.info().shallow_type()
    if t == _tm.C_LIST:
        cs_type = _tm.get_leaf_list_type(cs_node)
        return _list_to_leaflist(value, cs_type)

    if t == _tm.C_ENUM_VALUE:
        if isinstance(value, numbers.Number) and not isinstance(value, bool):
            return _tm.Value(value, _tm.C_ENUM_VALUE)

    if t == _tm.C_BINARY:
        return _tm.Value(value, _tm.C_BINARY)

    if t == _tm.C_BIT32 and (isinstance(value, numbers.Number) and not
                             isinstance(value, bool)):
        return _tm.Value(value, _tm.C_BIT32)

    if t == _tm.C_BIT64 and (isinstance(value, numbers.Number) and not
                             isinstance(value, bool)):
        return _tm.Value(value, _tm.C_BIT64)

    if t == _tm.C_BITBIG:
        def _resize_bb_val(value):
            add_sz = (cs_node.info().type().bitbig_size() - len(value))
            if isinstance(value, bytearray):
                value.extend(0 for _ in range(0, add_sz))
                return value
            else:
                return value + b'\x00' * add_sz

        if t == _tm.C_BITBIG and isinstance(value, bytes):
            return _tm.Value(_resize_bb_val(value), _tm.C_BITBIG)

        if isinstance(value, Bits):
            return _tm.Value(_resize_bb_val(value.bytearray()),
                             _tm.C_BITBIG)
        if isinstance(value, bytearray):
            return _tm.Value(_resize_bb_val(value), _tm.C_BITBIG)

    if isinstance(value, bool):
        value = 'true' if value else 'false'

    return _tm.Value.str2val(str(value), cs_node)


def _list_to_leaflist(value, cs_type):
    list_ = []
    for v in value:
        if not isinstance(v, _tm.Value):
            if isinstance(v, bool):
                v = 'true' if v else 'false'
            else:
                v = str(v)
            v = _tm.Value.str2val(v, cs_type)
        list_.append(v)
    return _tm.Value(list_, _tm.C_LIST)


def get_root(backend=None, shared=False):
    """Return a Root object for 'backend'.

    If 'backend' is a Transaction object, the returned Maagic object can be
    used to read and write transactional data. When 'backend' is a Maapi
    object you cannot read and write data, however, you may use the Maagic
    object to call an action (that doesn't require a transaction).
    If 'backend' is a Node object the underlying Transaction or Maapi object
    will be used (if any), otherwise backend will be assumed to be None.
    'backend' may also be None (default) in which case the returned Maagic
    object is not connected to NCS in any way. You can still use the maagic
    object to build an in-memory tree which may be converted to an array
    of TagValue objects.

    Arguments:

    * backend -- backend object (maagic.Node, maapi.Transaction, maapi.Maapi
                or None)
    * shared -- if set to 'True', fastmap-friendly maapi calls, such as
                shared_set_elem, will be used within the returned tree (boolean)

    Returns:

    * root node (maagic.Root)

    Example use:

        with ncs.maapi.Maapi() as m:
            with ncs.maapi.Session(m, 'admin', 'python'):
                root = ncs.maagic.get_root(m)
    """
    if isinstance(backend, Node):
        try:
            backend = get_trans(backend)
        except BackendError:
            try:
                backend = get_maapi(backend)
            except BackendError:
                backend = None

    if backend and 'maagic_object' in backend.__dict__:
        return backend.__dict__['maagic_object']
    else:
        if isinstance(backend, maapi.Transaction):
            backend_server = _TransactionBackend(backend)
            if shared:
                backend_server._set_shared()
        elif isinstance(backend, maapi.Maapi):
            backend_server = _MaapiBackend(backend)
        else:
            backend_server = None
        maagic = Root(backend_server)
        if backend:
            backend.__dict__['maagic_object'] = maagic
        return maagic


def get_maapi(obj):
    """Get Maapi object from obj.

    Return Maapi object from obj. raise BackendError if
    provided object does not contain a Maapi object.

    Arguements:

    * object (obj)

    Returns:

    * maapi object (maapi.Maapi)
    """
    if isinstance(obj, maapi.Maapi):
        return obj
    if hasattr(obj, '_backend') and obj._backend is None:
        raise BackendError("Not a Maapi or Transaction backend")
    return obj._backend.maapi


def get_trans(node_or_trans):
    """Get Transaction object from node_or_trans.

    Return Transaction object from node_or_trans. Raise BackendError if
    provided object does not contain a Transaction object.
    """
    if isinstance(node_or_trans, maapi.Transaction):
        return node_or_trans
    if not (hasattr(node_or_trans, '_backend') and
            hasattr(node_or_trans._backend, 'trans')):
        raise BackendError("Not a Transaction backend")
    return node_or_trans._backend.trans


def as_pyval(mobj, name_type=NODE_NAME_PY_SHORT,
             include_oper=False, enum_as_string=True):
    """Convert maagic object to python value.

    The types are converted as follows:

    * List is converted to list.
    * Container is converted to to dict.
    * Leaf is converted to python value.
    * EmptyLeaf is converted to bool.

    If include_oper is False and and a oper Node is
    passed None is returned.

    Arguments:

    * mobj -- maagic object (maagic.Enum, maagic.Bits, maagic.Node)
    * name_type -- one of NODE_NAME_SHORT, NODE_NAME_FULL,
    NODE_NAME_PY_SHORT and NODE_NAME_PY_FULL and controls dictionary
    key names
    * include_oper -- include operational data (boolean)
    * enum_as_string -- return enumerator in str form (boolean)

    """
    if mobj is None or not isinstance(mobj, (Enum, Bits, Node)):
        return mobj

    if hasattr(mobj, '_backend'):
        if mobj._backend is None:
            raise BackendError("Not a Transaction backend")
        trans = mobj._backend
    else:
        trans = None

    def is_oper(obj):
        return (hasattr(obj, '_cs_node')
                and obj._cs_node is not None
                and obj._cs_node.is_oper())

    def is_action(obj):
        return (hasattr(obj, '_cs_node')
                and obj._cs_node is not None
                and obj._cs_node.is_action())

    if (is_action(mobj)
            or (is_oper(mobj) and not include_oper)):
        return None

    if isinstance(mobj, List):
        value = []
        for mobj_value in mobj:
            value.append(as_pyval(
                mobj_value, name_type, include_oper))
        return value

    if isinstance(mobj, (Container, Root)):
        if (isinstance(mobj, PresenceContainer)
                and not mobj.exists()):
            return None

        def get_child_name(child):
            if name_type == NODE_NAME_PY_FULL:
                return child.py_full_name
            if name_type == NODE_NAME_PY_SHORT:
                return child.py_short_name
            if name_type == NODE_NAME_SHORT:
                return child.short_name
            return '%s:%s' % (child.ns, child.short_name)

        value = {}
        for child in mobj._children.children.values():
            if not hasattr(mobj, child.py_full_name):
                continue

            # ensure obj is loaded
            mobj._children.get_by_py(trans, mobj, child.py_full_name)
            if (not is_action(child.obj)
                    and not isinstance(child.obj, Choice)
                    and (include_oper or not is_oper(child.obj))):
                node = getattr(mobj, child.py_full_name)
                value[get_child_name(child)] = as_pyval(
                    node, name_type, include_oper)
        return value

    if isinstance(mobj, LeafList):
        return mobj.as_list()

    if isinstance(mobj, NonEmptyLeaf):
        return mobj.get_value()

    if isinstance(mobj, EmptyLeaf):
        return mobj.exists()

    if isinstance(mobj, Enum):
        if enum_as_string:
            return str(mobj)
        return int(mobj)

    if isinstance(mobj, Case):
        return str(mobj)

    if isinstance(mobj, Bits):
        return mobj.bytearray()

    raise TypeError('unsupported type %s' % (type(mobj), ))
