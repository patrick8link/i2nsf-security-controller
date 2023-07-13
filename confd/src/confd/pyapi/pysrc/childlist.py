"""Internally used classes and functions."""

import collections
import unittest
import keyword


class _Child(object):
    def __init__(self, cs_node, ns, short_name,
                 py_full_name, py_short_name, discouraged):
        self.cs_node = cs_node
        self.ns = ns
        self.short_name = short_name
        self.py_full_name = py_full_name
        self.py_short_name = py_short_name
        self.discouraged = discouraged
        self.obj = None

    def shallow_copy(self):
        return _Child(self.cs_node, self.ns, self.short_name,
                      self.py_full_name, self.py_short_name,
                      self.discouraged)


# _ChildList
# Maintains a list of children, and allows them to be addressed using their
# yang identifiers as well as python-friendly identifiers which can be used
# in __getattr__ overrides.
# Useful for container nodes, list items, action parameters and case nodes.
#
# The _ChildList is created with a namespace prefix and a list of values which
# cannot be used as python identifiers, typically the caller will pass
# dir(self) as forbidden.
# A child node is associated with four different strings:
# ns            - The namespace prefix of the child.
# short_name    - The yang identifier of the child.
# py_short_name - Mangled python variant of short_name
# py_full_name  - Mangled python variant of ns:short_name, typically looks like
#                 ns__short_name
#
# The child also has a flag, discouraged, which is set if usage of the short
# name is discouraged, ie it is unique but belongs to a foreign namespace.
#
# A node is added by calling add([ns], short_name, object).
# If ns is left out it is assumed to be equal to _ChildList.ns.
# if "ns:short_name" collides with a previous entry an exception is raised.
#
# Collision handling
# To generate the python friendly names, the characters '-' and '.' are
# replaced with '_'.
# If the generated name is a python keyword or exists in the list of forbidden
# identifiers, the following occurs:
#  short names - The name is discarded and the node gets no short python name
#  full names  - Underscores are appended to the name until it is acceptable
#
# Generally, if a new python name collides with an existing python name, an
# underscore is appended to the new name.
# However, if a short name collides with a long name, the short name will
# always be discarded, whether it belonged to the new or the previously
# existing item.
#
# Retrieving items
# Items can be retrieved using the methods get_by_yang and get_by_py.
# Both methods support full as well as short names.
# List notation can be used as a shorthand for get_by_py, ie
# c["node"] is equivalent to c.get_by_by("node")

class _ChildList(object):
    def __init__(self, ns, forbidden, mk_node):
        self.ns = ns
        self.forbidden = set(forbidden)
        self.short_name_to_full_name = {}
        self.py_short_name_to_full_name = {}
        self.py_full_name_to_full_name = {}
        self.discarded_short_names = set()
        self.children = collections.OrderedDict()
        # child object constructor for lazy construction
        self._mk_node = mk_node

    def shallow_copy(self):
        child_list_copy = _ChildList(self.ns, self.forbidden, self._mk_node)
        child_list_copy.short_name_to_full_name = self.short_name_to_full_name
        child_list_copy.py_short_name_to_full_name = \
            self.py_short_name_to_full_name
        child_list_copy.py_full_name_to_full_name = \
            self.py_full_name_to_full_name
        child_list_copy.discarded_short_names = self.discarded_short_names
        child_list_copy.children = collections.OrderedDict(
            [(full_name, c.shallow_copy())
             for full_name, c in self.children.items()])
        return child_list_copy

    def add(self, cs_node, ns, short_name):
        if ns is None:
            ns = self.ns

        full_name = "%s:%s" % (ns, short_name)
        if full_name in self.children:
            raise ValueError("Name already exists in list")

        py_short_name = self.short_python_name(short_name)
        discouraged = (ns != self.ns)
        py_full_name = self.full_python_name(ns, short_name)

        # All names generated, check for collisions
        while py_short_name:
            if py_short_name in self.py_full_name_to_full_name:
                py_short_name = None
            elif py_short_name in self.py_short_name_to_full_name:
                if discouraged:
                    name = self.full_name_from_py_short_name(py_short_name)
                    if self.children[name].discouraged:
                        self.discard_py_short_name(py_short_name)
                        py_short_name = None
                    else:
                        py_short_name = None
                else:
                    name = self.full_name_from_py_short_name(py_short_name)
                    if self.children[name].discouraged:
                        self.discard_py_short_name(py_short_name)
                    else:
                        py_short_name = self.next_name(py_short_name + '_')
            else:
                break

        while True:
            if py_full_name in self.py_full_name_to_full_name:
                py_full_name = self.next_name(py_full_name + '_')
            elif py_full_name in self.py_short_name_to_full_name:
                self.discard_py_short_name(py_full_name)
                break
            else:
                break

        # All conflicts resolved, store the object in all appropriate dicts
        if ns == self.ns:
            self.short_name_to_full_name[short_name] = full_name
        else:
            if short_name not in self.short_name_to_full_name and \
               short_name not in self.discarded_short_names:
                self.short_name_to_full_name[short_name] = full_name
            elif short_name not in self.discarded_short_names:
                sn_full_name = self.full_name_from_short_name(short_name)
                if self.children[sn_full_name].ns != self.ns:
                    self.discard_short_name(short_name)

        if py_short_name:
            self.py_short_name_to_full_name[py_short_name] = full_name
        self.py_full_name_to_full_name[py_full_name] = full_name

        self.children[full_name] = _Child(
            cs_node, ns, short_name, py_full_name, py_short_name, discouraged)

    def discard_short_name(self, short_name):
        self.discarded_short_names.add(short_name)
        if short_name in self.short_name_to_full_name:
            del self.short_name_to_full_name[short_name]

    def discard_py_short_name(self, py_short_name):
        if py_short_name in self.py_short_name_to_full_name:
            full_name = self.full_name_from_py_short_name(py_short_name)
            self.children[full_name].py_short_name = None
            del self.py_short_name_to_full_name[py_short_name]

    def next_name(self, name):
        while keyword.iskeyword(name) or name in self.forbidden:
            name += '_'
        return name

    def full_python_name(self, ns, name):
        ns = ns.replace('-', '_').replace('.', '_')
        name = name.replace('-', '_').replace('.', '_')
        n = "%s__%s" % (ns, name)
        return self.next_name(n)

    def short_python_name(self, name):
        name = name.replace('-', '_').replace('.', '_')
        if keyword.iskeyword(name) or name in self.forbidden:
            return None
        return name

    def get_by_yang(self, trans, parent, name):
        if ':' not in name:
            name = self.full_name_from_short_name(name)
        return self._get_obj(trans, parent, self.children[name])

    def get_by_py(self, trans, parent, py_name):
        if py_name in self.py_short_name_to_full_name:
            full_name = self.full_name_from_py_short_name(py_name)
        else:
            full_name = self.full_name_from_py_full_name(py_name)
        return self._get_obj(trans, parent, self.children[full_name])

    def has_py_name(self, py_name):
        return (py_name in self.py_short_name_to_full_name
                or py_name in self.py_full_name_to_full_name)

    def get_shortest_py_names(self):
        return [(not c.discouraged) and c.py_short_name or
                c.py_full_name for c in self.children.values()]

    def get_children(self, trans, parent):
        return [self._get_obj(trans, parent, c)
                for c in self.children.values()]

    def __contains__(self, item):
        return self.has_py_name(item)

    def full_name_from_short_name(self, short_name):
        return self.short_name_to_full_name[short_name]

    def full_name_from_py_short_name(self, py_short_name):
        return self.py_short_name_to_full_name[py_short_name]

    def full_name_from_py_full_name(self, py_full_name):
        return self.py_full_name_to_full_name[py_full_name]

    def _get_obj(self, trans, parent, child):
        if child.obj is None:
            child.obj = self._mk_node(trans, child.cs_node, parent)
        return child.obj


#
# UNIT TESTS
#
class _TestChildList(unittest.TestCase):

    def test_childlist(self):
        def mk_node(trans, cs_node, parent):
            return cs_node

        trans = None
        parent = None
        c = _ChildList("ns", ["ns__forbidden", "ns__forbidden_"], mk_node)
        c.add(0, None, "aegg")
        with self.assertRaises(ValueError):
            c.add(None, None, "aegg")
        with self.assertRaises(ValueError):
            c.add(None, "ns", "aegg")

        c.add(1, "ns", "flork")
        c.add(2, "x", "flork")
        c.add(3, None, "a_b")
        c.add(4, None, "a-b")
        c.add(5, None, "a.b")

        self.assertEqual(c.get_by_py(trans, parent, "a_b"),
                         c.get_by_yang(trans, parent, "ns:a_b"))
        self.assertEqual(c.get_by_py(trans, parent, "a_b_"),
                         c.get_by_yang(trans, parent, "ns:a-b"))
        self.assertEqual(c.get_by_py(trans, parent, "a_b__"),
                         c.get_by_yang(trans, parent, "a.b"))

        c.add(6, None, "bar__k")
        c.add(7, "bar", "k")

        self.assertEqual(c.get_by_py(trans, parent, "bar__k"), 7)

        c.add(8, None, "class")

        with self.assertRaises(KeyError):
            c.get_by_py(trans, parent, "class")

        c.add(9, None, "forbidden")

        self.assertEqual(c.get_by_py(trans, parent, "ns__forbidden__"), 9)

        names = [x for x in c.get_shortest_py_names()]
        self.assertIn("aegg", names)
        self.assertIn("ns__class", names)
        self.assertIn("ns__bar__k", names)

        self.assertIn("bar__k", c)

        self.assertEqual([0,1,2,3,4,5,6,7,8,9], c.get_children(trans, parent))

    def test_childlist_short_name(self):
        def mk_node(trans, cs_node, parent):
            return cs_node

        trans = None
        parent = None
        c = _ChildList("ns", [], mk_node)

        c.add(1, "other", "bark")
        self.assertEqual(c.get_by_yang(trans, parent, "bark"), 1)

        c.add(2, "ns", "bark")
        self.assertEqual(c.get_by_yang(trans, parent, "bark"), 2)

        c.add(3, "other2", "flork")
        self.assertEqual(c.get_by_yang(trans, parent, "flork"), 3)

        c.add(4, "other3", "flork")
        with self.assertRaises(KeyError):
            c.get_by_yang(trans, parent, "flork")

        c.add(5, "other4", "flork")
        with self.assertRaises(KeyError):
            c.get_by_yang(trans, parent, "flork")

    def test_discouraged(self):
        def mk_node(trans, cs_node, parent):
            return cs_node

        trans = None
        parent = None
        c = _ChildList("ns", [], mk_node)

        c.add(1, "other", "a")
        self.assertEqual(c.get_shortest_py_names(), ["other__a"])
        self.assertEqual(c.get_by_py(trans, parent, "a"), 1)

        c.add(2, "other2", "a")
        self.assertEqual(c.get_shortest_py_names(), ["other__a", "other2__a"])
        with self.assertRaises(KeyError):
            c.get_by_py(trans, parent, "a")

        c.add(3, None, "a")
        self.assertEqual(c.get_shortest_py_names(),
                         ["other__a", "other2__a", "a"])
        self.assertEqual(c.get_by_py(trans, parent, "a"), 3)

        c.add(4, "ns", "other--a")
        self.assertEqual(c.get_by_py(trans, parent, "other__a"), 1)
        self.assertTrue("ns__other__a" in c.get_shortest_py_names())

    def test_shallow_copy(self):
        stats = {'count': 0}
        def mk_node(trans, cs_node, parent):
            stats['count'] += 1
            return cs_node

        trans = None
        parent = None
        c = _ChildList("ns", [], mk_node)

        c.add(1, "other", "a")
        c.add(2, "other2", "a")
        c.get_by_py(trans, parent, "other__a")
        self.assertEqual(1, stats['count'])

        c_copy = c.shallow_copy()
        self.assertEqual(c.get_children(trans, parent),
                         c_copy.get_children(trans, parent))
        self.assertEqual(4, stats['count'])


if __name__ == '__main__':
    unittest.main()
