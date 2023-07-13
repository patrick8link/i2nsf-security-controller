"""Internally used classes and functions."""
import unittest
from . import fsm


class _InvalidKeyPath(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class _KeyPath(list):
    def first(self):
        return self.__getitem__(0)


def _Error(fsm):
    raise _InvalidKeyPath(fsm.input_symbol)


def _BegPart(fsm):
    """A 'key part' is stored as a string."""
    fsm.memory.append("")


def _EatPart(fsm):
    s = fsm.memory.pop()
    s = s + fsm.input_symbol
    fsm.memory.append(s)


def _BegEatPart(fsm):
    _BegPart(fsm)
    _EatPart(fsm)


def _EndPart(fsm):
    s = fsm.memory.pop()
    if ':' in s:
        fsm.memory.append(s.split(':'))
    else:
        fsm.memory.append(s)
    fsm.memory.append("")


def _BegKeys0(fsm):
    """Input begins with a '{' , denoting a key."""
    _BegPart(fsm)
    _BegKeys(fsm)


def _BegKeys(fsm):
    """Parse keys.

    Keys are temporarily stored in a list, while being parsed.
    When the keys have been parsed they are stored as a tuple.
    """
    s = fsm.memory.pop()
    if len(s) > 0:
        fsm.memory.append(s)
    fsm.memory.append([])


def _EatKey(fsm):
    keys = fsm.memory.pop()
    key = keys.pop()
    key = key + fsm.input_symbol
    keys.append(key)
    fsm.memory.append(keys)


def _BegKey(fsm):
    keys = fsm.memory.pop()
    keys.append(fsm.input_symbol)
    fsm.memory.append(keys)


def _BegQKey(fsm):
    keys = fsm.memory.pop()
    keys.append("")
    fsm.memory.append(keys)


def _EndKeys(fsm):
    keys = fsm.memory.pop()
    fsm.memory.append(tuple([y for y in keys]))


def _Ignore(fsm):
    s = fsm.memory.pop()
    if len(s) > 0:
        fsm.memory.append(s)
    fsm.memory.append("")


def _parse(input):
    f = fsm.FSM('INIT', _KeyPath())  # "memory" will be used as a stack.
    f.set_default_transition(_Error, 'INIT')

    f.add_transition('/', 'INIT', _BegPart, 'START')
    f.add_transition('{', 'INIT', _BegKeys0, 'KEYS')
    f.add_transition_any('INIT', _BegEatPart, 'START')

    f.add_transition('/', 'START', _Ignore, 'START')
    f.add_transition_any('START', _EatPart, 'PART')

    f.add_transition('/', 'PART', _EndPart, 'START')
    f.add_transition('{', 'PART', _BegKeys, 'KEYS')
    f.add_transition_any('PART', _EatPart, 'PART')

    f.add_transition(' ', 'KEYS', None, 'KEYS')
    f.add_transition('"', 'KEYS', _BegQKey, 'QKEY')
    f.add_transition('}', 'KEYS', _EndKeys, 'PART')
    f.add_transition_any('KEYS', _BegKey, 'KEY')

    f.add_transition('}', 'KEY', _EndKeys, 'PART')
    f.add_transition('"', 'KEY', _BegQKey, 'QKEY')
    f.add_transition(' ', 'KEY', None, 'KEYS')
    f.add_transition_any('KEY', _EatKey, 'KEY')

    f.add_transition('"', 'QKEY', None, 'KEYS')
    f.add_transition('\\', 'QKEY', None, 'ESCQKEY')
    f.add_transition_any('QKEY', _EatKey, 'QKEY')

    f.add_transition_any('ESCQKEY', _EatKey, 'QKEY')

    f.process_list(input)

    # Trim empty string on stack
    s = f.memory.pop()
    if len(s) > 0:
        f.memory.append(s)

    return f.memory

#
# UNIT TESTS
#


class _TestKeyPathParser(unittest.TestCase):

    def test_parse(self):

        # s = 'blaha/error'
        # with self.assertRaises(_InvalidKeyPath):
        #     _parse(s)

        s = '/person/name'
        self.assertEqual(_parse(s),
                         ['person', 'name'])

        s = '/person///name'
        self.assertEqual(_parse(s),
                         ['person', 'name'])

        s = '/person/name{arne}'
        self.assertEqual(_parse(s),
                         ['person', 'name', ('arne',)])

        s = '/person/name{ann britt}'
        self.assertEqual(_parse(s),
                         ['person', 'name', ('ann', 'britt',)])

        s = '/person/name{ann britt}/age'
        self.assertEqual(_parse(s),
                         ['person', 'name', ('ann', 'britt',), 'age'])

        s = '/xyz:person/name{arne}'
        self.assertEqual(_parse(s),
                         [['xyz', 'person'], 'name', ('arne',)])

        s = '/person/name{"arn{e}"}'
        self.assertEqual(_parse(s),
                         ['person', 'name', ('arn{e}',)])

        s = '/name{"tut tut"}'
        self.assertEqual(_parse(s),
                         ['name', ('tut tut',)])

        s = '/name{"tut\\"tut"}'
        self.assertEqual(_parse(s),
                         ['name', ('tut"tut',)])

        s = '/name{"tut\\\\tut"}'
        self.assertEqual(_parse(s),
                         ['name', ('tut\\tut',)])

        s = '/name{"tut tut" "bla bla"}'
        self.assertEqual(_parse(s),
                         ['name', ('tut tut', 'bla bla',)])

        s = '/name{  "tut tut"    "bla bla" }'
        self.assertEqual(_parse(s),
                         ['name', ('tut tut', 'bla bla',)])

        s = '/name{"tut/tut" "bla/bla\\/"}'
        self.assertEqual(_parse(s),
                         ['name', ('tut/tut', 'bla/bla/',)])

        s = 'x/datatypes/uint8'
        self.assertEqual(_parse(s),
                         ['x', 'datatypes', 'uint8'])

        s = './../datatypes/uint8/./'
        self.assertEqual(_parse(s),
                         ['.', '..', 'datatypes', 'uint8', '.'])

        s = '/./../datatypes/uint8'
        self.assertEqual(_parse(s),
                         ['.', '..', 'datatypes', 'uint8'])

        s = '{1 blask post}'
        self.assertEqual(_parse(s),
                         [('1', 'blask', 'post',)])

        s = '/name{"flork""flark"}'
        self.assertEqual(_parse(s),
                         ['name', ('flork', 'flark',)])

        s = '/name{flork"flark"karp}'
        self.assertEqual(_parse(s),
                         ['name', ('flork', 'flark', 'karp',)])

        s = '/bob{""}/sled'
        self.assertEqual(_parse(s),
                         ['bob', ('',), 'sled'])

        s = ('/al:alarms/alarm-list/alarm{dut-r1 connection-failure '
             '/devices/device[name=\'dut-r1\'] ""}')
        self.assertEqual(_parse(s),
                         [['al', 'alarms'], 'alarm-list', 'alarm',
                          ('dut-r1', 'connection-failure',
                           "/devices/device[name='dut-r1']", '')])


if __name__ == '__main__':
    unittest.main()
